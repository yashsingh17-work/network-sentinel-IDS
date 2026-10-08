"""Cached reverse-DNS and optional country context for visible IP addresses."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address, ip_network
import json
import socket
from threading import RLock
from urllib.parse import quote
from urllib.request import Request, urlopen

from backend.config import Settings


_DOCUMENTATION_NETWORKS = tuple(ip_network(cidr) for cidr in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"))


@dataclass(frozen=True, slots=True)
class IpContext:
    ip: str
    label: str
    hostname: str | None = None
    country: str | None = None
    country_code: str | None = None
    status: str = "ready"


class IpEnrichmentService:
    """Resolve at most once per cache period and never block dashboard updates."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._cache: dict[str, tuple[datetime, IpContext]] = {}
        self._pending: set[str] = set()
        self._lock = RLock()
        self._workers = ThreadPoolExecutor(max_workers=2, thread_name_prefix="ip-context")

    def describe(self, value: str) -> IpContext:
        try:
            address = ip_address(value)
        except ValueError:
            return IpContext(ip=value, label=value, status="invalid")
        if address.is_loopback:
            return IpContext(ip=value, label=f"{value} (This computer)")
        if any(address in network for network in _DOCUMENTATION_NETWORKS):
            return IpContext(ip=value, label=f"{value} (Documentation/demo address)")
        if address.is_private or address.is_link_local or address.is_reserved:
            return IpContext(ip=value, label=f"{value} (Private or local network)")
        if not self._settings.reverse_dns_enabled and not self._settings.country_lookup_enabled:
            return IpContext(ip=value, label=value, status="disabled")
        now = datetime.now(timezone.utc)
        with self._lock:
            cached = self._cache.get(value)
            if cached is not None and cached[0] > now:
                return cached[1]
            if value not in self._pending and (self._settings.reverse_dns_enabled or self._settings.country_lookup_enabled):
                self._pending.add(value)
                self._workers.submit(self._resolve, value)
        return IpContext(ip=value, label=f"{value} (resolving…)", status="resolving")

    def _resolve(self, value: str) -> None:
        hostname: str | None = None
        country: str | None = None
        country_code: str | None = None
        try:
            if self._settings.reverse_dns_enabled:
                try:
                    hostname = socket.gethostbyaddr(value)[0]
                except (socket.herror, socket.gaierror, OSError):
                    hostname = None
            if self._settings.country_lookup_enabled:
                country, country_code = self._country(value)
            parts = [item for item in (hostname, country) if item]
            label = f"{value} ({' · '.join(parts)})" if parts else value
            context = IpContext(ip=value, label=label, hostname=hostname, country=country, country_code=country_code)
            expires_at = datetime.now(timezone.utc) + timedelta(seconds=self._settings.ip_enrichment_cache_seconds)
            with self._lock:
                self._cache[value] = (expires_at, context)
        finally:
            with self._lock:
                self._pending.discard(value)

    def _country(self, value: str) -> tuple[str | None, str | None]:
        url = self._settings.country_lookup_url.replace("{ip}", quote(value, safe=""))
        request = Request(url, headers={"User-Agent": "Network-Sentinel/1.0"})
        try:
            with urlopen(request, timeout=2) as response:  # nosec B310 - URL is explicitly configured by the user
                payload = json.loads(response.read().decode("utf-8"))
        except (OSError, ValueError, TimeoutError):
            return None, None
        if payload.get("success") is False:
            return None, None
        return payload.get("country"), payload.get("country_code")
