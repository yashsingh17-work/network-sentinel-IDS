"""Small, bounded inventory of devices observed in local packet traffic."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from threading import RLock

from backend.config import Settings
from backend.models import NormalizedPacket
from backend.analyzer.device_identity import likely_role, mac_vendor, observed_service_labels


@dataclass(frozen=True, slots=True)
class ObservedDevice:
    mac_address: str
    ip_addresses: list[str]
    first_seen: datetime
    last_seen: datetime
    packets_seen: int
    protocols: dict[str, int]
    vendor: str | None
    likely_role: str
    observed_services: list[str]


@dataclass(slots=True)
class _MutableDevice:
    first_seen: datetime
    last_seen: datetime
    packets_seen: int = 0
    ip_addresses: set[str] = field(default_factory=set)
    protocols: dict[str, int] = field(default_factory=dict)
    source_ports: dict[int, int] = field(default_factory=dict)


class DeviceTracker:
    """Reports observed devices; absence from this list never proves a device is absent."""

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or Settings.from_env()
        self._devices: dict[str, _MutableDevice] = {}
        self._lock = RLock()

    def ingest(self, packet: NormalizedPacket) -> None:
        mac = packet.arp_source_mac or packet.source_mac
        if mac is None or mac == "00:00:00:00:00:00" or mac.startswith("ff:"):
            return
        with self._lock:
            existing = self._devices.get(mac)
            if existing is None:
                if len(self._devices) >= self._settings.max_tracked_devices:
                    oldest = min(self._devices, key=lambda key: self._devices[key].last_seen)
                    del self._devices[oldest]
                existing = _MutableDevice(first_seen=packet.timestamp, last_seen=packet.timestamp)
                self._devices[mac] = existing
            existing.last_seen = packet.timestamp
            existing.packets_seen += 1
            existing.protocols[packet.protocol] = existing.protocols.get(packet.protocol, 0) + 1
            if packet.source_port is not None:
                existing.source_ports[packet.source_port] = existing.source_ports.get(packet.source_port, 0) + 1
            for address in (packet.source_ip, packet.arp_source_ip):
                if address and address != "0.0.0.0":
                    existing.ip_addresses.add(address)

    def snapshot(self, now: datetime | None = None) -> list[ObservedDevice]:
        current = now or datetime.now(timezone.utc)
        with self._lock:
            cutoff = current - timedelta(seconds=self._settings.device_ttl_seconds)
            stale = [mac for mac, device in self._devices.items() if device.last_seen < cutoff]
            for mac in stale:
                del self._devices[mac]
            return [
                ObservedDevice(
                    mac_address=mac,
                    ip_addresses=sorted(device.ip_addresses),
                    first_seen=device.first_seen,
                    last_seen=device.last_seen,
                    packets_seen=device.packets_seen,
                    protocols=dict(device.protocols),
                    vendor=mac_vendor(mac),
                    likely_role=likely_role(sorted(device.ip_addresses), device.source_ports),
                    observed_services=observed_service_labels(device.source_ports),
                )
                for mac, device in sorted(self._devices.items(), key=lambda entry: entry[1].last_seen, reverse=True)
            ]
