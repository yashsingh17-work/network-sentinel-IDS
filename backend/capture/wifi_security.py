"""Read-only Wi-Fi posture check for Windows dashboard display."""

from __future__ import annotations

import platform
import subprocess
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from backend.config import Settings


@dataclass(frozen=True, slots=True)
class WifiSecurityStatus:
    available: bool
    connected: bool
    ssid: str | None
    authentication: str | None
    cipher: str | None
    secure: bool | None
    summary: str


class WifiSecurityInspector:
    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or Settings.from_env()
        self._cached: WifiSecurityStatus | None = None
        self._cached_at: datetime | None = None

    def status(self) -> WifiSecurityStatus:
        now = datetime.now(timezone.utc)
        if self._cached is not None and self._cached_at is not None and now - self._cached_at < timedelta(seconds=self._settings.wifi_status_refresh_seconds):
            return self._cached
        if platform.system() != "Windows":
            return self._cache(WifiSecurityStatus(False, False, None, None, None, None, "Wi-Fi posture check is currently available on Windows only."), now)
        try:
            output = subprocess.run(["netsh", "wlan", "show", "interfaces"], capture_output=True, text=True, timeout=5, check=False).stdout
            fields = self._fields(output)
            state = fields.get("state", "").lower()
            if state != "connected":
                return self._cache(WifiSecurityStatus(True, False, None, None, None, None, "No Wi-Fi connection is active."), now)
            authentication = fields.get("authentication")
            cipher = fields.get("cipher")
            secure, summary = self._assess(authentication, cipher)
            return self._cache(WifiSecurityStatus(True, True, fields.get("ssid"), authentication, cipher, secure, summary), now)
        except (OSError, subprocess.SubprocessError) as exc:
            return self._cache(WifiSecurityStatus(False, False, None, None, None, None, f"Unable to read Wi-Fi status: {exc}"), now)

    @staticmethod
    def _fields(output: str) -> dict[str, str]:
        fields: dict[str, str] = {}
        for line in output.splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                fields[key.strip().lower()] = value.strip()
        return fields

    @staticmethod
    def _assess(authentication: str | None, cipher: str | None) -> tuple[bool, str]:
        combined = f"{authentication or ''} {cipher or ''}".upper()
        if any(value in combined for value in ("OPEN", "NONE", "WEP")):
            return False, "Insecure Wi-Fi: open or WEP security was detected. Use WPA2/WPA3 with AES/CCMP."
        if "TKIP" in combined:
            return False, "Legacy TKIP Wi-Fi encryption was detected. Use WPA2/WPA3 with AES/CCMP."
        if "WPA2" in combined or "WPA3" in combined:
            return True, "Wi-Fi uses WPA2/WPA3-class protection based on Windows interface data."
        return False, "Wi-Fi security could not be verified. Check the router and use WPA2/WPA3 with AES/CCMP."

    def _cache(self, status: WifiSecurityStatus, now: datetime) -> WifiSecurityStatus:
        self._cached = status
        self._cached_at = now
        return status
