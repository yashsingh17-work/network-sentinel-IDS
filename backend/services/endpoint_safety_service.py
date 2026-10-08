"""Local endpoint-safety checks that feed the same event and alert pipeline."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from threading import RLock

from backend.capture import WifiSecurityInspector
from backend.config import Settings
from backend.events import SecurityEvent
from backend.services.event_ingestion_service import EventIngestionService
from backend.sources import WindowsDownloadMonitor


class EndpointSafetyService:
    """Observe downloads and unsafe Wi-Fi without uploading file contents or domains."""

    def __init__(self, downloads: WindowsDownloadMonitor, wifi: WifiSecurityInspector, ingestion: EventIngestionService, settings: Settings) -> None:
        self._downloads = downloads
        self._wifi = wifi
        self._ingestion = ingestion
        self._settings = settings
        self._last_download_scan: datetime | None = None
        self._last_wifi_fingerprint: tuple[str | None, str | None, str | None] | None = None
        self._lock = RLock()

    def poll(self) -> None:
        """Perform due read-only checks. Alert publication happens through ingestion."""
        now = datetime.now(timezone.utc)
        with self._lock:
            if self._last_download_scan is None or now - self._last_download_scan >= timedelta(seconds=self._settings.download_monitor_interval_seconds):
                self._last_download_scan = now
                for observation in self._downloads.scan():
                    self._ingestion.ingest(
                        SecurityEvent(
                            timestamp=now, source="windows_download_monitor", event_type="download_observed",
                            bytes_count=observation.size_bytes,
                            metadata={
                                "path": observation.path, "filename": observation.filename, "extension": observation.extension,
                                "sha256": observation.sha256, "hash_status": observation.hash_status,
                                "mark_of_the_web": observation.mark_of_the_web, "signature_status": observation.signature_status,
                                "publisher": observation.publisher, "risky_file_type": observation.risky_file_type,
                            },
                        )
                    )
            wifi = self._wifi.status()
            fingerprint = (wifi.ssid, wifi.authentication, wifi.cipher)
            if wifi.connected and wifi.secure is False and fingerprint != self._last_wifi_fingerprint:
                self._last_wifi_fingerprint = fingerprint
                posture = "open_or_legacy" if any(word in wifi.summary.lower() for word in ("open", "wep", "tkip")) else "unverified"
                self._ingestion.ingest(
                    SecurityEvent(
                        timestamp=now, source="windows_wifi_monitor", event_type="wifi_posture",
                        metadata={"ssid": wifi.ssid, "authentication": wifi.authentication, "cipher": wifi.cipher, "summary": wifi.summary, "posture": posture},
                    )
                )
            elif not wifi.connected or wifi.secure is True:
                self._last_wifi_fingerprint = None

    def audit_current_downloads(self) -> int:
        """Inspect current files only on user request; no content leaves this computer."""
        observations = self._downloads.scan(include_known=True)
        now = datetime.now(timezone.utc)
        for observation in observations:
            self._ingestion.ingest(
                SecurityEvent(
                    timestamp=now, source="windows_download_monitor", event_type="download_observed",
                    bytes_count=observation.size_bytes,
                    metadata={
                        "path": observation.path, "filename": observation.filename, "extension": observation.extension,
                        "sha256": observation.sha256, "hash_status": observation.hash_status,
                        "mark_of_the_web": observation.mark_of_the_web, "signature_status": observation.signature_status,
                        "publisher": observation.publisher, "risky_file_type": observation.risky_file_type,
                    },
                )
            )
        return len(observations)

    def download_status(self):
        return self._downloads.status()
