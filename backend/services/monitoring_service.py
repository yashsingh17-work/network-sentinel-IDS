"""Coordinates the in-process pipeline while a capture adapter is active."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from threading import RLock

from backend.alerts import Alert, AlertManager
from backend.analyzer import TrafficAnalyzer
from backend.detection import DetectionEngine
from backend.models import NormalizedPacket


@dataclass(frozen=True, slots=True)
class MonitoringStatus:
    active: bool
    started_at: datetime | None
    capture_ready: bool


class MonitoringService:
    """The one entrypoint that a future live capture adapter will call."""

    def __init__(self, analyzer: TrafficAnalyzer, detector: DetectionEngine, alert_manager: AlertManager) -> None:
        self._analyzer = analyzer
        self._detector = detector
        self._alert_manager = alert_manager
        self._lock = RLock()
        self._active = False
        self._started_at: datetime | None = None

    def start(self) -> MonitoringStatus:
        with self._lock:
            if not self._active:
                self._active = True
                self._started_at = datetime.now(timezone.utc)
            return self.status()

    def stop(self) -> MonitoringStatus:
        with self._lock:
            self._active = False
            self._started_at = None
            return self.status()

    def status(self) -> MonitoringStatus:
        with self._lock:
            return MonitoringStatus(active=self._active, started_at=self._started_at, capture_ready=False)

    def process(self, packet: NormalizedPacket) -> list[Alert]:
        """Process a packet only when monitoring is active."""
        with self._lock:
            if not self._active:
                return []
        self._analyzer.ingest(packet)
        return self._alert_manager.create_from_findings(self._detector.analyze(packet))
