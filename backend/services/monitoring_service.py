"""Coordinates the in-process pipeline while a capture adapter is active."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from threading import RLock
from collections.abc import Callable

from backend.alerts import Alert, AlertManager
from backend.analyzer import DeviceTracker, TrafficAnalyzer
from backend.capture import PacketCapture
from backend.detection import DetectionEngine
from backend.models import NormalizedPacket
from backend.parser import PacketParser


@dataclass(frozen=True, slots=True)
class MonitoringStatus:
    active: bool
    started_at: datetime | None
    capture_ready: bool
    interface: str | None
    last_error: str | None


class MonitoringService:
    """The one entrypoint that the live capture adapter calls."""

    def __init__(
        self,
        analyzer: TrafficAnalyzer,
        device_tracker: DeviceTracker,
        detector: DetectionEngine,
        alert_manager: AlertManager,
        parser: PacketParser,
        capture: PacketCapture,
        interface: str | None = None,
    ) -> None:
        self._analyzer = analyzer
        self._device_tracker = device_tracker
        self._detector = detector
        self._alert_manager = alert_manager
        self._parser = parser
        self._capture = capture
        self._interface = interface
        self._lock = RLock()
        self._active = False
        self._started_at: datetime | None = None
        self._alert_callback: Callable[[list[Alert]], None] | None = None

    def set_alert_callback(self, callback: Callable[[list[Alert]], None]) -> None:
        self._alert_callback = callback

    def start(self) -> MonitoringStatus:
        with self._lock:
            if self._active:
                return self.status()
            capture_status = self._capture.start(self.process_raw, self._interface)
            if not capture_status.running:
                self._active = False
                self._started_at = None
                return self.status()
            self._active = True
            self._started_at = datetime.now(timezone.utc)
            return self.status()

    def stop(self) -> MonitoringStatus:
        with self._lock:
            self._active = False
            self._started_at = None
            self._capture.stop()
            return self.status()

    def status(self) -> MonitoringStatus:
        with self._lock:
            capture_status = self._capture.status()
            return MonitoringStatus(
                active=self._active,
                started_at=self._started_at,
                capture_ready=capture_status.running,
                interface=capture_status.interface,
                last_error=capture_status.error,
            )

    def process_raw(self, raw_packet: object) -> list[Alert]:
        parsed = raw_packet if isinstance(raw_packet, NormalizedPacket) else self._parser.parse(raw_packet)
        return self.process(parsed) if parsed is not None else []

    def process(self, packet: NormalizedPacket) -> list[Alert]:
        """Process a packet only when monitoring is active."""
        with self._lock:
            if not self._active:
                return []
        self._analyzer.ingest(packet)
        self._device_tracker.ingest(packet)
        alerts = self._alert_manager.create_from_findings(self._detector.analyze(packet))
        if alerts and self._alert_callback is not None:
            self._alert_callback(alerts)
        return alerts
