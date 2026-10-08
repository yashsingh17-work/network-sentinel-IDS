"""Factory for the application's explicitly connected backend components."""

from __future__ import annotations

from dataclasses import dataclass

from backend.alerts import AlertManager
from backend.analyzer import DeviceTracker, TrafficAnalyzer
from backend.capture import DisabledPacketCapture, PacketCapture, ScapyPacketCapture, WifiSecurityInspector
from backend.config import Settings
from backend.database import AlertRepository, EventRepository
from backend.detection import DetectionEngine
from backend.services.monitoring_service import MonitoringService
from backend.services.event_ingestion_service import EventIngestionService
from backend.parser import PacketParser


@dataclass(slots=True)
class ApplicationServices:
    settings: Settings
    analyzer: TrafficAnalyzer
    device_tracker: DeviceTracker
    detector: DetectionEngine
    repository: AlertRepository
    event_repository: EventRepository
    alert_manager: AlertManager
    monitoring: MonitoringService
    event_ingestion: EventIngestionService
    wifi_security: WifiSecurityInspector


def build_services(settings: Settings | None = None, capture: PacketCapture | None = None) -> ApplicationServices:
    resolved_settings = settings or Settings.from_env()
    repository = AlertRepository(resolved_settings.database_path)
    repository.initialize()
    event_repository = EventRepository(resolved_settings.database_path)
    event_repository.initialize()
    analyzer = TrafficAnalyzer(resolved_settings)
    device_tracker = DeviceTracker(resolved_settings)
    detector = DetectionEngine(resolved_settings)
    alert_manager = AlertManager(repository, resolved_settings)
    monitoring = MonitoringService(
        analyzer,
        device_tracker,
        detector,
        alert_manager,
        PacketParser(),
        capture or (ScapyPacketCapture() if resolved_settings.packet_capture_enabled else DisabledPacketCapture()),
        resolved_settings.capture_interface,
    )
    return ApplicationServices(
        settings=resolved_settings,
        analyzer=analyzer,
        device_tracker=device_tracker,
        detector=detector,
        repository=repository,
        event_repository=event_repository,
        alert_manager=alert_manager,
        monitoring=monitoring,
        event_ingestion=EventIngestionService(event_repository, alert_manager, monitoring, resolved_settings),
        wifi_security=WifiSecurityInspector(resolved_settings),
    )
