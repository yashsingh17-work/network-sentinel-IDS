"""Factory for the application's explicitly connected backend components."""

from __future__ import annotations

from dataclasses import dataclass

from backend.alerts import AlertManager
from backend.analyzer import DeviceTracker, TrafficAnalyzer
from backend.capture import PacketCapture, ScapyPacketCapture, WifiSecurityInspector
from backend.config import Settings
from backend.database import AlertRepository
from backend.detection import DetectionEngine
from backend.services.monitoring_service import MonitoringService
from backend.parser import PacketParser


@dataclass(slots=True)
class ApplicationServices:
    settings: Settings
    analyzer: TrafficAnalyzer
    device_tracker: DeviceTracker
    detector: DetectionEngine
    repository: AlertRepository
    alert_manager: AlertManager
    monitoring: MonitoringService
    wifi_security: WifiSecurityInspector


def build_services(settings: Settings | None = None, capture: PacketCapture | None = None) -> ApplicationServices:
    resolved_settings = settings or Settings.from_env()
    repository = AlertRepository(resolved_settings.database_path)
    repository.initialize()
    analyzer = TrafficAnalyzer(resolved_settings)
    device_tracker = DeviceTracker(resolved_settings)
    detector = DetectionEngine(resolved_settings)
    alert_manager = AlertManager(repository, resolved_settings)
    return ApplicationServices(
        settings=resolved_settings,
        analyzer=analyzer,
        device_tracker=device_tracker,
        detector=detector,
        repository=repository,
        alert_manager=alert_manager,
        monitoring=MonitoringService(
            analyzer,
            device_tracker,
            detector,
            alert_manager,
            PacketParser(),
            capture or ScapyPacketCapture(),
            resolved_settings.capture_interface,
        ),
        wifi_security=WifiSecurityInspector(resolved_settings),
    )
