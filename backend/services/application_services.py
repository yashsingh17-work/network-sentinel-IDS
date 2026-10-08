"""Factory for the application's explicitly connected backend components."""

from __future__ import annotations

from dataclasses import dataclass

from backend.alerts import AlertManager
from backend.analyzer import DeviceTracker, TrafficAnalyzer
from backend.capture import DisabledPacketCapture, PacketCapture, ScapyPacketCapture, WifiSecurityInspector
from backend.config import Settings
from backend.database import AlertRepository, DeviceProfileRepository, EventRepository
from backend.detection import DetectionEngine
from backend.enrichment import IpEnrichmentService
from backend.services.monitoring_service import MonitoringService
from backend.services.event_ingestion_service import EventIngestionService
from backend.services.demo_service import DemoService
from backend.services.packet_tracer_demo_service import PacketTracerDemoService
from backend.services.endpoint_safety_service import EndpointSafetyService
from backend.parser import PacketParser
from backend.services.windows_import_service import WindowsImportService
from backend.sources import WindowsDownloadMonitor, WindowsEventNormalizer, WindowsSecurityEventReader


@dataclass(slots=True)
class ApplicationServices:
    settings: Settings
    analyzer: TrafficAnalyzer
    device_tracker: DeviceTracker
    detector: DetectionEngine
    repository: AlertRepository
    event_repository: EventRepository
    device_profiles: DeviceProfileRepository
    alert_manager: AlertManager
    monitoring: MonitoringService
    event_ingestion: EventIngestionService
    demo: DemoService
    packet_tracer_demo: PacketTracerDemoService
    windows_import: WindowsImportService
    enrichment: IpEnrichmentService
    wifi_security: WifiSecurityInspector
    endpoint_safety: EndpointSafetyService


def build_services(settings: Settings | None = None, capture: PacketCapture | None = None) -> ApplicationServices:
    resolved_settings = settings or Settings.from_env()
    repository = AlertRepository(resolved_settings.database_path)
    repository.initialize()
    event_repository = EventRepository(resolved_settings.database_path)
    event_repository.initialize()
    device_profiles = DeviceProfileRepository(resolved_settings.database_path)
    device_profiles.initialize()
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
    event_ingestion = EventIngestionService(event_repository, alert_manager, monitoring, resolved_settings)
    wifi_security = WifiSecurityInspector(resolved_settings)
    return ApplicationServices(
        settings=resolved_settings,
        analyzer=analyzer,
        device_tracker=device_tracker,
        detector=detector,
        repository=repository,
        event_repository=event_repository,
        device_profiles=device_profiles,
        alert_manager=alert_manager,
        monitoring=monitoring,
        event_ingestion=event_ingestion,
        demo=DemoService(event_ingestion, resolved_settings),
        packet_tracer_demo=PacketTracerDemoService(event_ingestion, resolved_settings),
        windows_import=WindowsImportService(WindowsSecurityEventReader(), WindowsEventNormalizer(), event_ingestion),
        enrichment=IpEnrichmentService(resolved_settings),
        wifi_security=wifi_security,
        endpoint_safety=EndpointSafetyService(WindowsDownloadMonitor(resolved_settings), wifi_security, event_ingestion, resolved_settings),
    )
