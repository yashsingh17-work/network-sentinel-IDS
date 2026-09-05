"""Factory for the application's explicitly connected backend components."""

from __future__ import annotations

from dataclasses import dataclass

from backend.alerts import AlertManager
from backend.analyzer import TrafficAnalyzer
from backend.config import Settings
from backend.database import AlertRepository
from backend.detection import DetectionEngine
from backend.services.monitoring_service import MonitoringService


@dataclass(slots=True)
class ApplicationServices:
    settings: Settings
    analyzer: TrafficAnalyzer
    detector: DetectionEngine
    repository: AlertRepository
    alert_manager: AlertManager
    monitoring: MonitoringService


def build_services(settings: Settings | None = None) -> ApplicationServices:
    resolved_settings = settings or Settings.from_env()
    repository = AlertRepository(resolved_settings.database_path)
    repository.initialize()
    analyzer = TrafficAnalyzer(resolved_settings)
    detector = DetectionEngine(resolved_settings)
    alert_manager = AlertManager(repository, resolved_settings)
    return ApplicationServices(
        settings=resolved_settings,
        analyzer=analyzer,
        detector=detector,
        repository=repository,
        alert_manager=alert_manager,
        monitoring=MonitoringService(analyzer, detector, alert_manager),
    )
