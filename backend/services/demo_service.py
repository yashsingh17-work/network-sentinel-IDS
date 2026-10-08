"""Safe, local sample data that demonstrates the Mini-SOC pipeline."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from threading import Lock

from backend.alerts import Alert
from backend.config import Settings
from backend.events import SecurityEvent
from backend.services.event_ingestion_service import EventIngestionService


@dataclass(frozen=True, slots=True)
class DemoResult:
    events_created: int
    alerts: list[Alert]


class DemoService:
    """Creates synthetic records only; it never sends packets or touches a network."""

    def __init__(self, ingestion: EventIngestionService, settings: Settings) -> None:
        self._ingestion = ingestion
        self._settings = settings
        self._lock = Lock()
        self._run_number = 0

    def run(self) -> DemoResult:
        with self._lock:
            self._run_number += 1
            source_ip = f"198.51.100.{10 + (self._run_number % 200)}"
        now = datetime.now(timezone.utc)
        generated_alerts: list[Alert] = []
        event_count = 0

        for offset in range(self._settings.port_scan_port_threshold):
            result = self._ingestion.ingest(
                SecurityEvent(
                    timestamp=now + timedelta(milliseconds=offset), source="synthetic", event_type="network_connection",
                    source_ip=source_ip, destination_ip="203.0.113.20", source_port=45000 + offset,
                    destination_port=10_000 + offset, protocol="TCP", bytes_count=60, packets_count=1,
                    metadata={"tcp_flags": "S", "scenario": "safe_port_scan_demo"},
                )
            )
            generated_alerts.extend(result.alerts)
            event_count += 1

        for offset in range(self._settings.auth_failure_threshold):
            result = self._ingestion.ingest(
                SecurityEvent(
                    timestamp=now + timedelta(seconds=1, milliseconds=offset), source="synthetic",
                    event_type="authentication_failure", source_ip=source_ip,
                    metadata={"user": "demo.user", "scenario": "safe_authentication_demo"},
                )
            )
            generated_alerts.extend(result.alerts)
            event_count += 1

        for event in (
            SecurityEvent(timestamp=now + timedelta(seconds=2), source="synthetic", event_type="authentication_success", source_ip=source_ip, metadata={"user": "demo.user", "scenario": "safe_authentication_demo"}),
            SecurityEvent(timestamp=now + timedelta(seconds=3), source="suricata", event_type="ids_alert", source_ip=source_ip, destination_ip="203.0.113.20", metadata={"signature": "DEMO: Suspicious test signature", "signature_id": 9_001_001, "severity": 2, "scenario": "safe_suricata_demo"}),
            SecurityEvent(timestamp=now + timedelta(seconds=4), source="zeek", event_type="zeek_notice", source_ip=source_ip, destination_ip="203.0.113.20", metadata={"note": "DEMO::SyntheticNetworkNotice", "scenario": "safe_zeek_demo"}),
        ):
            result = self._ingestion.ingest(event)
            generated_alerts.extend(result.alerts)
            event_count += 1
        return DemoResult(events_created=event_count, alerts=generated_alerts)
