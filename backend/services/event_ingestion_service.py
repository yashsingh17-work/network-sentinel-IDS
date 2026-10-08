"""Source-neutral event intake, correlation, and explainable alert creation."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from datetime import timedelta
from threading import RLock
from collections.abc import Callable

from backend.alerts import Alert, AlertManager
from backend.config import Settings
from backend.database import EventRepository
from backend.detection import DetectionFinding
from backend.events import SecurityEvent
from backend.services.monitoring_service import MonitoringService


@dataclass(frozen=True, slots=True)
class IngestionResult:
    event: SecurityEvent
    alerts: list[Alert]


class EventIngestionService:
    """Persist events, then route each source through small, explainable rules."""

    def __init__(self, repository: EventRepository, alerts: AlertManager, monitoring: MonitoringService, settings: Settings) -> None:
        self._repository = repository
        self._alerts = alerts
        self._monitoring = monitoring
        self._settings = settings
        self._failures: dict[str, deque] = {}
        self._lock = RLock()
        self._alert_callback: Callable[[list[Alert]], None] | None = None

    def set_alert_callback(self, callback: Callable[[list[Alert]], None]) -> None:
        self._alert_callback = callback

    def ingest(self, event: SecurityEvent) -> IngestionResult:
        self._repository.save(event)
        packet = event.to_packet()
        generated = self._monitoring.ingest_normalized(packet) if packet is not None else []
        generated.extend(self._alerts.create_from_findings(self._event_findings(event)))
        if generated and self._alert_callback is not None:
            self._alert_callback(generated)
        return IngestionResult(event=event, alerts=generated)

    def recent(self, limit: int = 100) -> list[SecurityEvent]:
        return self._repository.recent(limit)

    def _event_findings(self, event: SecurityEvent) -> list[DetectionFinding]:
        if event.event_type == "authentication_failure":
            return self._authentication_failure(event)
        if event.event_type == "authentication_success":
            return self._authentication_success(event)
        if event.source == "suricata" and event.event_type == "ids_alert":
            return [self._suricata_finding(event)]
        if event.source == "zeek" and event.event_type == "zeek_notice":
            return [
                DetectionFinding(
                    timestamp=event.timestamp, detection_type="ZEEK_NETWORK_ANOMALY", severity="MEDIUM",
                    source_ip=event.source_ip, destination_ip=event.destination_ip, observed_value=1, threshold=1,
                    evidence=f"Zeek emitted a notice: {event.metadata.get('note') or event.metadata.get('msg') or 'unspecified network anomaly'}.",
                    confidence=0.7, source="zeek",
                    recommended_investigation="Open the related Zeek records, validate the hosts and protocol, then pivot on the source and destination IP addresses.",
                )
            ]
        return []

    def _authentication_failure(self, event: SecurityEvent) -> list[DetectionFinding]:
        subject = str(event.metadata.get("user") or event.source_ip or "unknown")
        with self._lock:
            failures = self._failures.setdefault(subject, deque())
            cutoff = event.timestamp - timedelta(seconds=self._settings.auth_failure_time_window_seconds)
            while failures and failures[0] < cutoff:
                failures.popleft()
            failures.append(event.timestamp)
            count = len(failures)
        if count < self._settings.auth_failure_threshold:
            return []
        return [
            DetectionFinding(
                timestamp=event.timestamp, detection_type="AUTH_FAILURE_BURST", severity="HIGH",
                source_ip=event.source_ip, destination_ip=None, observed_value=count,
                threshold=self._settings.auth_failure_threshold,
                evidence=f"{count} failed authentication attempts for {subject} within {self._settings.auth_failure_time_window_seconds} seconds.",
                confidence=0.8, source=event.source,
                recommended_investigation="Verify the account owner, check the source IP and device, and reset or protect the account if the attempts are not expected.",
            )
        ]

    def _authentication_success(self, event: SecurityEvent) -> list[DetectionFinding]:
        subject = str(event.metadata.get("user") or event.source_ip or "unknown")
        with self._lock:
            failures = self._failures.get(subject, deque())
            cutoff = event.timestamp - timedelta(seconds=self._settings.suspicious_auth_sequence_window_seconds)
            recent_count = sum(timestamp >= cutoff for timestamp in failures)
        if not recent_count:
            return []
        return [
            DetectionFinding(
                timestamp=event.timestamp, detection_type="SUSPICIOUS_AUTH_SEQUENCE", severity="HIGH",
                source_ip=event.source_ip, destination_ip=None, observed_value=recent_count, threshold=1,
                evidence=f"A successful authentication for {subject} followed {recent_count} failed attempt(s) within {self._settings.suspicious_auth_sequence_window_seconds} seconds.",
                confidence=0.75, source=event.source,
                recommended_investigation="Confirm whether the successful logon was expected; review its source IP, device, logon type, and subsequent account activity.",
            )
        ]

    @staticmethod
    def _suricata_finding(event: SecurityEvent) -> DetectionFinding:
        severity_value = str(event.metadata.get("severity", "3"))
        severity = {"1": "CRITICAL", "2": "HIGH", "3": "MEDIUM", "4": "LOW"}.get(severity_value, "MEDIUM")
        signature = str(event.metadata.get("signature") or "Unspecified Suricata signature")
        return DetectionFinding(
            timestamp=event.timestamp, detection_type="SURICATA_SIGNATURE", severity=severity,  # type: ignore[arg-type]
            source_ip=event.source_ip, destination_ip=event.destination_ip, observed_value=1, threshold=1,
            evidence=f"Suricata signature {event.metadata.get('signature_id') or 'unknown'} matched: {signature}.",
            confidence=0.9, source="suricata",
            recommended_investigation="Read the Suricata signature/category, inspect the related flow and endpoint context, then validate whether the match is expected activity.",
        )
