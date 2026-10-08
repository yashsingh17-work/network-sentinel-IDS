"""Creates, deduplicates, and persists user-visible alerts."""

from __future__ import annotations

from datetime import datetime, timedelta
from threading import RLock
from uuid import uuid4

from backend.alerts.models import Alert
from backend.config import Settings
from backend.database.alert_repository import AlertRepository
from backend.detection import DetectionFinding


class AlertManager:
    def __init__(self, repository: AlertRepository, settings: Settings | None = None) -> None:
        self._repository = repository
        self._settings = settings or Settings.from_env()
        self._lock = RLock()
        self._recent_signatures: dict[tuple[str, str | None, str | None], datetime] = {}

    def create_from_finding(self, finding: DetectionFinding) -> Alert | None:
        """Persist a finding unless an identical subject is inside its cooldown."""
        signature = self._signature(finding)
        with self._lock:
            self._prune(finding.timestamp)
            previous = self._recent_signatures.get(signature)
            if previous is not None and finding.timestamp < previous + timedelta(seconds=self._settings.alert_cooldown_seconds):
                return None
            alert = Alert(
                id=str(uuid4()),
                timestamp=finding.timestamp,
                detection_type=finding.detection_type,
                severity=finding.severity,
                source_ip=finding.source_ip,
                destination_ip=finding.destination_ip,
                observed_value=finding.observed_value,
                threshold=finding.threshold,
                evidence=finding.evidence,
                confidence=finding.confidence,
                recommended_investigation=finding.recommended_investigation,
                source=finding.source,
                context=finding.context,
            )
            saved_alert = self._repository.save(alert)
            self._recent_signatures[signature] = finding.timestamp
            return saved_alert

    def create_from_findings(self, findings: list[DetectionFinding]) -> list[Alert]:
        return [alert for finding in findings if (alert := self.create_from_finding(finding)) is not None]

    def _prune(self, now: datetime) -> None:
        cutoff = now - timedelta(seconds=self._settings.alert_cooldown_seconds)
        expired = [signature for signature, timestamp in self._recent_signatures.items() if timestamp <= cutoff]
        for signature in expired:
            del self._recent_signatures[signature]

    @staticmethod
    def _signature(finding: DetectionFinding) -> tuple[str, str | None, str | None]:
        """Keep independent download alerts from suppressing each other globally."""
        if finding.detection_type in {"DOWNLOAD_OBSERVED", "UNVERIFIED_RISKY_DOWNLOAD"}:
            return finding.detection_type, str(finding.context.get("path") or "unknown"), None
        return finding.detection_type, finding.source_ip, finding.destination_ip
