"""Persistent alert data contract."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from backend.detection.detection_engine import DetectionType, Severity


@dataclass(frozen=True, slots=True)
class Alert:
    id: str
    timestamp: datetime
    detection_type: DetectionType
    severity: Severity
    source_ip: str | None
    destination_ip: str | None
    observed_value: float
    threshold: float
    evidence: str
