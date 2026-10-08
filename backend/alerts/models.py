"""Persistent alert data contract."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

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
    confidence: float = 0.7
    recommended_investigation: str = "Review the evidence, validate the activity with the asset owner, and check related events."
    source: str = "python_detection"
    context: dict[str, Any] = field(default_factory=dict)
