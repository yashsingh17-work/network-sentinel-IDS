"""Small, explainable rule-based IDS detection engine."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from threading import RLock
from typing import Literal

from backend.config import Settings
from backend.models import NormalizedPacket

DetectionType = Literal["PORT_SCAN", "SYN_FLOOD", "TRAFFIC_RATE_ANOMALY"]
Severity = Literal["LOW", "MEDIUM", "HIGH"]


@dataclass(frozen=True, slots=True)
class DetectionFinding:
    """An explainable candidate alert emitted by one detection rule."""

    timestamp: datetime
    detection_type: DetectionType
    severity: Severity
    source_ip: str | None
    destination_ip: str | None
    observed_value: float
    threshold: float
    evidence: str


class DetectionEngine:
    """Detect port scans, abnormal SYN volume, and aggregate traffic spikes."""

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or Settings.from_env()
        self._lock = RLock()
        self._port_events: dict[str, deque[tuple[datetime, int]]] = {}
        self._syn_events: dict[str, deque[datetime]] = {}
        self._traffic_events: deque[datetime] = deque()
        self._cooldowns: dict[tuple[DetectionType, str | None], datetime] = {}

    def analyze(self, packet: NormalizedPacket) -> list[DetectionFinding]:
        """Evaluate a normalized packet and return zero or more new findings."""
        with self._lock:
            findings: list[DetectionFinding] = []
            port_scan = self._check_port_scan(packet)
            if port_scan is not None:
                findings.append(port_scan)
            syn_activity = self._check_syn_activity(packet)
            if syn_activity is not None:
                findings.append(syn_activity)
            rate_anomaly = self._check_traffic_rate(packet)
            if rate_anomaly is not None:
                findings.append(rate_anomaly)
            self._prune_cooldowns(packet.timestamp)
            return findings

    def _check_port_scan(self, packet: NormalizedPacket) -> DetectionFinding | None:
        if packet.destination_port is None:
            return None
        events = self._events_for(self._port_events, packet.source_ip)
        cutoff = packet.timestamp - timedelta(seconds=self._settings.port_scan_time_window_seconds)
        self._prune_events(events, cutoff)
        events.append((packet.timestamp, packet.destination_port))
        self._cap_events(events)
        unique_ports = len({port for _, port in events})
        if unique_ports < self._settings.port_scan_port_threshold or not self._ready("PORT_SCAN", packet.source_ip, packet.timestamp):
            return None
        threshold = self._settings.port_scan_port_threshold
        return DetectionFinding(
            timestamp=packet.timestamp,
            detection_type="PORT_SCAN",
            severity="HIGH" if unique_ports >= threshold * 2 else "MEDIUM",
            source_ip=packet.source_ip,
            destination_ip=packet.destination_ip,
            observed_value=unique_ports,
            threshold=threshold,
            evidence=(
                f"{packet.source_ip} contacted {unique_ports} unique destination ports "
                f"within {self._settings.port_scan_time_window_seconds} seconds "
                f"(threshold: {threshold})."
            ),
        )

    def _check_syn_activity(self, packet: NormalizedPacket) -> DetectionFinding | None:
        if packet.protocol != "TCP" or not self._is_initial_syn(packet.tcp_flags):
            return None
        events = self._events_for(self._syn_events, packet.source_ip)
        cutoff = packet.timestamp - timedelta(seconds=self._settings.syn_time_window_seconds)
        self._prune_events(events, cutoff)
        events.append(packet.timestamp)
        self._cap_events(events)
        syn_count = len(events)
        if syn_count < self._settings.syn_rate_threshold or not self._ready("SYN_FLOOD", packet.source_ip, packet.timestamp):
            return None
        threshold = self._settings.syn_rate_threshold
        return DetectionFinding(
            timestamp=packet.timestamp,
            detection_type="SYN_FLOOD",
            severity="HIGH" if syn_count >= threshold * 2 else "MEDIUM",
            source_ip=packet.source_ip,
            destination_ip=packet.destination_ip,
            observed_value=syn_count,
            threshold=threshold,
            evidence=(
                f"{packet.source_ip} sent {syn_count} initial TCP SYN packets within "
                f"{self._settings.syn_time_window_seconds} second(s) (threshold: {threshold})."
            ),
        )

    def _check_traffic_rate(self, packet: NormalizedPacket) -> DetectionFinding | None:
        cutoff = packet.timestamp - timedelta(seconds=self._settings.traffic_rate_window_seconds)
        self._prune_events(self._traffic_events, cutoff)
        self._traffic_events.append(packet.timestamp)
        self._cap_events(self._traffic_events)
        packet_count = len(self._traffic_events)
        if packet_count < self._settings.traffic_rate_threshold or not self._ready("TRAFFIC_RATE_ANOMALY", None, packet.timestamp):
            return None
        threshold = self._settings.traffic_rate_threshold
        return DetectionFinding(
            timestamp=packet.timestamp,
            detection_type="TRAFFIC_RATE_ANOMALY",
            severity="HIGH" if packet_count >= threshold * 2 else "MEDIUM",
            source_ip=packet.source_ip,
            destination_ip=packet.destination_ip,
            observed_value=packet_count,
            threshold=threshold,
            evidence=(
                f"Observed {packet_count} packets across all traffic within "
                f"{self._settings.traffic_rate_window_seconds} second(s) (threshold: {threshold})."
            ),
        )

    def _events_for(self, registry: dict[str, deque], key: str) -> deque:
        events = registry.get(key)
        if events is not None:
            return events
        if len(registry) >= self._settings.max_tracked_endpoints:
            oldest_key = min(registry, key=lambda source: registry[source][-1][0] if isinstance(registry[source][-1], tuple) else registry[source][-1])
            del registry[oldest_key]
        registry[key] = deque()
        return registry[key]

    def _ready(self, detection_type: DetectionType, subject: str | None, now: datetime) -> bool:
        cooldown_key = (detection_type, subject)
        expires_at = self._cooldowns.get(cooldown_key)
        if expires_at is not None and now < expires_at:
            return False
        self._cooldowns[cooldown_key] = now + timedelta(seconds=self._settings.alert_cooldown_seconds)
        return True

    def _prune_cooldowns(self, now: datetime) -> None:
        expired = [key for key, expires_at in self._cooldowns.items() if expires_at <= now]
        for key in expired:
            del self._cooldowns[key]

    @staticmethod
    def _prune_events(events: deque, cutoff: datetime) -> None:
        while events and (events[0][0] if isinstance(events[0], tuple) else events[0]) < cutoff:
            events.popleft()

    def _cap_events(self, events: deque) -> None:
        while len(events) > self._settings.max_detector_events_per_key:
            events.popleft()

    @staticmethod
    def _is_initial_syn(flags: str | None) -> bool:
        return flags is not None and "S" in flags and "A" not in flags
