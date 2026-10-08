"""Small, explainable rule-based IDS detection engine."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from threading import RLock
from typing import Any, Literal

from backend.config import Settings
from backend.enrichment import describe_port
from backend.models import NormalizedPacket

DetectionType = Literal[
    "PORT_SCAN", "SYN_FLOOD", "TRAFFIC_RATE_ANOMALY", "ICMP_SWEEP", "DNS_QUERY_ANOMALY", "ARP_SPOOFING_SUSPECTED",
    "AUTH_FAILURE_BURST", "SUSPICIOUS_AUTH_SEQUENCE", "SURICATA_SIGNATURE", "ZEEK_NETWORK_ANOMALY",
    "DOWNLOAD_OBSERVED", "UNVERIFIED_RISKY_DOWNLOAD", "UNSAFE_WIFI_POSTURE", "SUSPICIOUS_DOMAIN"
]
Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]


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
    confidence: float = 0.7
    recommended_investigation: str = "Review the evidence, validate the activity with the asset owner, and check related events."
    source: str = "python_detection"
    context: dict[str, Any] = field(default_factory=dict)


class DetectionEngine:
    """Detect port scans, abnormal SYN volume, and aggregate traffic spikes."""

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or Settings.from_env()
        self._lock = RLock()
        self._port_events: dict[str, deque[tuple[datetime, int]]] = {}
        self._syn_events: dict[str, deque[datetime]] = {}
        self._traffic_events: deque[datetime] = deque()
        self._icmp_events: dict[str, deque[tuple[datetime, str]]] = {}
        self._dns_events: dict[str, deque[datetime]] = {}
        self._arp_claims: dict[str, dict[str, datetime]] = {}
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
            icmp_sweep = self._check_icmp_sweep(packet)
            if icmp_sweep is not None:
                findings.append(icmp_sweep)
            dns_anomaly = self._check_dns_query_rate(packet)
            if dns_anomaly is not None:
                findings.append(dns_anomaly)
            unsafe_domain = self._check_unsafe_domain(packet)
            if unsafe_domain is not None:
                findings.append(unsafe_domain)
            arp_conflict = self._check_arp_conflict(packet)
            if arp_conflict is not None:
                findings.append(arp_conflict)
            self._prune_cooldowns(packet.timestamp)
            context = self._packet_context(packet)
            return [replace(finding, context=context) for finding in findings]

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

    def _check_icmp_sweep(self, packet: NormalizedPacket) -> DetectionFinding | None:
        if packet.protocol != "ICMP" or packet.icmp_type not in {8, 128}:
            return None
        events = self._events_for(self._icmp_events, packet.source_ip)
        cutoff = packet.timestamp - timedelta(seconds=self._settings.icmp_sweep_time_window_seconds)
        self._prune_events(events, cutoff)
        events.append((packet.timestamp, packet.destination_ip))
        self._cap_events(events)
        destinations = len({destination for _, destination in events})
        if destinations < self._settings.icmp_sweep_destination_threshold or not self._ready("ICMP_SWEEP", packet.source_ip, packet.timestamp):
            return None
        threshold = self._settings.icmp_sweep_destination_threshold
        return DetectionFinding(
            timestamp=packet.timestamp,
            detection_type="ICMP_SWEEP",
            severity="HIGH" if destinations >= threshold * 2 else "MEDIUM",
            source_ip=packet.source_ip,
            destination_ip=packet.destination_ip,
            observed_value=destinations,
            threshold=threshold,
            evidence=(
                f"{packet.source_ip} sent ICMP echo requests to {destinations} unique destinations "
                f"within {self._settings.icmp_sweep_time_window_seconds} seconds (threshold: {threshold})."
            ),
        )

    def _check_dns_query_rate(self, packet: NormalizedPacket) -> DetectionFinding | None:
        if packet.dns_query_name is None:
            return None
        events = self._events_for(self._dns_events, packet.source_ip)
        cutoff = packet.timestamp - timedelta(seconds=self._settings.dns_query_time_window_seconds)
        self._prune_events(events, cutoff)
        events.append(packet.timestamp)
        self._cap_events(events)
        query_count = len(events)
        if query_count < self._settings.dns_query_rate_threshold or not self._ready("DNS_QUERY_ANOMALY", packet.source_ip, packet.timestamp):
            return None
        threshold = self._settings.dns_query_rate_threshold
        return DetectionFinding(
            timestamp=packet.timestamp,
            detection_type="DNS_QUERY_ANOMALY",
            severity="HIGH" if query_count >= threshold * 2 else "MEDIUM",
            source_ip=packet.source_ip,
            destination_ip=packet.destination_ip,
            observed_value=query_count,
            threshold=threshold,
            evidence=(
                f"{packet.source_ip} made {query_count} DNS queries within "
                f"{self._settings.dns_query_time_window_seconds} second(s) (threshold: {threshold})."
            ),
        )

    def _check_unsafe_domain(self, packet: NormalizedPacket) -> DetectionFinding | None:
        if not packet.dns_query_name:
            return None
        domain = packet.dns_query_name.rstrip(".").lower()
        indicator = next((item for item in self._settings.unsafe_domains if domain == item or domain.endswith(f".{item}")), None)
        if indicator is None or not self._ready("SUSPICIOUS_DOMAIN", domain, packet.timestamp):
            return None
        return DetectionFinding(
            timestamp=packet.timestamp, detection_type="SUSPICIOUS_DOMAIN", severity="HIGH",
            source_ip=packet.source_ip, destination_ip=packet.destination_ip, observed_value=1, threshold=1,
            evidence=f"DNS query for {domain} matched the configured local threat-domain indicator {indicator}.",
            confidence=0.9, source="local_domain_indicator",
            recommended_investigation="Do not continue to the site. Verify the domain against a trusted threat-intelligence source, inspect the endpoint for downloads, and block the domain at DNS/firewall level if confirmed.",
            context={"dns_query_name": domain, "matched_indicator": indicator},
        )

    def _check_arp_conflict(self, packet: NormalizedPacket) -> DetectionFinding | None:
        """Flag conflicting ARP replies; this is a warning, not proof of an attack."""
        if packet.protocol != "ARP" or packet.arp_operation != 2 or not packet.arp_source_ip or not packet.arp_source_mac:
            return None
        cutoff = packet.timestamp - timedelta(seconds=self._settings.arp_conflict_time_window_seconds)
        claims = self._arp_claims.setdefault(packet.arp_source_ip, {})
        for mac, last_seen in list(claims.items()):
            if last_seen < cutoff:
                del claims[mac]
        claims[packet.arp_source_mac] = packet.timestamp
        mac_count = len(claims)
        subject = packet.arp_source_ip
        if mac_count < self._settings.arp_conflict_mac_threshold or not self._ready("ARP_SPOOFING_SUSPECTED", subject, packet.timestamp):
            return None
        return DetectionFinding(
            timestamp=packet.timestamp,
            detection_type="ARP_SPOOFING_SUSPECTED",
            severity="HIGH" if mac_count > self._settings.arp_conflict_mac_threshold else "MEDIUM",
            source_ip=packet.arp_source_ip,
            destination_ip=packet.arp_target_ip,
            observed_value=mac_count,
            threshold=self._settings.arp_conflict_mac_threshold,
            evidence=(
                f"ARP conflict: {packet.arp_source_ip} was claimed by {mac_count} MAC addresses within "
                f"{self._settings.arp_conflict_time_window_seconds} seconds. This may indicate ARP spoofing "
                f"or a legitimate high-availability/network change."
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

    @staticmethod
    def _packet_context(packet: NormalizedPacket) -> dict[str, Any]:
        """Keep safe header metadata with an alert; application payloads stay excluded."""
        context: dict[str, Any] = {
            "telemetry_type": _packet_type(packet),
            "protocol": packet.protocol,
            "packet_size_bytes": packet.size_bytes,
            "source_ip": packet.source_ip,
            "destination_ip": packet.destination_ip,
        }
        if packet.source_port is not None:
            source = describe_port(packet.source_port)
            context.update(source_port=source.number, source_port_label=source.label, source_port_description=source.description)
        if packet.destination_port is not None:
            destination = describe_port(packet.destination_port)
            context.update(destination_port=destination.number, destination_port_label=destination.label, destination_port_description=destination.description)
        if packet.tcp_flags:
            context["tcp_flags"] = packet.tcp_flags
        if packet.dns_query_name:
            context["dns_query_name"] = packet.dns_query_name
        if packet.icmp_type is not None:
            context.update(icmp_type=packet.icmp_type, icmp_code=packet.icmp_code)
        if packet.arp_operation is not None:
            context.update(arp_operation=packet.arp_operation, arp_source_mac=packet.arp_source_mac, arp_target_mac=packet.arp_target_mac)
        return context


def _packet_type(packet: NormalizedPacket) -> str:
    if packet.protocol == "TCP":
        return f"TCP packet ({packet.tcp_flags or 'no flags'})"
    if packet.protocol == "UDP":
        return "UDP datagram"
    if packet.protocol == "ICMP":
        names = {0: "echo reply", 8: "echo request", 128: "echo request", 129: "echo reply"}
        return f"ICMP {names.get(packet.icmp_type, 'message')}"
    if packet.protocol == "ARP":
        return "ARP reply" if packet.arp_operation == 2 else "ARP request"
    return "Network packet"
