"""Bounded, in-memory traffic statistics independent from packet capture."""

from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from threading import RLock

from backend.config import Settings
from backend.enrichment import describe_port
from backend.models import NormalizedPacket


@dataclass(frozen=True, slots=True)
class RankedValue:
    value: str | int
    count: int


@dataclass(frozen=True, slots=True)
class ConnectionStatistics:
    active_connections: int
    total_connections_seen: int


@dataclass(frozen=True, slots=True)
class TrafficSnapshot:
    total_packets: int
    total_bytes: int
    packets_per_second: float
    bytes_per_second: float
    protocols: dict[str, int]
    top_source_ips: list[RankedValue]
    top_destination_ips: list[RankedValue]
    top_destination_ports: list[RankedValue]
    connections: ConnectionStatistics


@dataclass(frozen=True, slots=True)
class PacketObservation:
    """A bounded, header-only record retained for the dashboard investigator."""

    timestamp: datetime
    source_ip: str
    destination_ip: str
    protocol: str
    source_port: int | None
    destination_port: int | None
    tcp_flags: str | None
    size_bytes: int
    source_mac: str | None
    destination_mac: str | None
    dns_query_name: str | None
    icmp_type: int | None
    dhcp_message_type: str | None
    dhcp_server_id: str | None
    triggered_alert_types: tuple[str, ...]
    alert_evidence: tuple[str, ...]


@dataclass(slots=True)
class _Connection:
    last_seen: datetime
    packets: int = 0
    bytes: int = 0


class _BoundedCounter:
    """Fixed-size approximate heavy-hitter counter (Space-Saving algorithm)."""

    def __init__(self, capacity: int) -> None:
        self._capacity = capacity
        self._counts: Counter[str | int] = Counter()

    def add(self, value: str | int) -> None:
        if value in self._counts:
            self._counts[value] += 1
        elif len(self._counts) < self._capacity:
            self._counts[value] = 1
        else:
            evicted, minimum = min(self._counts.items(), key=lambda entry: entry[1])
            del self._counts[evicted]
            self._counts[value] = minimum + 1

    def top(self, limit: int) -> list[RankedValue]:
        return [RankedValue(value=value, count=count) for value, count in self._counts.most_common(limit)]


class TrafficAnalyzer:
    """Maintains responsive statistics without retaining raw packet history."""

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or Settings.from_env()
        self._lock = RLock()
        self._total_packets = 0
        self._total_bytes = 0
        self._protocols: Counter[str] = Counter()
        self._recent_rates: deque[tuple[datetime, int]] = deque()
        self._sources = _BoundedCounter(self._settings.max_tracked_endpoints)
        self._destinations = _BoundedCounter(self._settings.max_tracked_endpoints)
        self._ports = _BoundedCounter(self._settings.max_tracked_ports)
        self._connections: dict[tuple[str, int, str, int, str], _Connection] = {}
        self._total_connections_seen = 0
        self._packet_history: deque[PacketObservation] = deque(maxlen=self._settings.max_packet_history)

    def ingest(self, packet: NormalizedPacket, received_at: datetime | None = None) -> None:
        """Record one normalized packet using arrival time for live throughput.

        Event timestamps describe when something happened. Throughput must instead
        measure when Network Sentinel received telemetry; otherwise importing old
        Zeek/Windows records permanently displays zero packets per second.
        """
        observed_at = received_at or datetime.now(timezone.utc)
        with self._lock:
            self._total_packets += 1
            self._total_bytes += packet.size_bytes
            self._protocols[packet.protocol] += 1
            self._packet_history.append(PacketObservation(
                timestamp=packet.timestamp, source_ip=packet.source_ip, destination_ip=packet.destination_ip,
                protocol=packet.protocol, source_port=packet.source_port, destination_port=packet.destination_port,
                tcp_flags=packet.tcp_flags, size_bytes=packet.size_bytes, source_mac=packet.source_mac,
                destination_mac=packet.destination_mac, dns_query_name=packet.dns_query_name, icmp_type=packet.icmp_type,
                dhcp_message_type=packet.dhcp_message_type, dhcp_server_id=packet.dhcp_server_id,
                triggered_alert_types=(), alert_evidence=(),
            ))
            self._recent_rates.append((observed_at, packet.size_bytes))
            self._sources.add(packet.source_ip)
            self._destinations.add(packet.destination_ip)
            if packet.destination_port is not None:
                self._ports.add(packet.destination_port)
            self._track_connection(packet)
            self._prune(packet.timestamp)

    def snapshot(self, now: datetime | None = None, *, top_limit: int = 10) -> TrafficSnapshot:
        current_time = now or datetime.now(timezone.utc)
        with self._lock:
            self._prune(current_time)
            rate_cutoff = current_time - timedelta(seconds=self._settings.rate_window_seconds)
            rate_events = [(timestamp, size) for timestamp, size in self._recent_rates if timestamp >= rate_cutoff]
            window = self._settings.rate_window_seconds
            return TrafficSnapshot(
                total_packets=self._total_packets,
                total_bytes=self._total_bytes,
                packets_per_second=len(rate_events) / window,
                bytes_per_second=sum(size for _, size in rate_events) / window,
                protocols=dict(self._protocols),
                top_source_ips=self._sources.top(top_limit),
                top_destination_ips=self._destinations.top(top_limit),
                top_destination_ports=self._ports.top(top_limit),
                connections=ConnectionStatistics(
                    active_connections=len(self._connections),
                    total_connections_seen=self._total_connections_seen,
                ),
            )

    def recent_packets(
        self, *, protocol: str | None = None, mac_address: str | None = None,
        source_ip: str | None = None, destination_ip: str | None = None,
        destination_port: int | None = None, service: str | None = None, limit: int = 100,
    ) -> list[PacketObservation]:
        """Return newest-first records from the bounded header history."""
        normalized_protocol = protocol.upper() if protocol else None
        normalized_mac = mac_address.lower().replace("-", ":") if mac_address else None
        with self._lock:
            selected: list[PacketObservation] = []
            for item in reversed(self._packet_history):
                if normalized_protocol and item.protocol != normalized_protocol:
                    continue
                if normalized_mac and normalized_mac not in {(item.source_mac or "").lower(), (item.destination_mac or "").lower()}:
                    continue
                if source_ip and item.source_ip != source_ip:
                    continue
                if destination_ip and item.destination_ip != destination_ip:
                    continue
                if destination_port is not None and item.destination_port != destination_port:
                    continue
                if service and (item.destination_port is None or describe_port(item.destination_port).service.casefold() != service.casefold()):
                    continue
                selected.append(item)
                if len(selected) >= limit:
                    break
            return selected

    def annotate_packet_alerts(self, packet: NormalizedPacket, alerts: list[object]) -> None:
        """Attach only persisted alerts to the matching header record for packet-level explanations."""
        if not alerts:
            return
        alert_types = tuple(str(getattr(alert, "detection_type", "Security finding")) for alert in alerts)
        evidence = tuple(str(getattr(alert, "evidence", "")) for alert in alerts if getattr(alert, "evidence", None))
        with self._lock:
            for index in range(len(self._packet_history) - 1, -1, -1):
                observed = self._packet_history[index]
                if (
                    observed.timestamp == packet.timestamp and observed.source_ip == packet.source_ip
                    and observed.destination_ip == packet.destination_ip and observed.protocol == packet.protocol
                    and observed.source_port == packet.source_port and observed.destination_port == packet.destination_port
                ):
                    self._packet_history[index] = replace(
                        observed, triggered_alert_types=alert_types, alert_evidence=evidence,
                    )
                    return

    def _track_connection(self, packet: NormalizedPacket) -> None:
        if packet.source_port is None or packet.destination_port is None:
            return
        key = (packet.source_ip, packet.source_port, packet.destination_ip, packet.destination_port, packet.protocol)
        connection = self._connections.get(key)
        if connection is None:
            if len(self._connections) >= self._settings.max_connections:
                oldest_key = min(self._connections, key=lambda entry: self._connections[entry].last_seen)
                del self._connections[oldest_key]
            self._connections[key] = _Connection(last_seen=packet.timestamp, packets=1, bytes=packet.size_bytes)
            self._total_connections_seen += 1
        else:
            connection.last_seen = packet.timestamp
            connection.packets += 1
            connection.bytes += packet.size_bytes

    def _prune(self, now: datetime) -> None:
        history_cutoff = now - timedelta(seconds=self._settings.history_window_seconds)
        while self._recent_rates and self._recent_rates[0][0] < history_cutoff:
            self._recent_rates.popleft()
        connection_cutoff = now - timedelta(seconds=self._settings.connection_ttl_seconds)
        stale = [key for key, connection in self._connections.items() if connection.last_seen < connection_cutoff]
        for key in stale:
            del self._connections[key]
