from datetime import datetime, timedelta, timezone

from backend.analyzer.traffic_analyzer import TrafficAnalyzer
from backend.config import Settings
from backend.models import NormalizedPacket


NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def packet(**overrides: object) -> NormalizedPacket:
    values: dict[str, object] = {
        "timestamp": NOW,
        "source_ip": "10.0.0.10",
        "destination_ip": "10.0.0.20",
        "protocol": "TCP",
        "source_port": 40000,
        "destination_port": 443,
        "tcp_flags": "S",
        "size_bytes": 100,
    }
    values.update(overrides)
    return NormalizedPacket(**values)  # type: ignore[arg-type]


def analyzer(**settings: int) -> TrafficAnalyzer:
    return TrafficAnalyzer(Settings(**settings))


def test_tracks_packet_byte_protocol_and_endpoint_statistics() -> None:
    subject = analyzer()
    subject.ingest(packet())
    subject.ingest(packet(protocol="UDP", source_port=5353, destination_port=53, size_bytes=70))
    subject.ingest(packet(protocol="ICMP", source_port=None, destination_port=None, size_bytes=50))

    snapshot = subject.snapshot(NOW)

    assert (snapshot.total_packets, snapshot.total_bytes) == (3, 220)
    assert snapshot.protocols == {"TCP": 1, "UDP": 1, "ICMP": 1}
    assert snapshot.top_source_ips[0].value == "10.0.0.10"
    assert snapshot.top_destination_ports[0].value in {443, 53}


def test_calculates_one_second_rolling_rates() -> None:
    subject = analyzer(rate_window_seconds=1)
    subject.ingest(packet(timestamp=NOW - timedelta(milliseconds=500), size_bytes=100))
    subject.ingest(packet(timestamp=NOW - timedelta(seconds=2), size_bytes=500))

    snapshot = subject.snapshot(NOW)

    assert snapshot.packets_per_second == 1.0
    assert snapshot.bytes_per_second == 100.0


def test_tracks_a_connection_once_and_expires_it() -> None:
    subject = analyzer(connection_ttl_seconds=10)
    subject.ingest(packet())
    subject.ingest(packet(size_bytes=250))

    current = subject.snapshot(NOW)
    expired = subject.snapshot(NOW + timedelta(seconds=11))

    assert (current.connections.active_connections, current.connections.total_connections_seen) == (1, 1)
    assert expired.connections.active_connections == 0
    assert expired.connections.total_connections_seen == 1


def test_normal_traffic_does_not_create_or_mutate_detection_state() -> None:
    subject = analyzer()
    for offset in range(3):
        subject.ingest(packet(timestamp=NOW + timedelta(milliseconds=offset * 100)))

    snapshot = subject.snapshot(NOW + timedelta(milliseconds=300))

    assert snapshot.total_packets == 3
    assert snapshot.connections.active_connections == 1
