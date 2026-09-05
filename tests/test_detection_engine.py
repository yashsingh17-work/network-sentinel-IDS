from datetime import datetime, timedelta, timezone

from backend.config import Settings
from backend.detection import DetectionEngine
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
        "tcp_flags": "PA",
        "size_bytes": 100,
    }
    values.update(overrides)
    return NormalizedPacket(**values)  # type: ignore[arg-type]


def engine(**overrides: int) -> DetectionEngine:
    defaults = {"port_scan_port_threshold": 100, "syn_rate_threshold": 100, "traffic_rate_threshold": 100}
    defaults.update(overrides)
    return DetectionEngine(Settings(**defaults))


def test_detects_port_scan_and_explains_it() -> None:
    subject = engine(port_scan_port_threshold=3)

    findings = []
    for port in (20, 21, 22):
        findings = subject.analyze(packet(destination_port=port))

    assert len(findings) == 1
    finding = findings[0]
    assert (finding.detection_type, finding.observed_value, finding.threshold) == ("PORT_SCAN", 3, 3)
    assert "3 unique destination ports" in finding.evidence


def test_detects_high_initial_syn_rate_but_not_syn_ack() -> None:
    subject = engine(syn_rate_threshold=3)

    assert subject.analyze(packet(tcp_flags="SA")) == []
    subject.analyze(packet(tcp_flags="S"))
    subject.analyze(packet(tcp_flags="S"))
    findings = subject.analyze(packet(tcp_flags="S"))

    assert len(findings) == 1
    assert findings[0].detection_type == "SYN_FLOOD"
    assert findings[0].severity == "MEDIUM"


def test_detects_aggregate_traffic_rate_anomaly() -> None:
    subject = engine(traffic_rate_threshold=3)

    subject.analyze(packet())
    subject.analyze(packet())
    findings = subject.analyze(packet())

    assert len(findings) == 1
    assert findings[0].detection_type == "TRAFFIC_RATE_ANOMALY"
    assert "3 packets across all traffic" in findings[0].evidence


def test_cooldown_prevents_duplicate_alerts_until_it_expires() -> None:
    subject = engine(port_scan_port_threshold=2, alert_cooldown_seconds=10)
    subject.analyze(packet(destination_port=80))
    first = subject.analyze(packet(destination_port=443))
    suppressed = subject.analyze(packet(destination_port=8080))
    subject.analyze(packet(destination_port=8443, timestamp=NOW + timedelta(seconds=11)))
    after_cooldown = subject.analyze(packet(destination_port=9443, timestamp=NOW + timedelta(seconds=11)))

    assert len(first) == 1
    assert suppressed == []
    assert len(after_cooldown) == 1


def test_normal_traffic_does_not_trigger_any_detection() -> None:
    subject = engine(port_scan_port_threshold=5, syn_rate_threshold=5, traffic_rate_threshold=10)

    findings = []
    for offset in range(4):
        findings.extend(subject.analyze(packet(timestamp=NOW + timedelta(seconds=offset * 2))))

    assert findings == []
