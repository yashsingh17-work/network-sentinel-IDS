from datetime import datetime, timezone

from fastapi.testclient import TestClient

from backend.capture import InMemoryPacketCapture
from backend.config import Settings
from backend.main import create_app
from backend.services import build_services
from backend.sources import SuricataNormalizer, WindowsEventNormalizer, ZeekNormalizer


def _client(tmp_path):
    services = build_services(
        Settings(
            database_path=str(tmp_path / "events.db"),
            auth_failure_threshold=2,
            traffic_rate_threshold=100,
            port_scan_port_threshold=100,
            syn_rate_threshold=100,
        ),
        capture=InMemoryPacketCapture(),
    )
    return TestClient(create_app(services))


def test_normalizers_preserve_source_specific_metadata() -> None:
    zeek = ZeekNormalizer().normalize({"ts": 1_700_000_000, "id.orig_h": "10.0.0.5", "id.resp_h": "10.0.0.7", "id.orig_p": 50000, "id.resp_p": 443, "proto": "tcp", "orig_bytes": 25, "resp_bytes": 75})
    suricata = SuricataNormalizer().normalize({"timestamp": "2026-01-01T00:00:00Z", "event_type": "alert", "src_ip": "10.0.0.5", "dest_ip": "10.0.0.7", "proto": "TCP", "alert": {"signature": "Test rule", "severity": 2}})
    windows = WindowsEventNormalizer().normalize({"timestamp": "2026-01-01T00:00:00Z", "EventID": 4625, "TargetUserName": "sam", "IpAddress": "10.0.0.5"})

    assert zeek.event_type == "network_connection" and zeek.bytes_count == 100
    assert suricata.event_type == "ids_alert" and suricata.metadata["signature"] == "Test rule"
    assert windows.event_type == "authentication_failure" and windows.metadata["user"] == "sam"


def test_event_api_correlates_authentication_failures_and_persists_events(tmp_path) -> None:
    with _client(tmp_path) as client:
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(), "source": "windows_event_log",
            "event_type": "authentication_failure", "source_ip": "10.0.0.5", "metadata": {"user": "sam"},
        }
        assert client.post("/api/events", json=event).json()["alerts"] == []
        result = client.post("/api/events", json=event)

        assert result.status_code == 202
        assert result.json()["alerts"][0]["detection_type"] == "AUTH_FAILURE_BURST"
        assert client.get("/api/events/recent").json()[0]["source"] == "windows_event_log"


def test_event_api_turns_suricata_signature_into_explainable_alert(tmp_path) -> None:
    with _client(tmp_path) as client:
        response = client.post(
            "/api/events",
            json={
                "timestamp": datetime.now(timezone.utc).isoformat(), "source": "suricata", "event_type": "ids_alert",
                "source_ip": "10.0.0.5", "destination_ip": "10.0.0.7", "metadata": {"signature": "Potential exploit", "signature_id": 123, "severity": 2},
            },
        )

    alert = response.json()["alerts"][0]
    assert alert["detection_type"] == "SURICATA_SIGNATURE"
    assert alert["severity"] == "HIGH"
    assert "Potential exploit" in alert["evidence"]


def test_safe_demo_creates_local_investigation_data(tmp_path) -> None:
    with _client(tmp_path) as client:
        response = client.post("/api/demo/run")

    assert response.status_code == 200
    detections = {alert["detection_type"] for alert in response.json()["alerts"]}
    assert {"PORT_SCAN", "AUTH_FAILURE_BURST", "SUSPICIOUS_AUTH_SEQUENCE", "SURICATA_SIGNATURE", "ZEEK_NETWORK_ANOMALY"} <= detections
