from datetime import datetime, timezone

from fastapi.testclient import TestClient

from backend.config import Settings
from backend.capture import InMemoryPacketCapture
from backend.main import create_app
from backend.models import NormalizedPacket
from backend.services import build_services


def packet(destination_port: int) -> NormalizedPacket:
    return NormalizedPacket(
        timestamp=datetime.now(timezone.utc),
        source_ip="10.0.0.10",
        destination_ip="10.0.0.20",
        protocol="TCP",
        source_port=40000,
        destination_port=destination_port,
        tcp_flags="PA",
        size_bytes=100,
    )


def client_and_services(tmp_path):
    settings = Settings(
        database_path=str(tmp_path / "api-alerts.db"),
        port_scan_port_threshold=2,
        syn_rate_threshold=100,
        traffic_rate_threshold=100,
        icmp_sweep_destination_threshold=100,
        dns_query_rate_threshold=100,
    )
    services = build_services(settings, capture=InMemoryPacketCapture())
    return TestClient(create_app(services)), services


def test_monitoring_lifecycle_and_traffic_endpoints(tmp_path) -> None:
    client, services = client_and_services(tmp_path)

    assert client.get("/api/monitoring/status").json()["active"] is False
    started = client.post("/api/monitoring/start").json()
    services.monitoring.process(packet(443))

    assert started["active"] is True
    assert started["capture_ready"] is True
    assert client.get("/api/traffic/overall").json()["total_packets"] == 1
    assert client.get("/api/traffic/protocols").json()["protocols"] == {"TCP": 1}
    assert client.get("/api/traffic/top-ips").json()["sources"][0]["value"] == "10.0.0.10"
    assert client.get("/api/traffic/top-ports").json()["destinations"][0]["value"] == 443
    assert client.get("/api/traffic/top-ports").json()["destinations"][0]["label"] == "443 (HTTPS)"
    assert client.get("/api/traffic/connections").json()["active_connections"] == 1
    assert client.post("/api/monitoring/stop").json()["active"] is False


def test_alert_endpoints_return_history_and_details(tmp_path) -> None:
    client, services = client_and_services(tmp_path)
    client.post("/api/monitoring/start")
    services.monitoring.process(packet(80))
    generated = services.monitoring.process(packet(443))

    recent = client.get("/api/alerts/recent")
    history = client.get("/api/alerts/history?limit=10&offset=0")
    details = client.get(f"/api/alerts/{generated[0].id}")

    assert recent.status_code == 200
    assert recent.json()[0]["detection_type"] == "PORT_SCAN"
    assert history.json()["alerts"][0]["id"] == generated[0].id
    assert details.json()["evidence"]
    assert details.json()["context"]["destination_port_label"] == "443 (HTTPS)"
    assert client.get("/api/alerts/missing").status_code == 404
