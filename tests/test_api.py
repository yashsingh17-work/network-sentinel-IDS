from dataclasses import replace
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
        auto_start_monitoring=False,
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


def test_packet_tracer_scenarios_are_local_and_explainable(tmp_path) -> None:
    client, _ = client_and_services(tmp_path)

    scenarios = client.get("/api/demo/packet-tracer/scenarios")
    run = client.post("/api/demo/packet-tracer/tcp-port-scan")

    assert scenarios.status_code == 200
    assert {item["scenario_id"] for item in scenarios.json()} >= {"icmp-sweep", "tcp-port-scan", "dns-burst", "ftp-brute-force", "arp-conflict"}
    assert run.status_code == 200
    assert run.json()["scenario"]["scenario_id"] == "tcp-port-scan"
    assert run.json()["events_created"] == 3
    assert run.json()["alerts"][0]["detection_type"] == "PORT_SCAN"


def test_packet_tracer_scenes_use_the_canonical_lab_flows(tmp_path) -> None:
    profile = Settings.from_env("config.packet-tracer.yaml")
    services = build_services(
        replace(profile, database_path=str(tmp_path / "canonical-lab.db"), auto_start_monitoring=False),
        capture=InMemoryPacketCapture(),
    )
    client = TestClient(create_app(services))

    expected_detection = {
        "icmp-sweep": "ICMP_SWEEP",
        "tcp-port-scan": "PORT_SCAN",
        "dns-burst": "DNS_QUERY_ANOMALY",
        "ftp-brute-force": "AUTH_FAILURE_BURST",
        "arp-conflict": "ARP_SPOOFING_SUSPECTED",
    }
    for scenario_id, detection_type in expected_detection.items():
        response = client.post(f"/api/demo/packet-tracer/{scenario_id}")
        assert response.status_code == 200
        assert response.json()["scenario"]["scenario_id"] == scenario_id
        assert any(alert["detection_type"] == detection_type for alert in response.json()["alerts"])

    ftp_packets = client.get("/api/traffic/protocols/TCP/packets?service=FTP").json()
    assert len(ftp_packets) == profile.auth_failure_threshold
    assert {packet["destination_port"] for packet in ftp_packets} == {21}
    assert {packet["destination_ip"] for packet in ftp_packets} == {profile.packet_tracer_linux_target_ip}

    baseline = client.post("/api/demo/packet-tracer/baseline-http")
    assert baseline.status_code == 200
    assert baseline.json()["events_created"] == 3
    assert baseline.json()["alerts"] == []


def test_observed_device_profile_is_user_provided(tmp_path) -> None:
    client, services = client_and_services(tmp_path)
    client.post("/api/monitoring/start")
    observed = packet(443)
    observed = replace(observed, source_mac="00:25:96:aa:10:01")
    services.monitoring.process(observed)

    response = client.put(
        "/api/devices/00:25:96:aa:10:01/profile",
        json={"display_name": "Lab web server", "physical_location": "Lab A rack"},
    )
    device = client.get("/api/devices").json()[0]

    assert response.status_code == 200
    assert device["vendor"] == "Cisco Systems"
    assert device["display_name"] == "Lab web server"
    assert device["physical_location"] == "Lab A rack"


def test_packet_investigator_filters_by_service_and_keeps_packet_alert_reason(tmp_path) -> None:
    client, services = client_and_services(tmp_path)
    client.post("/api/monitoring/start")
    services.monitoring.process(packet(21))
    services.monitoring.process(packet(443))

    ftp_packets = client.get("/api/traffic/protocols/ALL/packets?service=FTP").json()
    https_packets = client.get("/api/traffic/protocols/TCP/packets?service=HTTPS").json()

    assert len(ftp_packets) == 1
    assert ftp_packets[0]["likely_application_protocol"] == "FTP"
    assert ftp_packets[0]["triggered_alert_types"] == ["INSECURE_SERVICE_OBSERVED"]
    assert "does not encrypt" in ftp_packets[0]["alert_evidence"][0]
    assert len(https_packets) == 1
    assert https_packets[0]["likely_application_protocol"] == "HTTPS"
