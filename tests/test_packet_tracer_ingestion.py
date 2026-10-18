from datetime import datetime, timezone

from fastapi.testclient import TestClient

from backend.capture import InMemoryPacketCapture
from backend.config import Settings
from backend.main import create_app
from backend.services import build_services
from pt_traffic_replay import scenario_events


def _client(tmp_path, *, max_packet_history: int = 1_000) -> TestClient:
    services = build_services(
        Settings(
            database_path=str(tmp_path / "packet-tracer.db"), auto_start_monitoring=False,
            port_scan_port_threshold=3, port_scan_time_window_seconds=8,
            icmp_sweep_destination_threshold=3, icmp_sweep_time_window_seconds=10,
            dns_query_rate_threshold=5, dns_query_time_window_seconds=5,
            auth_failure_threshold=3, auth_failure_time_window_seconds=30,
            syn_rate_threshold=100, traffic_rate_threshold=1000, alert_cooldown_seconds=1,
            max_packet_history=max_packet_history,
        ), capture=InMemoryPacketCapture()
    )
    return TestClient(create_app(services))


def _event(**changes):
    value = {
        "timestamp": datetime.now(timezone.utc).isoformat(), "source_ip": "192.168.10.10", "source_port": 49152,
        "dest_ip": "192.168.20.20", "dest_port": 21, "protocol": "TCP", "flags": ["SYN"],
        "payload_size": 64, "raw_data": "", "metadata": {"device_role": "Attacker"},
    }
    value.update(changes)
    return value


def test_packet_tracer_batch_ingestion_reaches_database_and_rules(tmp_path) -> None:
    with _client(tmp_path) as client:
        response = client.post("/api/events/ingest", json={"events": [
            _event(dest_ip="192.168.20.10", dest_port=port, raw_data="TCP SYN connection attempt") for port in (80, 445, 8080)
        ]})
        assert response.status_code == 202
        assert "PORT_SCAN" in {item["detection_type"] for item in response.json()["alerts"]}
        assert len(client.get("/api/events/recent").json()) == 3


def test_packet_tracer_single_event_shape_and_ftp_failures(tmp_path) -> None:
    with _client(tmp_path) as client:
        alerts = []
        for _ in range(3):
            response = client.post("/api/events/ingest", json=_event(raw_data="FTP 530 User cannot log in", flags=[]))
            alerts.extend(response.json()["alerts"])
        assert any(item["detection_type"] == "AUTH_FAILURE_BURST" for item in alerts)


def test_tcp_transport_is_classified_by_destination_port(tmp_path) -> None:
    with _client(tmp_path) as client:
        client.post("/api/events/ingest", json={"events": [
            _event(dest_port=port) for port in (21, 22, 53, 80, 443, 445, 8080)
        ]})
        recent = client.get("/api/events/recent").json()
        by_port = {item["destination_port"]: item["metadata"] for item in recent}
        assert by_port[21]["transport_protocol"] == "TCP"
        assert by_port[21]["likely_application_protocol"] == "FTP"
        assert by_port[22]["likely_application_protocol"] == "SSH"
        assert by_port[53]["likely_application_protocol"] == "DNS"
        assert by_port[80]["likely_application_protocol"] == "HTTP"
        assert by_port[443]["likely_application_protocol"] == "HTTPS"
        assert by_port[445]["likely_application_protocol"] == "SMB"
        assert by_port[8080]["likely_application_protocol"] == "HTTP alternate"


def test_filtered_packet_tracer_records_survive_a_busy_live_history_buffer(tmp_path) -> None:
    """Saved collector records remain investigable after live capture rotates memory."""
    with _client(tmp_path, max_packet_history=1) as client:
        client.post("/api/events/ingest", json={"events": [
            _event(protocol="UDP", dest_port=53, raw_data="DNS query retained.example"),
            _event(protocol="TCP", dest_port=443, raw_data="TCP connection attempt"),
        ]})

        response = client.get("/api/traffic/protocols/UDP/packets?service=DNS")

        assert response.status_code == 200
        records = response.json()
        assert len(records) == 1
        assert records[0]["dns_query_name"] == "DNS query retained.example"


def test_packet_tracer_replay_uses_configured_topology_addresses() -> None:
    settings = Settings(
        packet_tracer_attacker_ip="10.50.10.25",
        packet_tracer_windows_target_ip="10.50.20.10",
        packet_tracer_linux_target_ip="10.50.20.20",
        packet_tracer_dns_server="10.50.20.53",
        packet_tracer_network_zone="10.50.10.0/24",
    )
    events = scenario_events("icmp-sweep", settings)
    assert {event["dest_ip"] for event in events} == {"10.50.20.10", "10.50.20.20", "10.50.20.53"}
    assert {event["source_ip"] for event in events} == {"10.50.10.25"}
    assert {event["metadata"]["network_zone"] for event in events} == {"10.50.10.0/24"}
    port_scan = scenario_events("port-scan", settings)
    assert {event["dest_ip"] for event in port_scan} == {"10.50.20.10"}
    assert {event["dest_port"] for event in port_scan} == {80, 445, 8080}
    baseline = scenario_events("baseline-http", settings)
    assert baseline[0]["source_ip"] == "10.50.20.10"
    assert baseline[0]["dest_ip"] == settings.packet_tracer_dmz_web_server_ip
    assert baseline[0]["dest_port"] == 80
