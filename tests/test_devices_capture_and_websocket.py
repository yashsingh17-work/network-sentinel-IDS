from datetime import datetime, timezone

from fastapi.testclient import TestClient

from backend.analyzer import DeviceTracker
from backend.capture import InMemoryPacketCapture
from backend.config import Settings
from backend.main import create_app
from backend.models import NormalizedPacket
from backend.services import build_services


NOW = datetime.now(timezone.utc)


def arp_packet(mac: str) -> NormalizedPacket:
    return NormalizedPacket(
        timestamp=NOW,
        source_ip="192.168.1.10",
        destination_ip="192.168.1.1",
        protocol="ARP",
        source_port=None,
        destination_port=None,
        tcp_flags=None,
        size_bytes=42,
        arp_operation=2,
        arp_source_ip="192.168.1.10",
        arp_source_mac=mac,
        arp_target_ip="192.168.1.1",
        arp_target_mac="aa:bb:cc:dd:ee:ff",
    )


def test_device_tracker_groups_packets_by_mac() -> None:
    tracker = DeviceTracker(Settings())
    tracker.ingest(arp_packet("aa:bb:cc:dd:ee:01"))

    devices = tracker.snapshot(NOW)

    assert len(devices) == 1
    assert devices[0].mac_address == "aa:bb:cc:dd:ee:01"
    assert devices[0].ip_addresses == ["192.168.1.10"]


def test_in_memory_capture_drives_full_pipeline_and_websocket(tmp_path) -> None:
    capture = InMemoryPacketCapture()
    settings = Settings(database_path=str(tmp_path / "live.db"), auto_start_monitoring=False, port_scan_port_threshold=100, syn_rate_threshold=100, traffic_rate_threshold=100)
    services = build_services(settings, capture=capture)
    app = create_app(services)

    with TestClient(app) as client:
        with client.websocket_connect("/ws") as websocket:
            initial = websocket.receive_json()
            assert initial["type"] == "dashboard_update"
            assert client.post("/api/monitoring/start").json()["active"] is True
            capture.emit(arp_packet("aa:bb:cc:dd:ee:01"))
            assert client.get("/api/traffic/overall").json()["total_packets"] == 1
            assert client.get("/api/devices").json()[0]["mac_address"] == "aa:bb:cc:dd:ee:01"
