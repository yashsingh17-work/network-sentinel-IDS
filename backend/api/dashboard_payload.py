"""Serialization shared by the WebSocket dashboard feed."""

from __future__ import annotations

from typing import Any

from backend.alerts import Alert
from backend.services import ApplicationServices


def alert_payload(alert: Alert) -> dict[str, Any]:
    return {
        "id": alert.id,
        "timestamp": alert.timestamp.isoformat(),
        "detection_type": alert.detection_type,
        "severity": alert.severity,
        "source_ip": alert.source_ip,
        "destination_ip": alert.destination_ip,
        "observed_value": alert.observed_value,
        "threshold": alert.threshold,
        "evidence": alert.evidence,
        "confidence": alert.confidence,
        "recommended_investigation": alert.recommended_investigation,
        "source": alert.source,
    }


def dashboard_payload(services: ApplicationServices) -> dict[str, Any]:
    snapshot = services.analyzer.snapshot()
    status = services.monitoring.status()
    wifi = services.wifi_security.status()
    return {
        "type": "dashboard_update",
        "data": {
            "monitoring": {
                "active": status.active,
                "started_at": status.started_at.isoformat() if status.started_at else None,
                "capture_ready": status.capture_ready,
                "interface": status.interface,
                "last_error": status.last_error,
                "packets_captured": status.packets_captured,
            },
            "overall": {
                "total_packets": snapshot.total_packets,
                "total_bytes": snapshot.total_bytes,
                "packets_per_second": snapshot.packets_per_second,
                "bytes_per_second": snapshot.bytes_per_second,
                "total_alerts": len(services.repository.get_recent(500)),
            },
            "protocols": snapshot.protocols,
            "top_sources": [_ranked_ip(item.value, item.count, services) for item in snapshot.top_source_ips],
            "top_destinations": [_ranked_ip(item.value, item.count, services) for item in snapshot.top_destination_ips],
            "top_ports": [item.__dict__ if hasattr(item, "__dict__") else {"value": item.value, "count": item.count} for item in snapshot.top_destination_ports],
            "connections": {"active_connections": snapshot.connections.active_connections, "total_connections_seen": snapshot.connections.total_connections_seen},
            "devices": [
                {
                    "mac_address": device.mac_address,
                    "ip_addresses": device.ip_addresses,
                    "last_seen": device.last_seen.isoformat(),
                    "packets_seen": device.packets_seen,
                    "protocols": device.protocols,
                }
                for device in services.device_tracker.snapshot()
            ],
            "wifi": {
                "available": wifi.available,
                "connected": wifi.connected,
                "ssid": wifi.ssid,
                "authentication": wifi.authentication,
                "cipher": wifi.cipher,
                "secure": wifi.secure,
                "summary": wifi.summary,
            },
        },
    }


def _ranked_ip(value: str | int, count: int, services: ApplicationServices) -> dict[str, Any]:
    return {
        "value": value,
        "count": count,
        "label": services.enrichment.describe(value).label if isinstance(value, str) else None,
    }
