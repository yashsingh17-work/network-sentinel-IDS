"""Serialization shared by the WebSocket dashboard feed."""

from __future__ import annotations

from typing import Any

from backend.alerts import Alert
from backend.enrichment import describe_port
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
        "context": alert.context,
    }


def dashboard_payload(services: ApplicationServices) -> dict[str, Any]:
    snapshot = services.analyzer.snapshot()
    status = services.monitoring.status()
    wifi = services.wifi_security.status()
    profiles = services.device_profiles.profiles()
    downloads = services.endpoint_safety.download_status()
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
            "top_ports": [_ranked_port(item.value, item.count) for item in snapshot.top_destination_ports],
            "connections": {"active_connections": snapshot.connections.active_connections, "total_connections_seen": snapshot.connections.total_connections_seen},
            "devices": [
                {
                    "mac_address": device.mac_address,
                    "ip_addresses": device.ip_addresses,
                    "last_seen": device.last_seen.isoformat(),
                    "packets_seen": device.packets_seen,
                    "protocols": device.protocols,
                    "vendor": device.vendor,
                    "likely_role": device.likely_role,
                    "observed_services": device.observed_services,
                    "display_name": profiles.get(device.mac_address.lower()).display_name if device.mac_address.lower() in profiles else None,
                    "physical_location": profiles.get(device.mac_address.lower()).physical_location if device.mac_address.lower() in profiles else None,
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
            "endpoint_safety": {
                "downloads_enabled": downloads.enabled,
                "downloads_initialized": downloads.initialized,
                "tracked_download_files": downloads.tracked_files,
                "download_directories": downloads.directories,
                "last_download_scan_at": downloads.last_scan_at,
            },
        },
    }


def _ranked_ip(value: str | int, count: int, services: ApplicationServices) -> dict[str, Any]:
    return {
        "value": value,
        "count": count,
        "label": services.enrichment.describe(value).label if isinstance(value, str) else None,
    }


def _ranked_port(value: str | int, count: int) -> dict[str, Any]:
    if not isinstance(value, int):
        return {"value": value, "count": count, "label": str(value), "description": None}
    port = describe_port(value)
    return {"value": value, "count": count, "label": port.label, "description": port.description}
