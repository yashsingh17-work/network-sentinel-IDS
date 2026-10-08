"""Central, environment-configurable application settings."""

from __future__ import annotations

from dataclasses import dataclass
from os import getenv
from pathlib import Path
from typing import Any

import yaml


def _positive_int(name: str, default: int) -> int:
    value = int(getenv(name, str(default)))
    if value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


def _nested(document: dict[str, Any], *keys: str, default: Any) -> Any:
    value: Any = document
    for key in keys:
        if not isinstance(value, dict) or key not in value:
            return default
        value = value[key]
    return value


def _load_config(path: str) -> dict[str, Any]:
    config_path = Path(path)
    if not config_path.exists():
        return {}
    with config_path.open(encoding="utf-8") as handle:
        document = yaml.safe_load(handle) or {}
    if not isinstance(document, dict):
        raise ValueError("Configuration root must be a mapping.")
    return document


@dataclass(frozen=True, slots=True)
class Settings:
    """Application settings loaded from config.yaml and optionally overridden by environment variables."""

    port_scan_port_threshold: int = 50
    port_scan_time_window_seconds: int = 10
    syn_rate_threshold: int = 100
    syn_time_window_seconds: int = 1
    traffic_rate_threshold: int = 1_000
    traffic_rate_window_seconds: int = 1
    icmp_sweep_destination_threshold: int = 20
    icmp_sweep_time_window_seconds: int = 10
    dns_query_rate_threshold: int = 100
    dns_query_time_window_seconds: int = 10
    arp_conflict_time_window_seconds: int = 120
    arp_conflict_mac_threshold: int = 2
    alert_cooldown_seconds: int = 60
    rate_window_seconds: int = 1
    history_window_seconds: int = 60
    max_tracked_endpoints: int = 500
    max_tracked_ports: int = 500
    max_connections: int = 10_000
    connection_ttl_seconds: int = 300
    max_detector_events_per_key: int = 10_000
    database_path: str = "network_sentinel.db"
    max_tracked_devices: int = 500
    device_ttl_seconds: int = 3_600
    capture_interface: str | None = None
    wifi_status_refresh_seconds: int = 30
    auth_failure_threshold: int = 5
    auth_failure_time_window_seconds: int = 300
    suspicious_auth_sequence_window_seconds: int = 600
    packet_capture_enabled: bool = True
    zeek_enabled: bool = False
    suricata_enabled: bool = False
    windows_events_enabled: bool = False
    synthetic_enabled: bool = True
    storage_backend: str = "sqlite"
    node_red_webhook_url: str | None = None

    @classmethod
    def from_env(cls) -> "Settings":
        document = _load_config(getenv("CONFIG_PATH", "config.yaml"))
        detection = _nested(document, "detection", default={})
        sources = _nested(document, "sources", default={})
        storage = _nested(document, "storage", default={})

        def number(name: str, yaml_key: str, fallback: int) -> int:
            return _positive_int(name, int(detection.get(yaml_key, fallback)))

        def enabled(name: str, source_name: str, fallback: bool) -> bool:
            raw = getenv(name)
            if raw is not None:
                return raw.strip().lower() in {"1", "true", "yes", "on"}
            source = sources.get(source_name, {})
            return bool(source.get("enabled", fallback)) if isinstance(source, dict) else fallback

        capture_source = sources.get("packet_capture", {}) if isinstance(sources, dict) else {}
        return cls(
            port_scan_port_threshold=number("PORT_SCAN_PORT_THRESHOLD", "port_scan_port_threshold", 50),
            port_scan_time_window_seconds=number("PORT_SCAN_TIME_WINDOW", "port_scan_time_window_seconds", 10),
            syn_rate_threshold=number("SYN_RATE_THRESHOLD", "syn_rate_threshold", 100),
            syn_time_window_seconds=number("SYN_TIME_WINDOW", "syn_time_window_seconds", 1),
            traffic_rate_threshold=number("TRAFFIC_RATE_THRESHOLD", "traffic_rate_threshold", 1_000),
            traffic_rate_window_seconds=number("TRAFFIC_RATE_WINDOW", "traffic_rate_window_seconds", 1),
            icmp_sweep_destination_threshold=number("ICMP_SWEEP_DESTINATION_THRESHOLD", "icmp_sweep_destination_threshold", 20),
            icmp_sweep_time_window_seconds=number("ICMP_SWEEP_TIME_WINDOW", "icmp_sweep_time_window_seconds", 10),
            dns_query_rate_threshold=number("DNS_QUERY_RATE_THRESHOLD", "dns_query_rate_threshold", 100),
            dns_query_time_window_seconds=number("DNS_QUERY_TIME_WINDOW", "dns_query_time_window_seconds", 10),
            arp_conflict_time_window_seconds=number("ARP_CONFLICT_TIME_WINDOW", "arp_conflict_time_window_seconds", 120),
            arp_conflict_mac_threshold=number("ARP_CONFLICT_MAC_THRESHOLD", "arp_conflict_mac_threshold", 2),
            alert_cooldown_seconds=_positive_int("ALERT_COOLDOWN", int(detection.get("alert_cooldown_seconds", 60))),
            rate_window_seconds=_positive_int("RATE_WINDOW_SECONDS", 1),
            history_window_seconds=_positive_int("HISTORY_WINDOW_SECONDS", 60),
            max_tracked_endpoints=_positive_int("MAX_TRACKED_ENDPOINTS", 500),
            max_tracked_ports=_positive_int("MAX_TRACKED_PORTS", 500),
            max_connections=_positive_int("MAX_CONNECTIONS", 10_000),
            connection_ttl_seconds=_positive_int("CONNECTION_TTL_SECONDS", 300),
            max_detector_events_per_key=_positive_int("MAX_DETECTOR_EVENTS_PER_KEY", 10_000),
            database_path=getenv("DATABASE_PATH", str(storage.get("database_path", "network_sentinel.db"))),
            max_tracked_devices=_positive_int("MAX_TRACKED_DEVICES", 500),
            device_ttl_seconds=_positive_int("DEVICE_TTL_SECONDS", 3_600),
            capture_interface=(
                None
                if (configured_interface := getenv("CAPTURE_INTERFACE") or (capture_source.get("interface") if isinstance(capture_source, dict) else None)) in {None, "", "auto"}
                else str(configured_interface)
            ),
            wifi_status_refresh_seconds=_positive_int("WIFI_STATUS_REFRESH_SECONDS", 30),
            auth_failure_threshold=number("AUTH_FAILURE_THRESHOLD", "auth_failure_threshold", 5),
            auth_failure_time_window_seconds=number("AUTH_FAILURE_WINDOW", "auth_failure_time_window_seconds", 300),
            suspicious_auth_sequence_window_seconds=number("AUTH_SEQUENCE_WINDOW", "suspicious_auth_sequence_window_seconds", 600),
            packet_capture_enabled=enabled("PACKET_CAPTURE_ENABLED", "packet_capture", True),
            zeek_enabled=enabled("ZEEK_ENABLED", "zeek", False),
            suricata_enabled=enabled("SURICATA_ENABLED", "suricata", False),
            windows_events_enabled=enabled("WINDOWS_EVENTS_ENABLED", "windows_events", False),
            synthetic_enabled=enabled("SYNTHETIC_ENABLED", "synthetic", True),
            storage_backend=getenv("STORAGE_BACKEND", str(storage.get("backend", "sqlite"))),
            node_red_webhook_url=getenv("NODE_RED_WEBHOOK_URL") or _nested(document, "orchestration", "node_red_webhook_url", default=None),
        )
