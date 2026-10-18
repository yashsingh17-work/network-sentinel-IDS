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
    dhcp_server_conflict_time_window_seconds: int = 120
    dhcp_server_conflict_threshold: int = 2
    insecure_service_ports: tuple[int, ...] = (21, 23)
    alert_cooldown_seconds: int = 60
    rate_window_seconds: int = 5
    history_window_seconds: int = 60
    max_tracked_endpoints: int = 500
    max_tracked_ports: int = 500
    max_connections: int = 10_000
    connection_ttl_seconds: int = 300
    max_detector_events_per_key: int = 10_000
    max_packet_history: int = 1_000
    database_path: str = "network_sentinel.db"
    max_tracked_devices: int = 500
    device_ttl_seconds: int = 3_600
    capture_interface: str | None = None
    wifi_status_refresh_seconds: int = 30
    auth_failure_threshold: int = 5
    auth_failure_time_window_seconds: int = 300
    suspicious_auth_sequence_window_seconds: int = 600
    packet_capture_enabled: bool = True
    auto_start_monitoring: bool = True
    zeek_enabled: bool = False
    suricata_enabled: bool = False
    windows_events_enabled: bool = False
    synthetic_enabled: bool = True
    storage_backend: str = "sqlite"
    node_red_webhook_url: str | None = None
    reverse_dns_enabled: bool = True
    country_lookup_enabled: bool = False
    country_lookup_url: str = "https://ipwho.is/{ip}"
    ip_enrichment_cache_seconds: int = 86_400
    download_monitor_enabled: bool = True
    download_directories: tuple[str, ...] = ()
    download_monitor_interval_seconds: int = 15
    download_max_files: int = 1_000
    download_hash_max_bytes: int = 134_217_728
    unsafe_domains: tuple[str, ...] = ()
    packet_tracer_dns_server: str | None = None
    packet_tracer_lab_mode: bool = False
    packet_tracer_attacker_ip: str = "192.168.10.10"
    packet_tracer_windows_target_ip: str = "192.168.20.10"
    packet_tracer_linux_target_ip: str = "192.168.20.20"
    packet_tracer_dmz_web_server_ip: str = "192.168.30.10"
    packet_tracer_gateway_ip: str = "192.168.20.1"
    packet_tracer_network_zone: str = "192.168.10.0/24"
    packet_tracer_authentication_targets: tuple[str, ...] = ("192.168.20.20",)

    @classmethod
    def from_env(cls, config_path: str | None = None) -> "Settings":
        """Load environment-selected settings, optionally from an explicit profile path."""
        document = _load_config(config_path or getenv("CONFIG_PATH", "config.yaml"))
        detection = _nested(document, "detection", default={})
        sources = _nested(document, "sources", default={})
        storage = _nested(document, "storage", default={})
        enrichment = _nested(document, "enrichment", default={})
        download_monitor = sources.get("download_monitor", {}) if isinstance(sources, dict) else {}
        threat_intelligence = _nested(document, "threat_intelligence", default={})
        packet_tracer = _nested(document, "packet_tracer", default={})
        packet_tracer_targets = packet_tracer.get("targets", {}) if isinstance(packet_tracer, dict) else {}

        def number(name: str, yaml_key: str, fallback: int) -> int:
            return _positive_int(name, int(detection.get(yaml_key, fallback)))

        def enabled(name: str, source_name: str, fallback: bool) -> bool:
            raw = getenv(name)
            if raw is not None:
                return raw.strip().lower() in {"1", "true", "yes", "on"}
            source = sources.get(source_name, {})
            return bool(source.get("enabled", fallback)) if isinstance(source, dict) else fallback

        def boolean(name: str, value: Any) -> bool:
            raw = getenv(name)
            if raw is not None:
                return raw.strip().lower() in {"1", "true", "yes", "on"}
            return bool(value)

        capture_source = sources.get("packet_capture", {}) if isinstance(sources, dict) else {}
        configured_downloads = download_monitor.get("directories", [str(Path.home() / "Downloads")]) if isinstance(download_monitor, dict) else [str(Path.home() / "Downloads")]
        if not isinstance(configured_downloads, list):
            configured_downloads = [str(Path.home() / "Downloads")]
        if not configured_downloads:
            configured_downloads = [str(Path.home() / "Downloads")]
        configured_domains = threat_intelligence.get("unsafe_domains", []) if isinstance(threat_intelligence, dict) else []
        if not isinstance(configured_domains, list):
            configured_domains = []
        configured_insecure_ports = detection.get("insecure_service_ports", [21, 23]) if isinstance(detection, dict) else [21, 23]
        if not isinstance(configured_insecure_ports, list):
            configured_insecure_ports = [21, 23]
        insecure_service_ports: list[int] = []
        for item in configured_insecure_ports:
            try:
                port = int(item)
            except (TypeError, ValueError):
                continue
            if 0 <= port <= 65535:
                insecure_service_ports.append(port)
        if not isinstance(packet_tracer_targets, dict):
            packet_tracer_targets = {}
        configured_auth_targets = packet_tracer.get("authentication_targets", []) if isinstance(packet_tracer, dict) else []
        if not isinstance(configured_auth_targets, list):
            configured_auth_targets = []

        def topology_value(name: str, fallback: str) -> str:
            value = packet_tracer_targets.get(name, fallback)
            return str(value).strip() or fallback
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
            dhcp_server_conflict_time_window_seconds=number("DHCP_SERVER_CONFLICT_TIME_WINDOW", "dhcp_server_conflict_time_window_seconds", 120),
            dhcp_server_conflict_threshold=number("DHCP_SERVER_CONFLICT_THRESHOLD", "dhcp_server_conflict_threshold", 2),
            insecure_service_ports=tuple(insecure_service_ports) or (21, 23),
            alert_cooldown_seconds=_positive_int("ALERT_COOLDOWN", int(detection.get("alert_cooldown_seconds", 60))),
            rate_window_seconds=_positive_int("RATE_WINDOW_SECONDS", int(_nested(document, "dashboard", "rate_window_seconds", default=5))),
            history_window_seconds=_positive_int("HISTORY_WINDOW_SECONDS", 60),
            max_tracked_endpoints=_positive_int("MAX_TRACKED_ENDPOINTS", 500),
            max_tracked_ports=_positive_int("MAX_TRACKED_PORTS", 500),
            max_connections=_positive_int("MAX_CONNECTIONS", 10_000),
            connection_ttl_seconds=_positive_int("CONNECTION_TTL_SECONDS", 300),
            max_detector_events_per_key=_positive_int("MAX_DETECTOR_EVENTS_PER_KEY", 10_000),
            max_packet_history=_positive_int("MAX_PACKET_HISTORY", 1_000),
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
            auto_start_monitoring=boolean("AUTO_START_MONITORING", capture_source.get("auto_start", True) if isinstance(capture_source, dict) else True),
            zeek_enabled=enabled("ZEEK_ENABLED", "zeek", False),
            suricata_enabled=enabled("SURICATA_ENABLED", "suricata", False),
            windows_events_enabled=enabled("WINDOWS_EVENTS_ENABLED", "windows_events", False),
            synthetic_enabled=enabled("SYNTHETIC_ENABLED", "synthetic", True),
            storage_backend=getenv("STORAGE_BACKEND", str(storage.get("backend", "sqlite"))),
            node_red_webhook_url=getenv("NODE_RED_WEBHOOK_URL") or _nested(document, "orchestration", "node_red_webhook_url", default=None),
            reverse_dns_enabled=boolean("REVERSE_DNS_ENABLED", enrichment.get("reverse_dns_enabled", True)),
            country_lookup_enabled=boolean("COUNTRY_LOOKUP_ENABLED", enrichment.get("country_lookup_enabled", False)),
            country_lookup_url=getenv("COUNTRY_LOOKUP_URL", str(enrichment.get("country_lookup_url", "https://ipwho.is/{ip}"))),
            ip_enrichment_cache_seconds=_positive_int("IP_ENRICHMENT_CACHE_SECONDS", int(enrichment.get("cache_seconds", 86_400))),
            download_monitor_enabled=enabled("DOWNLOAD_MONITOR_ENABLED", "download_monitor", True),
            download_directories=tuple(str(Path(item).expanduser()) for item in configured_downloads if str(item).strip()),
            download_monitor_interval_seconds=_positive_int("DOWNLOAD_MONITOR_INTERVAL_SECONDS", int(download_monitor.get("interval_seconds", 15)) if isinstance(download_monitor, dict) else 15),
            download_max_files=_positive_int("DOWNLOAD_MAX_FILES", int(download_monitor.get("max_files", 1_000)) if isinstance(download_monitor, dict) else 1_000),
            download_hash_max_bytes=_positive_int("DOWNLOAD_HASH_MAX_BYTES", int(download_monitor.get("hash_max_bytes", 134_217_728)) if isinstance(download_monitor, dict) else 134_217_728),
            unsafe_domains=tuple(str(domain).strip().rstrip(".").lower() for domain in configured_domains if str(domain).strip()),
            packet_tracer_dns_server=(
                str(packet_tracer.get("dns_server") or packet_tracer_targets.get("dns_server")).strip()
                if isinstance(packet_tracer, dict) and (packet_tracer.get("dns_server") or packet_tracer_targets.get("dns_server"))
                else None
            ),
            packet_tracer_lab_mode=boolean(
                "PACKET_TRACER_LAB_MODE",
                packet_tracer.get("enabled", False) if isinstance(packet_tracer, dict) else False,
            ),
            packet_tracer_attacker_ip=topology_value("attacker", "192.168.10.10"),
            packet_tracer_windows_target_ip=topology_value("windows_target", "192.168.20.10"),
            packet_tracer_linux_target_ip=topology_value("linux_target", "192.168.20.20"),
            packet_tracer_dmz_web_server_ip=topology_value("dmz_web_server", "192.168.30.10"),
            packet_tracer_gateway_ip=topology_value("gateway", "192.168.20.1"),
            packet_tracer_network_zone=(
                str(packet_tracer.get("attacker_network", "192.168.10.0/24")).strip()
                if isinstance(packet_tracer, dict) else "192.168.10.0/24"
            ),
            packet_tracer_authentication_targets=tuple(
                str(item).strip() for item in configured_auth_targets if str(item).strip()
            ) or (topology_value("linux_target", "192.168.20.20"),),
        )
