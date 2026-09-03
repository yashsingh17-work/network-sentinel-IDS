"""Central, environment-configurable application settings."""

from __future__ import annotations

from dataclasses import dataclass
from os import getenv


def _positive_int(name: str, default: int) -> int:
    value = int(getenv(name, str(default)))
    if value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


@dataclass(frozen=True, slots=True)
class Settings:
    """All V1 limits and detection values live here, never inside business logic."""

    port_scan_port_threshold: int = 50
    port_scan_time_window_seconds: int = 10
    syn_rate_threshold: int = 100
    traffic_rate_threshold: int = 1_000
    alert_cooldown_seconds: int = 60
    rate_window_seconds: int = 1
    history_window_seconds: int = 60
    max_tracked_endpoints: int = 500
    max_tracked_ports: int = 500
    max_connections: int = 10_000
    connection_ttl_seconds: int = 300

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            port_scan_port_threshold=_positive_int("PORT_SCAN_PORT_THRESHOLD", 50),
            port_scan_time_window_seconds=_positive_int("PORT_SCAN_TIME_WINDOW", 10),
            syn_rate_threshold=_positive_int("SYN_RATE_THRESHOLD", 100),
            traffic_rate_threshold=_positive_int("TRAFFIC_RATE_THRESHOLD", 1_000),
            alert_cooldown_seconds=_positive_int("ALERT_COOLDOWN", 60),
            rate_window_seconds=_positive_int("RATE_WINDOW_SECONDS", 1),
            history_window_seconds=_positive_int("HISTORY_WINDOW_SECONDS", 60),
            max_tracked_endpoints=_positive_int("MAX_TRACKED_ENDPOINTS", 500),
            max_tracked_ports=_positive_int("MAX_TRACKED_PORTS", 500),
            max_connections=_positive_int("MAX_CONNECTIONS", 10_000),
            connection_ttl_seconds=_positive_int("CONNECTION_TTL_SECONDS", 300),
        )
