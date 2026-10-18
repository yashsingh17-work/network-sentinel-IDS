"""Pydantic response models for the public REST API."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator


class MonitoringStatusResponse(BaseModel):
    active: bool
    started_at: datetime | None
    capture_ready: bool
    interface: str | None
    last_error: str | None
    packets_captured: int


class OverallTrafficResponse(BaseModel):
    total_packets: int
    total_bytes: int
    packets_per_second: float
    bytes_per_second: float


class ProtocolStatisticsResponse(BaseModel):
    protocols: dict[str, int]


class RankedValueResponse(BaseModel):
    value: str | int
    count: int
    label: str | None = None
    description: str | None = None


class TopIpsResponse(BaseModel):
    sources: list[RankedValueResponse]
    destinations: list[RankedValueResponse]


class TopPortsResponse(BaseModel):
    destinations: list[RankedValueResponse]


class ConnectionStatisticsResponse(BaseModel):
    active_connections: int
    total_connections_seen: int


class PacketObservationResponse(BaseModel):
    timestamp: datetime
    source_ip: str
    destination_ip: str
    protocol: str
    source_port: int | None
    destination_port: int | None
    source_port_label: str | None = None
    destination_port_label: str | None = None
    likely_application_protocol: str | None = None
    tcp_flags: str | None
    size_bytes: int
    dns_query_name: str | None
    icmp_type: int | None
    dhcp_message_type: str | None = None
    dhcp_server_id: str | None = None
    triggered_alert_types: list[str] = Field(default_factory=list)
    alert_evidence: list[str] = Field(default_factory=list)


class DeviceActivityResponse(BaseModel):
    device: ObservedDeviceResponse
    recent_packets: list[PacketObservationResponse]
    history_note: str


class AlertResponse(BaseModel):
    id: str
    timestamp: datetime
    detection_type: Literal[
        "PORT_SCAN", "SYN_FLOOD", "TRAFFIC_RATE_ANOMALY", "ICMP_SWEEP", "DNS_QUERY_ANOMALY",
        "ARP_SPOOFING_SUSPECTED", "AUTH_FAILURE_BURST", "SUSPICIOUS_AUTH_SEQUENCE",
        "SURICATA_SIGNATURE", "ZEEK_NETWORK_ANOMALY", "DOWNLOAD_OBSERVED", "UNVERIFIED_RISKY_DOWNLOAD", "UNSAFE_WIFI_POSTURE", "SUSPICIOUS_DOMAIN",
        "INSECURE_SERVICE_OBSERVED", "MULTIPLE_DHCP_SERVERS_OBSERVED",
    ]
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    source_ip: str | None
    destination_ip: str | None
    observed_value: float
    threshold: float
    evidence: str
    confidence: float
    recommended_investigation: str
    source: str
    context: dict[str, Any]


class AlertHistoryResponse(BaseModel):
    alerts: list[AlertResponse]
    limit: int = Field(ge=1, le=500)
    offset: int = Field(ge=0)


class ObservedDeviceResponse(BaseModel):
    mac_address: str
    ip_addresses: list[str]
    first_seen: datetime
    last_seen: datetime
    packets_seen: int
    protocols: dict[str, int]
    vendor: str | None = None
    likely_role: str
    observed_services: list[str]
    display_name: str | None = None
    physical_location: str | None = None


class DeviceProfileRequest(BaseModel):
    display_name: str | None = Field(default=None, max_length=100)
    physical_location: str | None = Field(default=None, max_length=160)


class WifiSecurityResponse(BaseModel):
    available: bool
    connected: bool
    ssid: str | None
    authentication: str | None
    cipher: str | None
    secure: bool | None
    summary: str


class CaptureInterfaceResponse(BaseModel):
    name: str
    network_name: str
    description: str | None
    index: int | None
    ips: list[str]


class SecurityEventRequest(BaseModel):
    timestamp: datetime
    source: str = Field(min_length=1, max_length=80)
    event_type: str = Field(min_length=1, max_length=120)
    source_ip: str | None = None
    destination_ip: str | None = None
    source_port: int | None = Field(default=None, ge=0, le=65535)
    destination_port: int | None = Field(default=None, ge=0, le=65535)
    protocol: str | None = Field(default=None, max_length=20)
    bytes_count: int | None = Field(default=None, ge=0)
    packets_count: int | None = Field(default=None, ge=0)
    metadata: dict[str, Any] = Field(default_factory=dict)


class SecurityEventResponse(SecurityEventRequest):
    event_id: str


class EventIngestionResponse(BaseModel):
    event: SecurityEventResponse
    alerts: list[AlertResponse]


class EventBatchResponse(BaseModel):
    events_created: int
    alerts: list[AlertResponse]


class PacketTracerEventRequest(BaseModel):
    """The portable Packet Tracer collector envelope.

    Packet Tracer does not expose a native Python packet stream.  The collector
    therefore normalizes syslog records, exports, and replay records into this
    deliberately small schema before they enter the regular IDS pipeline.
    """

    timestamp: datetime
    source_ip: str
    source_port: int | None = Field(default=None, ge=0, le=65535)
    dest_ip: str
    dest_port: int | None = Field(default=None, ge=0, le=65535)
    protocol: Literal["TCP", "UDP", "ICMP", "ICMPV6", "ARP"]
    flags: list[str] = Field(default_factory=list, max_length=8)
    payload_size: int = Field(default=0, ge=0)
    raw_data: str = Field(default="", max_length=4096)
    metadata: dict[str, Any] = Field(default_factory=dict)


class PacketTracerIngestRequest(BaseModel):
    """Accept either one normalized event or ``{\"events\": [...]}``."""

    events: list[PacketTracerEventRequest] = Field(min_length=1, max_length=500)

    @model_validator(mode="before")
    @classmethod
    def accept_single_event(cls, value: Any) -> Any:
        if isinstance(value, dict) and "events" not in value:
            return {"events": [value]}
        return value


class PacketTracerScenarioResponse(BaseModel):
    scenario_id: str
    title: str
    description: str
    packet_tracer_action: str


class PacketTracerScenarioRunResponse(EventBatchResponse):
    scenario: PacketTracerScenarioResponse


class DownloadMonitorStatusResponse(BaseModel):
    enabled: bool
    initialized: bool
    directories: list[str]
    tracked_files: int
    last_scan_at: str | None


class DownloadAuditResponse(EventBatchResponse):
    files_inspected: int
