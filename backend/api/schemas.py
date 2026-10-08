"""Pydantic response models for the public REST API."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


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


class TopIpsResponse(BaseModel):
    sources: list[RankedValueResponse]
    destinations: list[RankedValueResponse]


class TopPortsResponse(BaseModel):
    destinations: list[RankedValueResponse]


class ConnectionStatisticsResponse(BaseModel):
    active_connections: int
    total_connections_seen: int


class AlertResponse(BaseModel):
    id: str
    timestamp: datetime
    detection_type: Literal[
        "PORT_SCAN", "SYN_FLOOD", "TRAFFIC_RATE_ANOMALY", "ICMP_SWEEP", "DNS_QUERY_ANOMALY",
        "ARP_SPOOFING_SUSPECTED", "AUTH_FAILURE_BURST", "SUSPICIOUS_AUTH_SEQUENCE",
        "SURICATA_SIGNATURE", "ZEEK_NETWORK_ANOMALY",
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
