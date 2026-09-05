"""Pydantic response models for the public REST API."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class MonitoringStatusResponse(BaseModel):
    active: bool
    started_at: datetime | None
    capture_ready: bool


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
    detection_type: Literal["PORT_SCAN", "SYN_FLOOD", "TRAFFIC_RATE_ANOMALY", "ICMP_SWEEP", "DNS_QUERY_ANOMALY"]
    severity: Literal["LOW", "MEDIUM", "HIGH"]
    source_ip: str | None
    destination_ip: str | None
    observed_value: float
    threshold: float
    evidence: str


class AlertHistoryResponse(BaseModel):
    alerts: list[AlertResponse]
    limit: int = Field(ge=1, le=500)
    offset: int = Field(ge=0)
