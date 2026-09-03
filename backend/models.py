"""Internal, framework-independent data models."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Literal

Protocol = Literal["TCP", "UDP", "ICMP", "OTHER"]


@dataclass(frozen=True, slots=True)
class NormalizedPacket:
    """The small, stable representation consumed by analysis and detection."""

    timestamp: datetime
    source_ip: str
    destination_ip: str
    protocol: Protocol
    source_port: int | None
    destination_port: int | None
    tcp_flags: str | None
    size_bytes: int

    @classmethod
    def now(
        cls,
        *,
        source_ip: str,
        destination_ip: str,
        protocol: Protocol,
        source_port: int | None = None,
        destination_port: int | None = None,
        tcp_flags: str | None = None,
        size_bytes: int = 0,
    ) -> "NormalizedPacket":
        return cls(
            timestamp=datetime.now(timezone.utc),
            source_ip=source_ip,
            destination_ip=destination_ip,
            protocol=protocol,
            source_port=source_port,
            destination_port=destination_port,
            tcp_flags=tcp_flags,
            size_bytes=size_bytes,
        )
