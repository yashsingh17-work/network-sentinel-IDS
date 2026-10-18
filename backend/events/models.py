"""A stable event envelope shared by network, IDS, host, and test sources."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping
from uuid import uuid4

from backend.models import NormalizedPacket


@dataclass(frozen=True, slots=True)
class SecurityEvent:
    """Common fields remain searchable; source details stay in ``metadata``."""

    timestamp: datetime
    source: str
    event_type: str
    source_ip: str | None = None
    destination_ip: str | None = None
    source_port: int | None = None
    destination_port: int | None = None
    protocol: str | None = None
    bytes_count: int | None = None
    packets_count: int | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)
    event_id: str = field(default_factory=lambda: str(uuid4()))

    @classmethod
    def now(cls, *, source: str, event_type: str, **kwargs: Any) -> "SecurityEvent":
        return cls(timestamp=datetime.now(timezone.utc), source=source, event_type=event_type, **kwargs)

    @classmethod
    def from_packet(cls, packet: NormalizedPacket, source: str = "packet_capture") -> "SecurityEvent":
        return cls(
            timestamp=packet.timestamp,
            source=source,
            event_type="network_packet",
            source_ip=packet.source_ip,
            destination_ip=packet.destination_ip,
            source_port=packet.source_port,
            destination_port=packet.destination_port,
            protocol=packet.protocol,
            bytes_count=packet.size_bytes,
            packets_count=1,
            metadata={
                "tcp_flags": packet.tcp_flags,
                "icmp_type": packet.icmp_type,
                "icmp_code": packet.icmp_code,
                "dns_query_name": packet.dns_query_name,
                "dhcp_message_type": packet.dhcp_message_type,
                "dhcp_server_id": packet.dhcp_server_id,
                "source_mac": packet.source_mac,
                "destination_mac": packet.destination_mac,
                "arp_operation": packet.arp_operation,
                "arp_source_ip": packet.arp_source_ip,
                "arp_source_mac": packet.arp_source_mac,
                "arp_target_ip": packet.arp_target_ip,
                "arp_target_mac": packet.arp_target_mac,
            },
        )

    def to_packet(self) -> NormalizedPacket | None:
        """Adapt network metadata to the existing packet-analysis rules when safe."""
        protocol = (self.protocol or "").upper()
        # Authentication events with a complete transport tuple are still
        # network telemetry. Keeping them visible lets an FTP/SSH failure show
        # up in the live protocol, service-port, and packet-investigation
        # views as well as in the authentication alert feed.
        if self.event_type not in {"network_packet", "network_connection", "authentication_failure", "authentication_success"} or protocol not in {"TCP", "UDP", "ICMP", "ICMPV6", "ARP"}:
            return None
        if not self.source_ip or not self.destination_ip:
            return None
        metadata = self.metadata
        return NormalizedPacket(
            timestamp=self.timestamp,
            source_ip=self.source_ip,
            destination_ip=self.destination_ip,
            protocol=protocol,  # type: ignore[arg-type]
            source_port=self.source_port,
            destination_port=self.destination_port,
            tcp_flags=_string_or_none(metadata.get("tcp_flags")),
            size_bytes=max(0, self.bytes_count or 0),
            icmp_type=_int_or_none(metadata.get("icmp_type")),
            icmp_code=_int_or_none(metadata.get("icmp_code")),
            dns_query_name=_string_or_none(metadata.get("dns_query_name")),
            dhcp_message_type=_string_or_none(metadata.get("dhcp_message_type")),
            dhcp_server_id=_string_or_none(metadata.get("dhcp_server_id")),
            source_mac=_string_or_none(metadata.get("source_mac")),
            destination_mac=_string_or_none(metadata.get("destination_mac")),
            arp_operation=_int_or_none(metadata.get("arp_operation")),
            arp_source_ip=_string_or_none(metadata.get("arp_source_ip")),
            arp_source_mac=_string_or_none(metadata.get("arp_source_mac")),
            arp_target_ip=_string_or_none(metadata.get("arp_target_ip")),
            arp_target_mac=_string_or_none(metadata.get("arp_target_mac")),
        )


def _string_or_none(value: Any) -> str | None:
    return str(value) if value is not None else None


def _int_or_none(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None
