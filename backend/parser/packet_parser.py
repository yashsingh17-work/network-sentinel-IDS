"""Conversion from Scapy packets to Network Sentinel's internal model."""

from __future__ import annotations

from datetime import datetime, timezone

from typing import Any

from backend.models import NormalizedPacket


class PacketParser:
    """Parse only IPv4 packets; unsupported or malformed input is ignored safely."""

    def parse(self, packet: Any) -> NormalizedPacket | None:
        try:
            if not packet.haslayer("IP"):
                return None

            ip = packet["IP"]
            protocol = "OTHER"
            source_port: int | None = None
            destination_port: int | None = None
            tcp_flags: str | None = None

            if packet.haslayer("TCP"):
                tcp = packet["TCP"]
                protocol = "TCP"
                source_port = int(tcp.sport)
                destination_port = int(tcp.dport)
                tcp_flags = str(tcp.flags)
            elif packet.haslayer("UDP"):
                udp = packet["UDP"]
                protocol = "UDP"
                source_port = int(udp.sport)
                destination_port = int(udp.dport)
            elif packet.haslayer("ICMP"):
                protocol = "ICMP"

            raw_timestamp = getattr(packet, "time", None)
            timestamp = datetime.fromtimestamp(float(raw_timestamp), tz=timezone.utc) if raw_timestamp else datetime.now(timezone.utc)
            return NormalizedPacket(
                timestamp=timestamp,
                source_ip=str(ip.src),
                destination_ip=str(ip.dst),
                protocol=protocol,
                source_port=source_port,
                destination_port=destination_port,
                tcp_flags=tcp_flags,
                size_bytes=len(packet),
            )
        except (AttributeError, TypeError, ValueError, IndexError):
            return None
