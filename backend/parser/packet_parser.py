"""Conversion from Scapy packets to Network Sentinel's internal model."""

from __future__ import annotations

from datetime import datetime, timezone

from typing import Any

from backend.models import NormalizedPacket


class PacketParser:
    """Parse only IPv4 packets; unsupported or malformed input is ignored safely."""

    def parse(self, packet: Any) -> NormalizedPacket | None:
        try:
            if not packet.haslayer("IP") and not packet.haslayer("ARP"):
                return None

            ip = packet["IP"] if packet.haslayer("IP") else None
            protocol = "OTHER"
            source_port: int | None = None
            destination_port: int | None = None
            tcp_flags: str | None = None
            icmp_type: int | None = None
            icmp_code: int | None = None
            dns_query_name: str | None = None
            source_mac: str | None = None
            destination_mac: str | None = None
            arp_operation: int | None = None
            arp_source_ip: str | None = None
            arp_source_mac: str | None = None
            arp_target_ip: str | None = None
            arp_target_mac: str | None = None

            if packet.haslayer("Ether"):
                ether = packet["Ether"]
                source_mac = str(ether.src).lower()
                destination_mac = str(ether.dst).lower()

            if packet.haslayer("ARP"):
                arp = packet["ARP"]
                protocol = "ARP"
                arp_operation = int(arp.op)
                arp_source_ip = str(arp.psrc)
                arp_source_mac = str(arp.hwsrc).lower()
                arp_target_ip = str(arp.pdst)
                arp_target_mac = str(arp.hwdst).lower()
            elif packet.haslayer("TCP"):
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
                icmp = packet["ICMP"]
                protocol = "ICMP"
                icmp_type = int(icmp.type)
                icmp_code = int(icmp.code)

            if packet.haslayer("DNSQR"):
                dns_query_name = self._decode_dns_query(packet["DNSQR"].qname)

            raw_timestamp = getattr(packet, "time", None)
            timestamp = datetime.fromtimestamp(float(raw_timestamp), tz=timezone.utc) if raw_timestamp else datetime.now(timezone.utc)
            return NormalizedPacket(
                timestamp=timestamp,
                source_ip=arp_source_ip or str(ip.src),
                destination_ip=arp_target_ip or str(ip.dst),
                protocol=protocol,
                source_port=source_port,
                destination_port=destination_port,
                tcp_flags=tcp_flags,
                size_bytes=len(packet),
                icmp_type=icmp_type,
                icmp_code=icmp_code,
                dns_query_name=dns_query_name,
                source_mac=source_mac,
                destination_mac=destination_mac,
                arp_operation=arp_operation,
                arp_source_ip=arp_source_ip,
                arp_source_mac=arp_source_mac,
                arp_target_ip=arp_target_ip,
                arp_target_mac=arp_target_mac,
            )
        except (AttributeError, TypeError, ValueError, IndexError):
            return None

    @staticmethod
    def _decode_dns_query(value: object) -> str | None:
        if isinstance(value, bytes):
            return value.decode("idna").rstrip(".")
        if isinstance(value, str):
            return value.rstrip(".")
        return None
