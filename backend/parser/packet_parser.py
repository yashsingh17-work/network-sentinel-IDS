"""Conversion from Scapy packets to Network Sentinel's internal model."""

from __future__ import annotations

from datetime import datetime, timezone

from typing import Any

from backend.models import NormalizedPacket


class PacketParser:
    """Normalize safe network headers from IPv4, IPv6, ARP, DNS, and DHCP traffic."""

    def parse(self, packet: Any) -> NormalizedPacket | None:
        try:
            if not packet.haslayer("IP") and not packet.haslayer("IPv6") and not packet.haslayer("ARP"):
                return None

            ip = packet["IP"] if packet.haslayer("IP") else (packet["IPv6"] if packet.haslayer("IPv6") else None)
            protocol = "OTHER"
            source_port: int | None = None
            destination_port: int | None = None
            tcp_flags: str | None = None
            icmp_type: int | None = None
            icmp_code: int | None = None
            dns_query_name: str | None = None
            dhcp_message_type: str | None = None
            dhcp_server_id: str | None = None
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
            elif packet.haslayer("ICMPv6EchoRequest"):
                protocol = "ICMPV6"
                icmp_type = 128
                icmp_code = 0
            elif packet.haslayer("ICMPv6EchoReply"):
                protocol = "ICMPV6"
                icmp_type = 129
                icmp_code = 0
            elif packet.haslayer("ICMPv6ND_RA"):
                protocol = "ICMPV6"
                icmp_type = 134
                icmp_code = 0

            if packet.haslayer("DNSQR"):
                dns_query_name = self._decode_dns_query(packet["DNSQR"].qname)
            if packet.haslayer("DHCP"):
                dhcp_message_type, dhcp_server_id = self._dhcp_details(packet["DHCP"])

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
                dhcp_message_type=dhcp_message_type,
                dhcp_server_id=dhcp_server_id,
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

    @staticmethod
    def _dhcp_details(dhcp: object) -> tuple[str | None, str | None]:
        """Extract DHCP option metadata without retaining its payload."""
        options = getattr(dhcp, "options", ())
        if not isinstance(options, (list, tuple)):
            return None, None
        values = {item[0]: item[1] for item in options if isinstance(item, tuple) and len(item) >= 2}
        message = values.get("message-type")
        if isinstance(message, bytes):
            message = message.decode("ascii", errors="ignore")
        names = {1: "discover", 2: "offer", 3: "request", 5: "ack", 6: "nak", 7: "release", 8: "inform"}
        try:
            message_name = names.get(int(message), str(message).lower()) if message is not None else None
        except (TypeError, ValueError):
            message_name = str(message).lower() if message is not None else None
        server_id = values.get("server_id")
        return message_name, str(server_id) if server_id is not None else None
