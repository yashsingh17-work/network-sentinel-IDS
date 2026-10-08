"""Small local port-service catalogue for understandable dashboard labels."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class PortInfo:
    number: int
    service: str
    description: str

    @property
    def label(self) -> str:
        return f"{self.number} ({self.service})"


_PORTS: dict[int, tuple[str, str]] = {
    20: ("FTP data", "File Transfer Protocol data channel"),
    21: ("FTP", "File Transfer Protocol control channel"),
    22: ("SSH", "Secure Shell remote administration"),
    23: ("Telnet", "Unencrypted remote terminal service"),
    25: ("SMTP", "Email sending service"),
    53: ("DNS", "Domain-name lookup service"),
    67: ("DHCP server", "Automatic network-address assignment server"),
    68: ("DHCP client", "Automatic network-address assignment client"),
    80: ("HTTP", "Unencrypted web traffic"),
    110: ("POP3", "Email retrieval service"),
    123: ("NTP", "Network time synchronization"),
    135: ("MS RPC", "Microsoft Remote Procedure Call endpoint mapper"),
    137: ("NetBIOS name", "Legacy Windows name service"),
    138: ("NetBIOS datagram", "Legacy Windows datagram service"),
    139: ("NetBIOS session", "Legacy Windows file/printer sharing"),
    143: ("IMAP", "Email retrieval service"),
    161: ("SNMP", "Network-device monitoring and management"),
    389: ("LDAP", "Directory-service queries"),
    443: ("HTTPS", "Encrypted web traffic"),
    445: ("SMB", "Windows file and printer sharing"),
    3389: ("RDP", "Windows Remote Desktop"),
    3306: ("MySQL", "MySQL database service"),
    5432: ("PostgreSQL", "PostgreSQL database service"),
    6379: ("Redis", "Redis data-store service"),
    8080: ("HTTP alternate", "Common alternate web or proxy port"),
    8443: ("HTTPS alternate", "Common alternate encrypted web port"),
}


def describe_port(number: int) -> PortInfo:
    service, description = _PORTS.get(number, ("Unregistered/ephemeral", "No common well-known service is assigned to this port."))
    return PortInfo(number=number, service=service, description=description)
