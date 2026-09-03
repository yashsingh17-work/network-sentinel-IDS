from datetime import timezone
from types import SimpleNamespace

from backend.parser import PacketParser


class SyntheticPacket:
    """Small Scapy-compatible test double; no network stack is involved."""

    def __init__(self, layers: dict[str, object], *, size: int = 60, timestamp: float = 1_700_000_000) -> None:
        self.layers = layers
        self.size = size
        self.time = timestamp

    def haslayer(self, name: str) -> bool:
        return name in self.layers

    def __getitem__(self, name: str) -> object:
        return self.layers[name]

    def __len__(self) -> int:
        return self.size


def ip_packet(*layers: tuple[str, object]) -> SyntheticPacket:
    return SyntheticPacket({"IP": SimpleNamespace(src="10.0.0.10", dst="10.0.0.20"), **dict(layers)})


def test_parses_tcp_packet() -> None:
    parsed = PacketParser().parse(ip_packet(("TCP", SimpleNamespace(sport=54321, dport=443, flags="S"))))

    assert parsed is not None
    assert (parsed.protocol, parsed.source_port, parsed.destination_port, parsed.tcp_flags) == ("TCP", 54321, 443, "S")
    assert parsed.timestamp.tzinfo == timezone.utc
    assert parsed.size_bytes == 60


def test_parses_udp_packet() -> None:
    parsed = PacketParser().parse(ip_packet(("UDP", SimpleNamespace(sport=53000, dport=53))))

    assert parsed is not None
    assert (parsed.protocol, parsed.source_port, parsed.destination_port) == ("UDP", 53000, 53)
    assert parsed.tcp_flags is None


def test_parses_icmp_packet() -> None:
    parsed = PacketParser().parse(ip_packet(("ICMP", object())))

    assert parsed is not None
    assert parsed.protocol == "ICMP"
    assert parsed.source_port is None


def test_handles_non_ip_and_malformed_packet_without_crashing() -> None:
    assert PacketParser().parse(SyntheticPacket({"Ether": object()})) is None
    assert PacketParser().parse(ip_packet(("TCP", SimpleNamespace(sport="invalid")))) is None


def test_parses_unknown_ip_protocol_as_other() -> None:
    parsed = PacketParser().parse(ip_packet())

    assert parsed is not None
    assert parsed.protocol == "OTHER"
