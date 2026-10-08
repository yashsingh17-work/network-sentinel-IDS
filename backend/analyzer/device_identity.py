"""Cautious, offline hints for an observed MAC address and its traffic role."""

from __future__ import annotations

from collections.abc import Mapping

from backend.enrichment import describe_port


# A small offline set of recognisable common prefixes. Anything else remains
# unknown rather than making a guess from an unverified online lookup.
_OUI_VENDORS = {
    "00:25:96": "Cisco Systems",
    "00:1A:A1": "Cisco Systems",
    "00:1B:21": "Intel Corporate",
    "00:1C:42": "Parallels",
    "00:1E:C2": "Apple",
    "00:25:00": "Apple",
    "00:50:56": "VMware",
    "08:00:27": "Oracle VirtualBox",
    "3C:52:82": "Google",
    "F4:F5:E8": "Google",
    "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi",
}


def mac_vendor(mac_address: str) -> str | None:
    """Return an offline MAC-prefix match, if the short reference table knows it."""
    return _OUI_VENDORS.get(mac_address.upper().replace("-", ":")[:8])


def likely_role(ip_addresses: list[str], source_ports: Mapping[int, int]) -> str:
    """Return a conservative role hint derived only from observed headers."""
    ports = set(source_ports)
    if 53 in ports:
        return "Likely DNS service"
    if 67 in ports:
        return "Likely DHCP service"
    if 80 in ports or 443 in ports:
        return "Likely web service"
    if 22 in ports:
        return "Likely SSH service"
    if any(address.endswith(".1") for address in ip_addresses):
        return "Possible gateway or network device"
    return "Observed network device"


def observed_service_labels(source_ports: Mapping[int, int]) -> list[str]:
    """Expose only familiar low-numbered source services, never an invented device type."""
    return [
        describe_port(port).label
        for port, _ in sorted(source_ports.items(), key=lambda item: (-item[1], item[0]))
        if port <= 1024 and describe_port(port).description != "No common well-known service is assigned to this port."
    ][:5]
