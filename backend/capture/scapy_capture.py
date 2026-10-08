"""Windows-aware Scapy capture adapter; imports Scapy only when monitoring starts."""

from __future__ import annotations

import platform
import ctypes
from dataclasses import dataclass
from threading import RLock
from typing import Any, Callable, Protocol


class CaptureError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class CaptureStatus:
    running: bool
    interface: str | None
    error: str | None
    packets_captured: int = 0


class PacketCapture(Protocol):
    def start(self, callback: Callable[[Any], None], interface: str | None = None) -> CaptureStatus: ...
    def stop(self) -> CaptureStatus: ...
    def status(self) -> CaptureStatus: ...


class ScapyPacketCapture:
    def __init__(self) -> None:
        self._sniffer: Any | None = None
        self._status = CaptureStatus(running=False, interface=None, error=None)
        self._packets_captured = 0
        self._lock = RLock()

    def start(self, callback: Callable[[Any], None], interface: str | None = None) -> CaptureStatus:
        with self._lock:
            if self._status.running:
                return self._status
            if platform.system() != "Windows":
                return self._fail("Live capture currently supports Windows. Use a supported Scapy capture adapter on this OS.")
            if not self._is_elevated():
                return self._fail(
                    "Packet capture requires an elevated Windows process on this Npcap installation. "
                    "Close this server, open PowerShell as Administrator, and start Network Sentinel again."
                )
            try:
                # On Windows Scapy can translate a friendly adapter name such as
                # "Wi-Fi" to Npcap's \Device\NPF_{GUID} identifier.  Using that
                # identifier avoids silently sniffing the wrong adapter.
                import scapy.arch.windows  # noqa: F401
                from scapy.interfaces import resolve_iface
                # Register Ethernet's link-layer decoder before opening the
                # Npcap handle. Without this import Scapy receives frames as
                # generic packets, which prevents the parser from seeing IP,
                # ARP, TCP, UDP, or ICMP layers.
                from scapy.layers.l2 import Ether  # noqa: F401
                from scapy.sendrecv import AsyncSniffer

                capture_interface = resolve_iface(interface).network_name if interface else None
                self._packets_captured = 0

                def handle_packet(packet: Any) -> None:
                    with self._lock:
                        self._packets_captured += 1
                    callback(packet)

                self._sniffer = AsyncSniffer(iface=capture_interface, prn=handle_packet, store=False)
                self._sniffer.start()
                self._status = CaptureStatus(running=True, interface=capture_interface, error=None, packets_captured=0)
            except Exception as exc:
                self._sniffer = None
                self._fail(
                    "Unable to start packet capture. Install Npcap (with WinPcap-compatible mode), "
                    f"then rerun with administrator permission if needed. Details: {exc}"
                )
            return self._status

    def stop(self) -> CaptureStatus:
        with self._lock:
            if self._sniffer is not None:
                try:
                    self._sniffer.stop()
                except Exception as exc:
                    self._status = CaptureStatus(running=False, interface=self._status.interface, error=f"Failed to stop capture cleanly: {exc}", packets_captured=self._packets_captured)
                    self._sniffer = None
                    return self._status
            self._sniffer = None
            self._status = CaptureStatus(running=False, interface=self._status.interface, error=None, packets_captured=self._packets_captured)
            return self._status

    def status(self) -> CaptureStatus:
        with self._lock:
            return CaptureStatus(
                running=self._status.running,
                interface=self._status.interface,
                error=self._status.error,
                packets_captured=self._packets_captured,
            )

    def available_interfaces(self) -> list[dict[str, object]]:
        """Return Scapy/Npcap device identifiers to make adapter selection explicit."""
        if platform.system() != "Windows":
            return []
        try:
            # Importing this module registers Scapy's Windows/Npcap provider.
            import scapy.arch.windows  # noqa: F401
            from scapy.interfaces import ifaces

            ifaces.reload()
            interfaces = []
            for interface in ifaces.values():
                ip_versions = getattr(interface, "ips", {})
                addresses = [
                    str(address)
                    for family_addresses in ip_versions.values()
                    for address in family_addresses
                ]
                interfaces.append(
                    {
                        "name": interface.name,
                        "network_name": str(getattr(interface, "network_name", interface.name)),
                        "description": getattr(interface, "description", None),
                        "index": getattr(interface, "index", None),
                        "ips": addresses,
                    }
                )
            return interfaces
        except Exception as exc:
            raise CaptureError(f"Unable to enumerate Npcap interfaces: {exc}") from exc

    def _fail(self, message: str) -> CaptureStatus:
        self._status = CaptureStatus(running=False, interface=self._status.interface, error=message, packets_captured=self._packets_captured)
        return self._status

    @staticmethod
    def _is_elevated() -> bool:
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError):
            return False


class InMemoryPacketCapture:
    """Test adapter that lets tests inject raw packets without a network driver."""

    def __init__(self) -> None:
        self._callback: Callable[[Any], None] | None = None
        self._status = CaptureStatus(running=False, interface="synthetic", error=None)

    def start(self, callback: Callable[[Any], None], interface: str | None = None) -> CaptureStatus:
        self._callback = callback
        self._status = CaptureStatus(running=True, interface=interface or "synthetic", error=None)
        return self._status

    def stop(self) -> CaptureStatus:
        self._status = CaptureStatus(running=False, interface=self._status.interface, error=None)
        return self._status

    def status(self) -> CaptureStatus:
        return self._status

    def available_interfaces(self) -> list[dict[str, object]]:
        return [
            {
                "name": "synthetic",
                "network_name": "synthetic",
                "description": "In-memory test capture",
                "index": None,
                "ips": [],
            }
        ]

    def emit(self, packet: Any) -> None:
        if self._status.running and self._callback is not None:
            self._callback(packet)


class DisabledPacketCapture:
    """Intentional no-op source used when packet capture is disabled in config."""

    def __init__(self) -> None:
        self._status = CaptureStatus(running=False, interface=None, error="Packet capture is disabled by configuration.")

    def start(self, callback: Callable[[Any], None], interface: str | None = None) -> CaptureStatus:
        return self._status

    def stop(self) -> CaptureStatus:
        return self._status

    def status(self) -> CaptureStatus:
        return self._status

    def available_interfaces(self) -> list[dict[str, object]]:
        return []
