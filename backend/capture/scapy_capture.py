"""Windows-aware Scapy capture adapter; imports Scapy only when monitoring starts."""

from __future__ import annotations

import platform
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


class PacketCapture(Protocol):
    def start(self, callback: Callable[[Any], None], interface: str | None = None) -> CaptureStatus: ...
    def stop(self) -> CaptureStatus: ...
    def status(self) -> CaptureStatus: ...


class ScapyPacketCapture:
    def __init__(self) -> None:
        self._sniffer: Any | None = None
        self._status = CaptureStatus(running=False, interface=None, error=None)
        self._lock = RLock()

    def start(self, callback: Callable[[Any], None], interface: str | None = None) -> CaptureStatus:
        with self._lock:
            if self._status.running:
                return self._status
            if platform.system() != "Windows":
                return self._fail("Live capture currently supports Windows. Use a supported Scapy capture adapter on this OS.")
            try:
                from scapy.sendrecv import AsyncSniffer

                self._sniffer = AsyncSniffer(iface=interface, prn=callback, store=False)
                self._sniffer.start()
                self._status = CaptureStatus(running=True, interface=interface, error=None)
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
                    self._status = CaptureStatus(running=False, interface=self._status.interface, error=f"Failed to stop capture cleanly: {exc}")
                    self._sniffer = None
                    return self._status
            self._sniffer = None
            self._status = CaptureStatus(running=False, interface=self._status.interface, error=None)
            return self._status

    def status(self) -> CaptureStatus:
        with self._lock:
            return self._status

    def _fail(self, message: str) -> CaptureStatus:
        self._status = CaptureStatus(running=False, interface=self._status.interface, error=message)
        return self._status


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

    def emit(self, packet: Any) -> None:
        if self._status.running and self._callback is not None:
            self._callback(packet)
