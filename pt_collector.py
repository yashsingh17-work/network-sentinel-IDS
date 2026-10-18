"""Packet Tracer bridge for Network Sentinel.

This program never sends packets to lab hosts.  It listens for records that a
Cisco device/exporter sends to it, normalizes them, and POSTs them to the local
Network Sentinel API.  It supports three honest Packet Tracer integration
paths: Cisco-style syslog, newline-delimited JSON, and exported text/PCAP
files placed in a watched folder.

Start the dashboard API first, then run this program in a second terminal.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
import time
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen


DEFAULT_API = "http://127.0.0.1:8000/api/events/ingest"
_ACL = re.compile(
    r"(?P<protocol>tcp|udp|icmp|arp)\s+(?P<src>\d{1,3}(?:\.\d{1,3}){3})(?:\((?P<src_port>\d+)\))?"
    r"\s*(?:->|to)\s*(?P<dst>\d{1,3}(?:\.\d{1,3}){3})(?:\((?P<dst_port>\d+)\))?",
    re.IGNORECASE,
)
_FTP_FAILURE = re.compile(r"(?:ftp.*)?\b530\b|user cannot log in|authentication failed", re.IGNORECASE)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _number(value: str | None) -> int | None:
    return int(value) if value else None


def normalize_syslog(line: str) -> dict[str, Any] | None:
    """Convert common IOS ACL/syslog syntax into the collector schema.

    Unknown log lines are deliberately ignored rather than guessed.  A raw
    copy is retained for investigation, capped by the API schema.
    """
    match = _ACL.search(line)
    if not match:
        return None
    protocol = match.group("protocol").upper()
    flags = ["SYN"] if protocol == "TCP" and "SYN" in line.upper() else []
    return {
        "timestamp": _now(),
        "source_ip": match.group("src"),
        "source_port": _number(match.group("src_port")),
        "dest_ip": match.group("dst"),
        "dest_port": _number(match.group("dst_port")),
        "protocol": protocol,
        "flags": flags,
        "payload_size": 0,
        "raw_data": line[:4096],
        "metadata": {"device_role": "Gateway", "ingestion_source": "cisco_syslog"},
    }


def normalize_json(value: dict[str, Any]) -> dict[str, Any] | None:
    """Validate/lightly complete an already-normalized JSON event."""
    required = {"source_ip", "dest_ip", "protocol"}
    if not required <= value.keys():
        return None
    protocol = str(value["protocol"]).upper()
    if protocol not in {"TCP", "UDP", "ICMP", "ARP"}:
        return None
    flags = value.get("flags", [])
    if isinstance(flags, str):
        flags = [flag for flag in re.split(r"[,\s]+", flags) if flag]
    return {
        "timestamp": str(value.get("timestamp") or _now()),
        "source_ip": str(value["source_ip"]), "source_port": value.get("source_port"),
        "dest_ip": str(value["dest_ip"]), "dest_port": value.get("dest_port"),
        "protocol": protocol, "flags": list(flags),
        "payload_size": int(value.get("payload_size", 0) or 0),
        "raw_data": str(value.get("raw_data", ""))[:4096],
        "metadata": dict(value.get("metadata") or {}),
    }


def post_events(api_url: str, events: list[dict[str, Any]]) -> dict[str, Any]:
    payload = json.dumps({"events": events}).encode("utf-8")
    request = Request(api_url, data=payload, headers={"Content-Type": "application/json"}, method="POST")
    with urlopen(request, timeout=5) as response:  # noqa: S310 - user selects a local API URL.
        return json.loads(response.read().decode("utf-8"))


class _UdpProtocol(asyncio.DatagramProtocol):
    def __init__(self, callback):
        self._callback = callback

    def datagram_received(self, data: bytes, addr) -> None:  # type: ignore[no-untyped-def]
        self._callback(data.decode("utf-8", errors="replace"))


async def serve_live(api_url: str, host: str, syslog_port: int, json_port: int) -> None:
    """Run UDP syslog plus TCP JSON line listeners until Ctrl+C."""
    loop = asyncio.get_running_loop()

    def submit(record: dict[str, Any] | None) -> None:
        if record is None:
            return
        try:
            result = post_events(api_url, [record])
            print(f"ingested 1 event; alerts={len(result.get('alerts', []))}")
        except (URLError, TimeoutError, OSError, ValueError) as exc:
            print(f"API delivery failed: {exc}", file=sys.stderr)

    udp_transport, _ = await loop.create_datagram_endpoint(
        lambda: _UdpProtocol(lambda line: submit(normalize_syslog(line))), local_addr=(host, syslog_port)
    )

    async def on_json(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while line := await reader.readline():
                try:
                    raw = json.loads(line.decode("utf-8"))
                    submit(normalize_json(raw) if isinstance(raw, dict) else None)
                except json.JSONDecodeError:
                    continue
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(on_json, host, json_port)
    print(f"Listening for Cisco syslog on udp://{host}:{syslog_port} and JSON lines on tcp://{host}:{json_port}")
    try:
        async with server:
            await server.serve_forever()
    finally:
        udp_transport.close()


def events_from_text(path: Path) -> Iterable[dict[str, Any]]:
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            decoded = json.loads(line)
        except json.JSONDecodeError:
            event = normalize_syslog(line)
        else:
            event = normalize_json(decoded) if isinstance(decoded, dict) else None
        if event:
            yield event


def ingest_directory(api_url: str, directory: Path, once: bool = False) -> None:
    """Poll an export folder.  Files are read only after their size settles."""
    seen: dict[Path, tuple[int, float]] = {}
    print(f"Watching exports in {directory.resolve()}")
    while True:
        for path in directory.glob("*"):
            if not path.is_file() or path.suffix.lower() not in {".jsonl", ".json", ".log", ".txt"}:
                continue
            stamp = (path.stat().st_size, path.stat().st_mtime)
            if seen.get(path) == stamp:
                continue
            seen[path] = stamp
            events = list(events_from_text(path))
            if not events:
                continue
            try:
                result = post_events(api_url, events)
                print(f"{path.name}: ingested {len(events)} event(s); alerts={len(result.get('alerts', []))}")
            except (URLError, TimeoutError, OSError, ValueError) as exc:
                print(f"{path.name}: API delivery failed: {exc}", file=sys.stderr)
        if once:
            return
        time.sleep(1)


def main() -> int:
    parser = argparse.ArgumentParser(description="Bridge Packet Tracer exports/syslog to Network Sentinel.")
    parser.add_argument("--api", default=DEFAULT_API)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--syslog-port", type=int, default=514)
    parser.add_argument("--json-port", type=int, default=9999)
    parser.add_argument("--watch", type=Path, help="Folder containing .jsonl/.json/.log/.txt exports")
    parser.add_argument("--once", action="store_true", help="Read the watch folder once and exit")
    args = parser.parse_args()
    if args.watch:
        args.watch.mkdir(parents=True, exist_ok=True)
        ingest_directory(args.api, args.watch, args.once)
    else:
        try:
            asyncio.run(serve_live(args.api, args.host, args.syslog_port, args.json_port))
        except KeyboardInterrupt:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
