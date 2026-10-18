"""Safe local Packet Tracer traffic replay for the documented private lab.

It posts labelled event records to localhost only.  It does not open sockets to
192.168.x.x hosts, scan devices, or require Packet Tracer to be running.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
from os import getenv
from pathlib import Path

from backend.config import Settings
from pt_collector import DEFAULT_API, post_events


def lab_settings() -> Settings:
    """Use the dedicated lab topology unless the caller explicitly overrides it.

    The API server already selects its profile in its own PowerShell window.
    Replay runs in a different process, so it must select the same profile by
    default rather than silently falling back to the normal network profile.
    """
    return Settings.from_env(getenv("CONFIG_PATH") or str(Path(__file__).with_name("config.packet-tracer.yaml")))


def event(settings: Settings, now: datetime, *, dest_ip: str, protocol: str, dest_port: int | None = None, flags: list[str] | None = None, raw_data: str = "", offset_ms: int = 0) -> dict:
    return {
        "timestamp": (now + timedelta(milliseconds=offset_ms)).isoformat(),
        "source_ip": settings.packet_tracer_attacker_ip, "source_port": 49152 + offset_ms,
        "dest_ip": dest_ip, "dest_port": dest_port, "protocol": protocol,
        "flags": flags or [], "payload_size": 64, "raw_data": raw_data,
        "metadata": {"device_role": "Attacker", "network_zone": settings.packet_tracer_network_zone, "simulation": True},
    }


def scenario_events(name: str, settings: Settings | None = None) -> list[dict]:
    settings = settings or lab_settings()
    now = datetime.now(timezone.utc)
    if name == "icmp-sweep":
        return [event(settings, now, dest_ip=target, protocol="ICMP", raw_data="ICMP echo request", offset_ms=index * 100)
                for index, target in enumerate((settings.packet_tracer_windows_target_ip, settings.packet_tracer_linux_target_ip, settings.packet_tracer_dns_server or settings.packet_tracer_windows_target_ip))]
    if name == "port-scan":
        # Canonical lab flow: Kali probes three different Windows_Target ports.
        return [event(settings, now, dest_ip=settings.packet_tracer_windows_target_ip, protocol="TCP", dest_port=port, flags=["SYN"], raw_data="TCP SYN connection attempt", offset_ms=index * 100)
                for index, port in enumerate((80, 445, 8080))]
    if name == "syn-flood":
        return [event(settings, now, dest_ip=settings.packet_tracer_windows_target_ip, protocol="TCP", dest_port=80, flags=["SYN"], raw_data="TCP SYN", offset_ms=index * 10)
                for index in range(20)]
    if name == "dns-burst":
        return [event(settings, now, dest_ip=settings.packet_tracer_dns_server or settings.packet_tracer_windows_target_ip, protocol="UDP", dest_port=53, raw_data=f"DNS query lab-{index}.example", offset_ms=index * 100)
                for index in range(5)]
    if name == "ftp-failures":
        return [event(settings, now, dest_ip=settings.packet_tracer_linux_target_ip, protocol="TCP", dest_port=21, raw_data="FTP 530 User cannot log in", offset_ms=index * 100)
                for index in range(3)]
    if name == "baseline-http":
        # This normal flow comes from Windows_Target rather than the attacker.
        baseline = event(settings, now, dest_ip=settings.packet_tracer_dmz_web_server_ip, protocol="TCP", dest_port=80, flags=["SYN"], raw_data="HTTP GET /", offset_ms=0)
        baseline["source_ip"] = settings.packet_tracer_windows_target_ip
        baseline["source_port"] = 51_000
        baseline["metadata"] = {"device_role": "Victim", "network_zone": settings.packet_tracer_internal_network, "simulation": True}
        return [baseline]
    if name == "all":
        return scenario_events("icmp-sweep", settings) + scenario_events("port-scan", settings) + scenario_events("syn-flood", settings) + scenario_events("dns-burst", settings) + scenario_events("ftp-failures", settings) + scenario_events("baseline-http", settings)
    raise ValueError(name)


def main() -> int:
    parser = argparse.ArgumentParser(description="Send safe local Packet Tracer lab records to Network Sentinel.")
    parser.add_argument("scenario", choices=["icmp-sweep", "port-scan", "syn-flood", "dns-burst", "ftp-failures", "baseline-http", "all"])
    parser.add_argument("--api", default=DEFAULT_API)
    args = parser.parse_args()
    settings = lab_settings()
    result = post_events(args.api, scenario_events(args.scenario, settings))
    print(f"Using configured lab topology: attacker={settings.packet_tracer_attacker_ip}, DNS={settings.packet_tracer_dns_server}, auth targets={', '.join(settings.packet_tracer_authentication_targets)}")
    print(f"Sent {result['events_created']} local lab event(s); generated {len(result['alerts'])} alert(s).")
    for alert in result["alerts"]:
        print(f"- {alert['severity']}: {alert['detection_type']} — {alert['evidence']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
