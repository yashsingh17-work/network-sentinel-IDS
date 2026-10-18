"""Safe Packet Tracer companion scenarios for the Network Sentinel dashboard.

Packet Tracer is a visual network simulator; it does not send its simulated
frames into this local application. These scenarios create matching, labelled
security records locally so a demonstration is repeatable and never contacts a
real device.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from threading import Lock

from backend.alerts import Alert
from backend.config import Settings
from backend.events import SecurityEvent
from backend.services.event_ingestion_service import EventIngestionService


@dataclass(frozen=True, slots=True)
class PacketTracerScenario:
    scenario_id: str
    title: str
    description: str
    packet_tracer_action: str


@dataclass(frozen=True, slots=True)
class PacketTracerDemoResult:
    scenario: PacketTracerScenario
    events_created: int
    alerts: list[Alert]


class PacketTracerDemoService:
    """Creates local-only records corresponding to the documented Packet Tracer lab."""

    _SCENARIOS = (
        PacketTracerScenario(
            scenario_id="icmp-sweep",
            title="ICMP subnet sweep",
            description="Kali_Attacker sends Echo Requests to all three internal lab targets.",
            packet_tracer_action="In Simulation Mode, send ICMP Echo Requests from Kali_Attacker (192.168.10.10) to .20.10, .20.20, and .20.53 within 10 seconds.",
        ),
        PacketTracerScenario(
            scenario_id="tcp-port-scan",
            title="TCP port scan",
            description="Kali_Attacker probes TCP ports 80, 445, and 8080 on Windows_Target.",
            packet_tracer_action="From Kali_Attacker (192.168.10.10), send TCP SYN probes to Windows_Target (192.168.20.10) ports 80, 445, and 8080 within 8 seconds.",
        ),
        PacketTracerScenario(
            scenario_id="dns-burst",
            title="DNS query burst",
            description="Kali_Attacker sends five rapid DNS queries to the internal DNS authority.",
            packet_tracer_action="Send at least five DNS queries from Kali_Attacker to DNS_Server (192.168.20.53) in five seconds.",
        ),
        PacketTracerScenario(
            scenario_id="ftp-brute-force",
            title="FTP authentication failures",
            description="Kali_Attacker makes repeated failed FTP logins to Linux_Target.",
            packet_tracer_action="Attempt three failed FTP logins from Kali_Attacker to Linux_Target (192.168.20.20, TCP 21) in 30 seconds; each failure should return FTP 530.",
        ),
        PacketTracerScenario(
            scenario_id="baseline-http",
            title="Normal HTTP baseline",
            description="Windows_Target browses the DMZ web server; it should not create an attack alert.",
            packet_tracer_action="Browse from Windows_Target (192.168.20.10) to web.corp.local (192.168.30.10, TCP 80) and inspect the TCP handshake plus HTTP request/response.",
        ),
        PacketTracerScenario(
            scenario_id="arp-conflict",
            title="Possible internal ARP conflict",
            description="Two MAC addresses claim R1's internal gateway; this is a warning for investigation, not proof of an attack.",
            packet_tracer_action="On the internal Switch_B segment, inspect two ARP replies that claim 192.168.20.1 and compare their MAC addresses.",
        ),
    )

    def __init__(self, ingestion: EventIngestionService, settings: Settings) -> None:
        self._ingestion = ingestion
        self._settings = settings
        self._lock = Lock()
        self._run_number = 0

    def scenarios(self) -> tuple[PacketTracerScenario, ...]:
        return self._SCENARIOS

    def run(self, scenario_id: str) -> PacketTracerDemoResult:
        scenario = next((item for item in self._SCENARIOS if item.scenario_id == scenario_id), None)
        if scenario is None:
            raise ValueError(f"Unknown Packet Tracer scenario: {scenario_id}")
        with self._lock:
            self._run_number += 1
            run_number = self._run_number
        now = datetime.now(timezone.utc)
        events = self._events_for(scenario_id, now, run_number)
        alerts: list[Alert] = []
        for event in events:
            alerts.extend(self._ingestion.ingest(event).alerts)
        return PacketTracerDemoResult(scenario=scenario, events_created=len(events), alerts=alerts)

    def _events_for(self, scenario_id: str, now: datetime, run_number: int) -> list[SecurityEvent]:
        metadata = {"scenario": f"packet_tracer:{scenario_id}", "simulation": True}
        if scenario_id == "icmp-sweep":
            return [
                SecurityEvent(
                    timestamp=now + timedelta(milliseconds=offset), source="packet_tracer_demo", event_type="network_packet",
                    source_ip=self._settings.packet_tracer_attacker_ip, destination_ip=destination_ip,
                    protocol="ICMP", bytes_count=64, packets_count=1,
                    metadata={**metadata, "icmp_type": 8, "icmp_code": 0, "topology_role": "Kali_Attacker to internal target"},
                )
                for offset, destination_ip in enumerate((
                    self._settings.packet_tracer_windows_target_ip,
                    self._settings.packet_tracer_linux_target_ip,
                    self._settings.packet_tracer_dns_server or "192.168.20.53",
                ))
            ]
        if scenario_id == "tcp-port-scan":
            source_port = 40_000 + ((run_number * 100) % 20_000)
            return [
                SecurityEvent(
                    timestamp=now + timedelta(milliseconds=offset), source="packet_tracer_demo", event_type="network_connection",
                    source_ip=self._settings.packet_tracer_attacker_ip, destination_ip=self._settings.packet_tracer_windows_target_ip, source_port=source_port + offset,
                    destination_port=destination_port, protocol="TCP", bytes_count=60, packets_count=1,
                    metadata={**metadata, "tcp_flags": "S", "topology_role": "Kali_Attacker to Windows_Target"},
                )
                for offset, destination_port in enumerate((80, 445, 8080))
            ]
        if scenario_id == "dns-burst":
            return [
                SecurityEvent(
                    timestamp=now + timedelta(milliseconds=offset), source="packet_tracer_demo", event_type="network_packet",
                    source_ip=self._settings.packet_tracer_attacker_ip, destination_ip=self._settings.packet_tracer_dns_server or "192.168.20.53",
                    source_port=50_000 + offset, destination_port=53, protocol="UDP", bytes_count=72, packets_count=1,
                    metadata={**metadata, "dns_query_name": f"burst-{offset}.corp.local", "topology_role": "Kali_Attacker to DNS_Server"},
                )
                for offset in range(self._settings.dns_query_rate_threshold)
            ]
        if scenario_id == "ftp-brute-force":
            return [
                SecurityEvent(
                    timestamp=now + timedelta(milliseconds=offset), source="packet_tracer_demo", event_type="authentication_failure",
                    source_ip=self._settings.packet_tracer_attacker_ip, destination_ip=self._settings.packet_tracer_linux_target_ip,
                    source_port=49_000 + offset, destination_port=21, protocol="TCP",
                    metadata={**metadata, "user": "invalid-lab-user", "auth_protocol": "FTP", "response": "530 User cannot log in", "topology_role": "Kali_Attacker to Linux_Target"},
                )
                for offset in range(self._settings.auth_failure_threshold)
            ]
        if scenario_id == "baseline-http":
            return [
                SecurityEvent(
                    timestamp=now + timedelta(milliseconds=offset), source="packet_tracer_demo", event_type="network_connection",
                    source_ip=self._settings.packet_tracer_windows_target_ip, destination_ip=self._settings.packet_tracer_dmz_web_server_ip,
                    source_port=51_000 + offset, destination_port=80, protocol="TCP", bytes_count=160, packets_count=1,
                    metadata={**metadata, "tcp_flags": flags, "application": "HTTP", "http_method": "GET" if offset == 2 else None, "topology_role": "Windows_Target to Web_Server"},
                )
                for offset, flags in enumerate(("S", "SA", "A"))
            ]
        if scenario_id == "arp-conflict":
            return [
                SecurityEvent(
                    timestamp=now + timedelta(milliseconds=offset), source="packet_tracer_demo", event_type="network_packet",
                    source_ip=self._settings.packet_tracer_gateway_ip, destination_ip=self._settings.packet_tracer_windows_target_ip, protocol="ARP", bytes_count=42, packets_count=1,
                    metadata={**metadata, "arp_operation": 2, "arp_source_ip": self._settings.packet_tracer_gateway_ip, "arp_source_mac": mac,
                              "arp_target_ip": self._settings.packet_tracer_windows_target_ip, "arp_target_mac": "00:25:96:aa:10:25", "topology_role": "Configured lab gateway"},
                )
                for offset, mac in enumerate(("00:25:96:aa:10:01", "00:25:96:aa:10:99"))
            ]
        raise ValueError(f"Unknown Packet Tracer scenario: {scenario_id}")
