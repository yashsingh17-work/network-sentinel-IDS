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
            scenario_id="dmz-port-scan",
            title="DMZ port scan",
            description="An outside test host probes many ports on the DMZ web server.",
            packet_tracer_action="Use Simulation Mode to send repeated TCP connection attempts from Attacker-PC to DMZ-Web.",
        ),
        PacketTracerScenario(
            scenario_id="login-brute-force",
            title="Failed logins followed by success",
            description="A demo account has repeated failures, then one successful login.",
            packet_tracer_action="Show the Admin-PC attempting a permitted management login after the failed-login story card.",
        ),
        PacketTracerScenario(
            scenario_id="arp-conflict",
            title="Possible ARP spoofing",
            description="Two MAC addresses claim the same gateway IP; this is a warning, not proof of an attack.",
            packet_tracer_action="Inspect ARP traffic on the user VLAN in Simulation Mode and compare the two claimed MAC addresses.",
        ),
        PacketTracerScenario(
            scenario_id="ids-signature",
            title="IDS signature match",
            description="An IDS signature reports suspicious traffic headed for the DMZ service.",
            packet_tracer_action="Follow the traffic through the firewall and ISR IDS/IPS sensor in the topology.",
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
        if scenario_id == "dmz-port-scan":
            source_port = 40_000 + ((run_number * 100) % 20_000)
            return [
                SecurityEvent(
                    timestamp=now + timedelta(milliseconds=offset), source="packet_tracer_demo", event_type="network_connection",
                    source_ip="198.18.0.10", destination_ip="172.16.40.10", source_port=source_port + offset,
                    destination_port=10_000 + offset, protocol="TCP", bytes_count=60, packets_count=1,
                    metadata={**metadata, "tcp_flags": "S", "topology_role": "Attacker-PC to DMZ-Web"},
                )
                for offset in range(self._settings.port_scan_port_threshold)
            ]
        if scenario_id == "login-brute-force":
            failures = [
                SecurityEvent(
                    timestamp=now + timedelta(milliseconds=offset), source="packet_tracer_demo", event_type="authentication_failure",
                    source_ip="10.10.30.25", metadata={**metadata, "user": "lab.admin", "topology_role": "Admin-PC"},
                )
                for offset in range(self._settings.auth_failure_threshold)
            ]
            return failures + [
                SecurityEvent(
                    timestamp=now + timedelta(seconds=1), source="packet_tracer_demo", event_type="authentication_success",
                    source_ip="10.10.30.25", metadata={**metadata, "user": "lab.admin", "topology_role": "Admin-PC"},
                )
            ]
        if scenario_id == "arp-conflict":
            return [
                SecurityEvent(
                    timestamp=now + timedelta(milliseconds=offset), source="packet_tracer_demo", event_type="network_packet",
                    source_ip="10.10.10.1", destination_ip="10.10.10.25", protocol="ARP", bytes_count=42, packets_count=1,
                    metadata={**metadata, "arp_operation": 2, "arp_source_ip": "10.10.10.1", "arp_source_mac": mac,
                              "arp_target_ip": "10.10.10.25", "arp_target_mac": "00:25:96:aa:10:25", "topology_role": "User VLAN gateway"},
                )
                for offset, mac in enumerate(("00:25:96:aa:10:01", "00:25:96:aa:10:99"))
            ]
        return [
            SecurityEvent(
                timestamp=now, source="suricata", event_type="ids_alert", source_ip="198.18.0.10", destination_ip="172.16.40.10",
                protocol="TCP", destination_port=443,
                metadata={**metadata, "signature": "DEMO: Packet Tracer DMZ policy test", "signature_id": 9_002_001,
                          "severity": 2, "topology_role": "ISR IDS/IPS sensor"},
            )
        ]
