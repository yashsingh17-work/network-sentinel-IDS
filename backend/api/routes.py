"""REST endpoints for monitoring, traffic visibility, and alerts."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, Request, status

from backend.alerts import Alert
from backend.api.dashboard_payload import dashboard_payload
from backend.api.schemas import (
    AlertHistoryResponse,
    AlertResponse,
    ConnectionStatisticsResponse,
    PacketObservationResponse,
    DeviceActivityResponse,
    MonitoringStatusResponse,
    OverallTrafficResponse,
    ProtocolStatisticsResponse,
    RankedValueResponse,
    TopIpsResponse,
    TopPortsResponse,
    ObservedDeviceResponse,
    DeviceProfileRequest,
    WifiSecurityResponse,
    CaptureInterfaceResponse,
    EventIngestionResponse,
    EventBatchResponse,
    PacketTracerScenarioResponse,
    PacketTracerScenarioRunResponse,
    DownloadAuditResponse,
    DownloadMonitorStatusResponse,
    SecurityEventRequest,
    SecurityEventResponse,
    PacketTracerIngestRequest,
)
from backend.database import AlertNotFoundError
from backend.events import SecurityEvent
from backend.enrichment import describe_port
from backend.sources import WindowsEventReadError
from backend.services import ApplicationServices


router = APIRouter(prefix="/api")


def _services(request: Request) -> ApplicationServices:
    return request.app.state.services


def _status_response(services: ApplicationServices) -> MonitoringStatusResponse:
    current = services.monitoring.status()
    return MonitoringStatusResponse(
        active=current.active,
        started_at=current.started_at,
        capture_ready=current.capture_ready,
        interface=current.interface,
        last_error=current.last_error,
        packets_captured=current.packets_captured,
    )


def _alert_response(alert: Alert) -> AlertResponse:
    return AlertResponse(
        id=alert.id,
        timestamp=alert.timestamp,
        detection_type=alert.detection_type,
        severity=alert.severity,
        source_ip=alert.source_ip,
        destination_ip=alert.destination_ip,
        observed_value=alert.observed_value,
        threshold=alert.threshold,
        evidence=alert.evidence,
        confidence=alert.confidence,
        recommended_investigation=alert.recommended_investigation,
        source=alert.source,
        context=alert.context,
    )


def _event_response(event: SecurityEvent) -> SecurityEventResponse:
    return SecurityEventResponse(
        event_id=event.event_id, timestamp=event.timestamp, source=event.source, event_type=event.event_type,
        source_ip=event.source_ip, destination_ip=event.destination_ip, source_port=event.source_port,
        destination_port=event.destination_port, protocol=event.protocol, bytes_count=event.bytes_count,
        packets_count=event.packets_count, metadata=dict(event.metadata),
    )


def _ranked_response(value: str | int, count: int, services: ApplicationServices) -> RankedValueResponse:
    label = services.enrichment.describe(value).label if isinstance(value, str) else None
    return RankedValueResponse(value=value, count=count, label=label)


@router.get("/monitoring/status", response_model=MonitoringStatusResponse)
def monitoring_status(request: Request) -> MonitoringStatusResponse:
    return _status_response(_services(request))


@router.get("/dashboard")
def dashboard_state(request: Request) -> dict[str, object]:
    """Immediate HTTP snapshot for dashboards before a WebSocket update."""
    return dashboard_payload(_services(request))["data"]


@router.get("/monitoring/interfaces", response_model=list[CaptureInterfaceResponse])
def monitoring_interfaces(request: Request) -> list[dict[str, object]]:
    try:
        return _services(request).monitoring.available_interfaces()
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc


@router.post("/monitoring/start", response_model=MonitoringStatusResponse)
def start_monitoring(request: Request) -> MonitoringStatusResponse:
    _services(request).monitoring.start()
    return _status_response(_services(request))


@router.post("/monitoring/stop", response_model=MonitoringStatusResponse)
def stop_monitoring(request: Request) -> MonitoringStatusResponse:
    _services(request).monitoring.stop()
    return _status_response(_services(request))


@router.get("/traffic/overall", response_model=OverallTrafficResponse)
def overall_traffic(request: Request) -> OverallTrafficResponse:
    snapshot = _services(request).analyzer.snapshot()
    return OverallTrafficResponse(
        total_packets=snapshot.total_packets,
        total_bytes=snapshot.total_bytes,
        packets_per_second=snapshot.packets_per_second,
        bytes_per_second=snapshot.bytes_per_second,
    )


@router.get("/traffic/protocols", response_model=ProtocolStatisticsResponse)
def protocol_statistics(request: Request) -> ProtocolStatisticsResponse:
    return ProtocolStatisticsResponse(protocols=_services(request).analyzer.snapshot().protocols)


@router.get("/traffic/top-ips", response_model=TopIpsResponse)
def top_ips(request: Request) -> TopIpsResponse:
    snapshot = _services(request).analyzer.snapshot()
    services = _services(request)
    return TopIpsResponse(
        sources=[_ranked_response(item.value, item.count, services) for item in snapshot.top_source_ips],
        destinations=[_ranked_response(item.value, item.count, services) for item in snapshot.top_destination_ips],
    )


@router.get("/traffic/top-ports", response_model=TopPortsResponse)
def top_ports(request: Request) -> TopPortsResponse:
    snapshot = _services(request).analyzer.snapshot()
    return TopPortsResponse(
        destinations=[
            RankedValueResponse(
                value=item.value,
                count=item.count,
                label=describe_port(item.value).label,
                description=describe_port(item.value).description,
            )
            for item in snapshot.top_destination_ports
        ]
    )


@router.get("/traffic/connections", response_model=ConnectionStatisticsResponse)
def connection_statistics(request: Request) -> ConnectionStatisticsResponse:
    connections = _services(request).analyzer.snapshot().connections
    return ConnectionStatisticsResponse(
        active_connections=connections.active_connections,
        total_connections_seen=connections.total_connections_seen,
    )


def _packet_observation_response(packet) -> PacketObservationResponse:
    source = describe_port(packet.source_port) if packet.source_port is not None else None
    destination = describe_port(packet.destination_port) if packet.destination_port is not None else None
    return PacketObservationResponse(
        timestamp=packet.timestamp, source_ip=packet.source_ip, destination_ip=packet.destination_ip,
        protocol=packet.protocol, source_port=packet.source_port, destination_port=packet.destination_port,
        source_port_label=source.label if source else None,
        destination_port_label=destination.label if destination else None,
        likely_application_protocol=destination.service if destination else None,
        tcp_flags=packet.tcp_flags, size_bytes=packet.size_bytes,
        dns_query_name=packet.dns_query_name, icmp_type=packet.icmp_type,
        dhcp_message_type=packet.dhcp_message_type, dhcp_server_id=packet.dhcp_server_id,
        triggered_alert_types=list(getattr(packet, "triggered_alert_types", ())),
        alert_evidence=list(getattr(packet, "alert_evidence", ())),
    )


@router.get("/traffic/protocols/{protocol}/packets", response_model=list[PacketObservationResponse])
def protocol_packets(
    request: Request, protocol: str, limit: int = Query(default=100, ge=1, le=500),
    source_ip: str | None = None, destination_ip: str | None = None,
    destination_port: int | None = Query(default=None, ge=0, le=65535),
    service: str | None = Query(default=None, max_length=50),
) -> list[PacketObservationResponse]:
    normalized = protocol.upper()
    if normalized not in {"ALL", "TCP", "UDP", "ICMP", "ICMPV6", "ARP", "OTHER"}:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Unknown protocol.")
    services = _services(request)
    recent = services.analyzer.recent_packets(
        protocol=None if normalized == "ALL" else normalized, source_ip=source_ip, destination_ip=destination_ip,
        destination_port=destination_port, service=service, limit=limit,
    )
    if recent or (normalized == "ALL" and not any((source_ip, destination_ip, destination_port, service))):
        return [_packet_observation_response(packet) for packet in recent]

    # Packet Tracer/collector events are persisted. If busy live capture has
    # already rotated the bounded dashboard buffer, keep a filtered
    # investigation useful by looking at those saved, normalized records.
    stored = []
    for event in services.event_ingestion.recent(limit=500):
        packet = event.to_packet()
        if packet is None:
            continue
        if normalized != "ALL" and packet.protocol != normalized:
            continue
        if source_ip and packet.source_ip != source_ip:
            continue
        if destination_ip and packet.destination_ip != destination_ip:
            continue
        if destination_port is not None and packet.destination_port != destination_port:
            continue
        if service and (packet.destination_port is None or describe_port(packet.destination_port).service.casefold() != service.casefold()):
            continue
        stored.append(_packet_observation_response(packet))
        if len(stored) >= limit:
            break
    return stored


@router.get("/devices", response_model=list[ObservedDeviceResponse])
def observed_devices(request: Request) -> list[ObservedDeviceResponse]:
    profiles = _services(request).device_profiles.profiles()
    return [
        ObservedDeviceResponse(
            mac_address=device.mac_address,
            ip_addresses=device.ip_addresses,
            first_seen=device.first_seen,
            last_seen=device.last_seen,
            packets_seen=device.packets_seen,
            protocols=device.protocols,
            vendor=device.vendor,
            likely_role=device.likely_role,
            observed_services=device.observed_services,
            display_name=profiles.get(device.mac_address.lower()).display_name if device.mac_address.lower() in profiles else None,
            physical_location=profiles.get(device.mac_address.lower()).physical_location if device.mac_address.lower() in profiles else None,
        )
        for device in _services(request).device_tracker.snapshot()
    ]


@router.get("/devices/{mac_address}/activity", response_model=DeviceActivityResponse)
def device_activity(request: Request, mac_address: str, limit: int = Query(default=100, ge=1, le=500)) -> DeviceActivityResponse:
    normalized = mac_address.lower().replace("-", ":")
    device = next((item for item in _services(request).device_tracker.snapshot() if item.mac_address.lower() == normalized), None)
    if device is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device has not been observed in captured traffic.")
    profile = _services(request).device_profiles.profiles().get(normalized)
    response = ObservedDeviceResponse(
        mac_address=device.mac_address, ip_addresses=device.ip_addresses, first_seen=device.first_seen, last_seen=device.last_seen,
        packets_seen=device.packets_seen, protocols=device.protocols, vendor=device.vendor, likely_role=device.likely_role,
        observed_services=device.observed_services, display_name=profile.display_name if profile else None,
        physical_location=profile.physical_location if profile else None,
    )
    return DeviceActivityResponse(
        device=response,
        recent_packets=[_packet_observation_response(packet) for packet in _services(request).analyzer.recent_packets(mac_address=normalized, limit=limit)],
        history_note="This is the newest bounded in-memory header history (up to 1,000 packets), not a full packet capture archive.",
    )


@router.put("/devices/{mac_address}/profile", response_model=ObservedDeviceResponse)
def update_device_profile(request: Request, mac_address: str, body: DeviceProfileRequest) -> ObservedDeviceResponse:
    """Store a human-provided name/location; physical location is never inferred from packets."""
    normalized = mac_address.lower().replace("-", ":")
    profile = _services(request).device_profiles.upsert(
        normalized, body.display_name.strip() if body.display_name else None,
        body.physical_location.strip() if body.physical_location else None,
    )
    device = next((item for item in _services(request).device_tracker.snapshot() if item.mac_address.lower() == normalized), None)
    if device is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device has not been observed in captured traffic.")
    return ObservedDeviceResponse(
        mac_address=device.mac_address, ip_addresses=device.ip_addresses, first_seen=device.first_seen, last_seen=device.last_seen,
        packets_seen=device.packets_seen, protocols=device.protocols, vendor=device.vendor, likely_role=device.likely_role,
        observed_services=device.observed_services, display_name=profile.display_name, physical_location=profile.physical_location,
    )


@router.get("/wifi/security", response_model=WifiSecurityResponse)
def wifi_security(request: Request) -> WifiSecurityResponse:
    current = _services(request).wifi_security.status()
    return WifiSecurityResponse(
        available=current.available,
        connected=current.connected,
        ssid=current.ssid,
        authentication=current.authentication,
        cipher=current.cipher,
        secure=current.secure,
        summary=current.summary,
    )


@router.get("/endpoint/downloads/status", response_model=DownloadMonitorStatusResponse)
def download_monitor_status(request: Request) -> DownloadMonitorStatusResponse:
    current = _services(request).endpoint_safety.download_status()
    return DownloadMonitorStatusResponse(
        enabled=current.enabled, initialized=current.initialized, directories=current.directories,
        tracked_files=current.tracked_files, last_scan_at=current.last_scan_at,
    )


@router.post("/endpoint/downloads/audit", response_model=DownloadAuditResponse)
def audit_current_downloads(request: Request) -> DownloadAuditResponse:
    """On-demand local inspection of current Downloads files; does not upload or execute files."""
    inspected = _services(request).endpoint_safety.audit_current_downloads()
    return DownloadAuditResponse(
        files_inspected=inspected, events_created=inspected,
        alerts=[],
    )


@router.post("/events", response_model=EventIngestionResponse, status_code=status.HTTP_202_ACCEPTED)
def ingest_event(request: Request, body: SecurityEventRequest) -> EventIngestionResponse:
    event = SecurityEvent(**body.model_dump())
    result = _services(request).event_ingestion.ingest(event)
    return EventIngestionResponse(event=_event_response(result.event), alerts=[_alert_response(alert) for alert in result.alerts])


@router.post("/events/ingest", response_model=EventBatchResponse, status_code=status.HTTP_202_ACCEPTED)
def ingest_packet_tracer_events(request: Request, body: PacketTracerIngestRequest) -> EventBatchResponse:
    """Ingest one or a batch of strict Packet Tracer-normalized events.

    This route is intentionally source-specific so a Packet Tracer collector
    can use stable names (``dest_ip``, ``flags``, ``payload_size``) without
    leaking Cisco/syslog syntax into the rest of the application.
    """
    from backend.events import SecurityEvent

    alerts: list[Alert] = []
    for record in body.events:
        metadata = dict(record.metadata)
        metadata.update({
            "tcp_flags": "".join(record.flags),
            "raw_data": record.raw_data,
            "collector_schema": "packet_tracer.v1",
        })
        if record.dest_port is not None:
            service = describe_port(record.dest_port)
            metadata.update({
                "transport_protocol": record.protocol,
                "likely_application_protocol": service.service,
                "application_protocol_description": service.description,
                "application_protocol_basis": "destination port (port-based estimate)",
            })
        # Packet Tracer text exports frequently expose DNS/ICMP as prose rather
        # than a full packet object.  Preserve only the small fields the normal
        # rule engine needs; application payloads are not interpreted.
        if record.protocol == "ICMP" and "echo request" in record.raw_data.lower():
            metadata.setdefault("icmp_type", 8)
        if record.protocol in {"TCP", "UDP"} and record.dest_port == 53:
            metadata.setdefault("dns_query_name", record.raw_data or "packet-tracer-dns-query")
        event = SecurityEvent(
            timestamp=record.timestamp,
            source="packet_tracer_collector",
            event_type="network_packet",
            source_ip=record.source_ip,
            destination_ip=record.dest_ip,
            source_port=record.source_port,
            destination_port=record.dest_port,
            protocol=record.protocol,
            bytes_count=record.payload_size,
            packets_count=1,
            metadata=metadata,
        )
        alerts.extend(_services(request).event_ingestion.ingest(event).alerts)
    return EventBatchResponse(events_created=len(body.events), alerts=[_alert_response(alert) for alert in alerts])


@router.get("/events/recent", response_model=list[SecurityEventResponse])
def recent_events(request: Request, limit: int = Query(default=100, ge=1, le=500)) -> list[SecurityEventResponse]:
    return [_event_response(event) for event in _services(request).event_ingestion.recent(limit)]


@router.post("/demo/run", response_model=EventBatchResponse)
def run_safe_demo(request: Request) -> EventBatchResponse:
    """Generate local synthetic records only; it never sends network traffic."""
    result = _services(request).demo.run()
    return EventBatchResponse(events_created=result.events_created, alerts=[_alert_response(alert) for alert in result.alerts])


def _packet_tracer_scenario_response(scenario: object) -> PacketTracerScenarioResponse:
    return PacketTracerScenarioResponse(
        scenario_id=scenario.scenario_id, title=scenario.title, description=scenario.description,
        packet_tracer_action=scenario.packet_tracer_action,
    )


@router.get("/demo/packet-tracer/scenarios", response_model=list[PacketTracerScenarioResponse])
def packet_tracer_scenarios(request: Request) -> list[PacketTracerScenarioResponse]:
    return [_packet_tracer_scenario_response(item) for item in _services(request).packet_tracer_demo.scenarios()]


@router.post("/demo/packet-tracer/{scenario_id}", response_model=PacketTracerScenarioRunResponse)
def run_packet_tracer_scenario(request: Request, scenario_id: str) -> PacketTracerScenarioRunResponse:
    """Create only local, labelled records that match a Packet Tracer lab scene."""
    try:
        result = _services(request).packet_tracer_demo.run(scenario_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return PacketTracerScenarioRunResponse(
        scenario=_packet_tracer_scenario_response(result.scenario), events_created=result.events_created,
        alerts=[_alert_response(alert) for alert in result.alerts],
    )


@router.post("/sources/windows-events/import", response_model=EventBatchResponse)
def import_windows_events(request: Request, limit: int = Query(default=100, ge=1, le=500)) -> EventBatchResponse:
    """Read recent successful/failed Windows authentications without changing the event log."""
    try:
        result = _services(request).windows_import.import_recent(limit)
    except WindowsEventReadError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc
    return EventBatchResponse(events_created=result.events_imported, alerts=[_alert_response(alert) for alert in result.alerts])


@router.get("/alerts/recent", response_model=list[AlertResponse])
def recent_alerts(request: Request, limit: int = Query(default=50, ge=1, le=500)) -> list[AlertResponse]:
    return [_alert_response(alert) for alert in _services(request).repository.get_recent(limit)]


@router.get("/alerts/history", response_model=AlertHistoryResponse)
def alert_history(
    request: Request,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> AlertHistoryResponse:
    alerts = _services(request).repository.get_history(limit=limit, offset=offset)
    return AlertHistoryResponse(alerts=[_alert_response(alert) for alert in alerts], limit=limit, offset=offset)


@router.get("/alerts/{alert_id}", response_model=AlertResponse)
def alert_details(request: Request, alert_id: str) -> AlertResponse:
    try:
        return _alert_response(_services(request).repository.get_by_id(alert_id))
    except AlertNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found") from exc
