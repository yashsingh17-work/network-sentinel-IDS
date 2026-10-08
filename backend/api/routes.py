"""REST endpoints for monitoring, traffic visibility, and alerts."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, Request, status

from backend.alerts import Alert
from backend.api.schemas import (
    AlertHistoryResponse,
    AlertResponse,
    ConnectionStatisticsResponse,
    MonitoringStatusResponse,
    OverallTrafficResponse,
    ProtocolStatisticsResponse,
    RankedValueResponse,
    TopIpsResponse,
    TopPortsResponse,
    ObservedDeviceResponse,
    WifiSecurityResponse,
    CaptureInterfaceResponse,
    EventIngestionResponse,
    EventBatchResponse,
    SecurityEventRequest,
    SecurityEventResponse,
)
from backend.database import AlertNotFoundError
from backend.events import SecurityEvent
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
    )


def _event_response(event: SecurityEvent) -> SecurityEventResponse:
    return SecurityEventResponse(
        event_id=event.event_id, timestamp=event.timestamp, source=event.source, event_type=event.event_type,
        source_ip=event.source_ip, destination_ip=event.destination_ip, source_port=event.source_port,
        destination_port=event.destination_port, protocol=event.protocol, bytes_count=event.bytes_count,
        packets_count=event.packets_count, metadata=dict(event.metadata),
    )


@router.get("/monitoring/status", response_model=MonitoringStatusResponse)
def monitoring_status(request: Request) -> MonitoringStatusResponse:
    return _status_response(_services(request))


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
    return TopIpsResponse(
        sources=[RankedValueResponse(value=item.value, count=item.count) for item in snapshot.top_source_ips],
        destinations=[RankedValueResponse(value=item.value, count=item.count) for item in snapshot.top_destination_ips],
    )


@router.get("/traffic/top-ports", response_model=TopPortsResponse)
def top_ports(request: Request) -> TopPortsResponse:
    snapshot = _services(request).analyzer.snapshot()
    return TopPortsResponse(destinations=[RankedValueResponse(value=item.value, count=item.count) for item in snapshot.top_destination_ports])


@router.get("/traffic/connections", response_model=ConnectionStatisticsResponse)
def connection_statistics(request: Request) -> ConnectionStatisticsResponse:
    connections = _services(request).analyzer.snapshot().connections
    return ConnectionStatisticsResponse(
        active_connections=connections.active_connections,
        total_connections_seen=connections.total_connections_seen,
    )


@router.get("/devices", response_model=list[ObservedDeviceResponse])
def observed_devices(request: Request) -> list[ObservedDeviceResponse]:
    return [
        ObservedDeviceResponse(
            mac_address=device.mac_address,
            ip_addresses=device.ip_addresses,
            first_seen=device.first_seen,
            last_seen=device.last_seen,
            packets_seen=device.packets_seen,
            protocols=device.protocols,
        )
        for device in _services(request).device_tracker.snapshot()
    ]


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


@router.post("/events", response_model=EventIngestionResponse, status_code=status.HTTP_202_ACCEPTED)
def ingest_event(request: Request, body: SecurityEventRequest) -> EventIngestionResponse:
    event = SecurityEvent(**body.model_dump())
    result = _services(request).event_ingestion.ingest(event)
    return EventIngestionResponse(event=_event_response(result.event), alerts=[_alert_response(alert) for alert in result.alerts])


@router.get("/events/recent", response_model=list[SecurityEventResponse])
def recent_events(request: Request, limit: int = Query(default=100, ge=1, le=500)) -> list[SecurityEventResponse]:
    return [_event_response(event) for event in _services(request).event_ingestion.recent(limit)]


@router.post("/demo/run", response_model=EventBatchResponse)
def run_safe_demo(request: Request) -> EventBatchResponse:
    """Generate local synthetic records only; it never sends network traffic."""
    result = _services(request).demo.run()
    return EventBatchResponse(events_created=result.events_created, alerts=[_alert_response(alert) for alert in result.alerts])


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
