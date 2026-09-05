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
)
from backend.database import AlertNotFoundError
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
    )


@router.get("/monitoring/status", response_model=MonitoringStatusResponse)
def monitoring_status(request: Request) -> MonitoringStatusResponse:
    return _status_response(_services(request))


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
