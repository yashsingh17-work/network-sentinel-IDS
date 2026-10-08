# Network Sentinel: AI handoff

## Primary files

- `backend/events/models.py` is the source-neutral `SecurityEvent` contract.
- `backend/services/event_ingestion_service.py` is the cross-source correlation brain.
- `backend/detection/detection_engine.py` contains the packet-based IDS rules.
- `backend/config.py` defines every threshold, window, capacity, and cooldown.
- `backend/models.py` defines `NormalizedPacket`, the data contract for all layers.
- `backend/parser/packet_parser.py` extracts packet header details into that model.
- `tests/test_detection_engine.py` and `tests/test_packet_parser.py` protect the rules.
- `backend/services/monitoring_service.py` is the single packet-processing entrypoint.
- `backend/database/alert_repository.py` and `backend/database/event_repository.py` persist alerts and event evidence.
- `backend/sources/normalizers.py` converts Zeek, Suricata, and Windows event records without tying the app to any of those tools.
- `backend/api/routes.py` provides the FastAPI REST surface.

## Current scope

Six explainable, header-only detections exist: `PORT_SCAN`, `SYN_FLOOD`,
`TRAFFIC_RATE_ANOMALY`, `ICMP_SWEEP`, `DNS_QUERY_ANOMALY`, and
`ARP_SPOOFING_SUSPECTED`. Each finding has
a timestamp, severity, source/destination IPs when relevant, observed value,
threshold, and a human-readable explanation. The engine keeps time-window data
bounded and suppresses duplicates using `ALERT_COOLDOWN`.

The Mini-SOC intake adds `AUTH_FAILURE_BURST`, `SUSPICIOUS_AUTH_SEQUENCE`,
`SURICATA_SIGNATURE`, and `ZEEK_NETWORK_ANOMALY`. Its public integration point
is `POST /api/events`, with `GET /api/events/recent` for investigation. Alert
records include confidence, source, evidence, and a recommended next step.

The application retains Ethernet/ARP identity for a bounded observed-device
list, detects conflicting ARP replies, and provides a local Windows Wi-Fi
posture check. These are risk signals—not conclusive device-malice labels. The
dashboard files are `frontend/index.html`, `frontend/styles.css`, and
`frontend/app.js`; its WebSocket layer is `backend/api/realtime.py` and
`backend/api/dashboard_payload.py`.

## Safe change checklist

1. Add any new threshold or limit to `config.yaml` and `Settings` in `backend/config.py`.
2. Preserve `SecurityEvent` metadata; do not flatten away source-specific facts.
3. Keep rules explainable; do not add payload inspection, machine learning,
   cloud services, or automatic response without a separately agreed scope.
4. Add normal-traffic and positive synthetic tests.
5. Run `python -m pytest tests -q` before committing.

## API milestone status

The REST API, alert manager, SQLite database, Scapy capture adapter, WebSockets,
and dashboard are complete. Npcap and appropriate Windows permissions are
still required for actual live capture.
