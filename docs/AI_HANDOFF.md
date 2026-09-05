# Network Sentinel: AI handoff

## Primary files

- `backend/detection/detection_engine.py` is the IDS rule engine (the “brain”).
- `backend/config.py` defines every threshold, window, capacity, and cooldown.
- `backend/models.py` defines `NormalizedPacket`, the data contract for all layers.
- `backend/parser/packet_parser.py` extracts packet header details into that model.
- `tests/test_detection_engine.py` and `tests/test_packet_parser.py` protect the rules.
- `backend/services/monitoring_service.py` is the single packet-processing entrypoint.
- `backend/database/alert_repository.py` persists alerts in SQLite.
- `backend/api/routes.py` provides the FastAPI REST surface.

## Current scope

Six explainable, header-only detections exist: `PORT_SCAN`, `SYN_FLOOD`,
`TRAFFIC_RATE_ANOMALY`, `ICMP_SWEEP`, `DNS_QUERY_ANOMALY`, and
`ARP_SPOOFING_SUSPECTED`. Each finding has
a timestamp, severity, source/destination IPs when relevant, observed value,
threshold, and a human-readable explanation. The engine keeps time-window data
bounded and suppresses duplicates using `ALERT_COOLDOWN`.

The application retains Ethernet/ARP identity for a bounded observed-device
list, detects conflicting ARP replies, and provides a local Windows Wi-Fi
posture check. These are risk signals—not conclusive device-malice labels. The
dashboard files are `frontend/index.html`, `frontend/styles.css`, and
`frontend/app.js`; its WebSocket layer is `backend/api/realtime.py` and
`backend/api/dashboard_payload.py`.

## Safe change checklist

1. Add any new threshold or limit to `Settings` in `backend/config.py` and its
   `from_env()` method.
2. Preserve the `NormalizedPacket` contract or update parser and tests together.
3. Keep rules header-only and explainable for V1; do not add payload inspection,
   machine learning, cloud services, or automatic response.
4. Add normal-traffic and positive synthetic tests.
5. Run `python -m pytest tests -q` before committing.

## API milestone status

The REST API, alert manager, SQLite database, Scapy capture adapter, WebSockets,
and dashboard are complete. Npcap and appropriate Windows permissions are
still required for actual live capture.
