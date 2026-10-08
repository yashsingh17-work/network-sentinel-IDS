# Network Sentinel architecture

Network Sentinel is a small, local Security Monitoring / Mini-SOC platform.
It is deliberately source-agnostic: capture is an input, not the application.

```text
Packet capture / Zeek / Suricata / Windows events / synthetic data
                            |
                       normalizers
                            |
                     SecurityEvent
                            |
      event storage -> correlation + Python detection -> alerts
                            |
                  REST API / WebSocket dashboard / Node-RED
```

## Where to make changes

| Need | Main file |
| --- | --- |
| Shared event fields | `backend/events/models.py` |
| Zeek, Suricata, Windows format conversion | `backend/sources/normalizers.py` |
| Cross-source correlation | `backend/services/event_ingestion_service.py` |
| Packet-based detections | `backend/detection/detection_engine.py` |
| Alert persistence | `backend/database/alert_repository.py` |
| Event persistence | `backend/database/event_repository.py` |
| API routes | `backend/api/routes.py` |
| Configuration | `config.yaml` and `backend/config.py` |

## Source contracts

`SecurityEvent` contains the fields that are useful across sources: timestamp,
source, event type, IPs, ports, protocol, byte/packet counts, and metadata.
Source-specific details stay in `metadata`; they are never discarded just to
make unrelated systems look identical.

`POST /api/events` accepts this normalized shape. This is the clean integration
point for Node-RED or a future log-tail/import component. It returns every
explainable alert created from that event. `GET /api/events/recent` supports
simple investigation.

## Current first-version stack

- Python/FastAPI: source adapters, normalization, detection, correlation, API.
- SQLite: local event and alert storage, intentionally behind small repository classes.
- Npcap/Scapy: optional lightweight Windows capture input.
- Zeek/Suricata: optional JSON record adapters; neither is installed or required.
- Node-RED: optional webhook bridge only; core detection remains fully functional without it.
- Grafana: intentionally deferred. It can query a future PostgreSQL backend or an exported metrics endpoint without changing detection code.

PostgreSQL is a storage-layer change: add a repository with the same `save` and
`recent/history` methods, then select it from `storage.backend`. Detection and
normalization do not depend on SQLite SQL.
