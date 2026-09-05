# Network Sentinel

Local real-time network traffic analyzer and rule-based IDS.

## Development setup

Target runtime: Python 3.12. Create a virtual environment, install dependencies,
then run the synthetic parser tests:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m pytest
```

The first implemented component is the packet parser. It converts Scapy IPv4 TCP,
UDP, ICMP, and other IP packets to `NormalizedPacket`, while safely discarding
non-IP and malformed input. Live capture is intentionally not connected yet.

## Current detection scope

The rule engine provides five transparent, configurable checks: port scans,
high initial TCP SYN activity, total packet-rate anomalies, ICMP echo sweeps,
and unusually high per-source DNS query volume. It examines packet headers and
DNS query names only; it does not inspect application payloads or claim to
classify malicious domains.

See `docs/AI_HANDOFF.md` for the small set of files another coding agent should
read before modifying detection behavior.

## Run the backend API

```powershell
python -m uvicorn backend.main:app --reload
```

Open `http://127.0.0.1:8000/docs` to explore the generated API documentation.
The current API exposes monitoring controls, traffic statistics, and persisted
alert history/details. It deliberately reports `capture_ready: false` until the
next phase wires in the Windows packet-capture adapter.

Key endpoints: `POST /api/monitoring/start`, `POST /api/monitoring/stop`,
`GET /api/traffic/overall`, `GET /api/traffic/protocols`,
`GET /api/traffic/top-ips`, `GET /api/traffic/top-ports`,
`GET /api/traffic/connections`, `GET /api/alerts/recent`,
`GET /api/alerts/history`, and `GET /api/alerts/{alert_id}`.
