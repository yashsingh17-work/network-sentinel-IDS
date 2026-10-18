# Packet Tracer to Network Sentinel bridge

`simulation interface.pkt` is a Cisco Packet Tracer simulation file. Packet
Tracer does not offer a native API that forwards every simulated frame into a
Windows Python process. This project therefore uses three accurate, visible
paths into the same IDS pipeline:

1. Cisco IOS devices send ACL/interface records as UDP syslog to the collector.
2. A Packet Tracer Sniffer or Simulation Mode export is saved as text/JSONL in
   an export folder; the collector watches that folder.
3. `pt_traffic_replay.py` creates clearly labelled local records for repeatable
   demonstrations. It never sends a ping, scan, or login attempt to a device.

All paths are normalized into the same schema and POSTed to
`POST /api/events/ingest`. The API stores source/destination/protocol/port
evidence in SQLite and immediately sends any generated alert to the dashboard
WebSocket (`/ws` and `/api/ws`).

## TCP versus the application using it

TCP is the delivery method, not the application name. The bridge keeps
`protocol: TCP` and also labels the likely application from the destination
port: TCP/21 is FTP, TCP/80 is HTTP, TCP/443 is HTTPS, TCP/22 is SSH, and
TCP/53 is DNS-over-TCP. That label is stored with the event and shown in alert
context. It is explicitly marked as a **port-based estimate**: a service can
run on a non-standard port, so only deep application inspection could prove it.

## Start the isolated lab profile

Before starting, edit [`config.packet-tracer.yaml`](../../config.packet-tracer.yaml)
when your Packet Tracer topology changes. The `packet_tracer.targets` section
is the single source of truth for the attacker, Windows target, Linux target,
DNS server, DMZ web server, and gateway. The collector itself accepts events
from any address; this configuration controls the lab replay and the DNS/FTP/
SSH-specific rules.

Open PowerShell in the project folder and use two windows.

Window 1 starts the dashboard/API with thresholds made for this private lab:

```powershell
$env:CONFIG_PATH = "config.packet-tracer.yaml"
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

Window 2 starts the bridge:

```powershell
python pt_collector.py
```

The bridge listens on UDP `514` for Cisco syslog and TCP `9999` for one JSON
object per line. If UDP 514 is already occupied, select a different port with
`--syslog-port 5514`, then use that same port in the Cisco logging command.

For file exports instead of live syslog:

```powershell
python pt_collector.py --watch .\captures
```

It reads only `.jsonl`, `.json`, `.log`, and `.txt` files. One JSON object per
line is the most dependable format. Unknown lines are ignored rather than
invented as traffic.

## Cisco configuration concept

On the router/switch that produces ACL messages, point syslog to the computer
running the collector. Replace `IDS_HOST_IP` with the **actual Windows IPv4
address** reachable from the Packet Tracer lab (or a relay address if the lab
is not bridged to your host):

```text
conf t
logging host IDS_HOST_IP transport udp port 514
logging trap informational
service timestamps log datetime msec
end
```

Packet Tracer's simulated interfaces do not normally reach a Windows host by
themselves. Treat this as a logging/export integration, unless your Packet
Tracer version/topology has a deliberate external bridge. The collector is
still useful in either case because all source records use the same dashboard
and alert engine.

## Lab rules in this profile

The dedicated profile implements the requested small-lab thresholds:

| Activity | Trigger | Alert |
| --- | --- | --- |
| ICMP sweep | 3 destinations in 10 seconds | Medium `ICMP_SWEEP` |
| TCP port scan | 3 destination ports in 8 seconds | Medium/High `PORT_SCAN` |
| SYN flood | 20 initial SYN packets in 1 second | High/Critical `SYN_FLOOD` |
| DNS burst | 5 DNS queries in 5 seconds | Medium `DNS_QUERY_ANOMALY` |
| FTP/SSH failed logins | 3 failures in 30 seconds against `192.168.20.20` | High `AUTH_FAILURE_BURST` |

The raw alert title and explanation are generated from these detections and
include the packet headers/ports that caused them. An alert is a prompt to
investigate—not proof that a machine is malicious.

## Verify without attacking anything

With the profile server running, execute:

```powershell
python test_pipeline.py
```

It posts labelled localhost-only records for the attacker `192.168.10.10`, the
internal targets `192.168.20.10/.20/.53`, and verifies the ICMP sweep, TCP
port-probe, and FTP-failure alert chain. The resulting events and alerts remain
in `packet_tracer_network_sentinel.db` for the dashboard to display.

To run individual visual lab scenarios:

```powershell
python pt_traffic_replay.py icmp-sweep
python pt_traffic_replay.py port-scan
python pt_traffic_replay.py syn-flood
python pt_traffic_replay.py dns-burst
python pt_traffic_replay.py ftp-failures
```
