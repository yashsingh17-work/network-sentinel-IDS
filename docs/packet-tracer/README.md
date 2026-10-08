# Network Sentinel Packet Tracer demo lab

This is a **safe hybrid demonstration**. Cisco Packet Tracer shows the dummy
network and packet path; Network Sentinel remains the local security dashboard.
Packet Tracer does not execute this Python application or send its simulated
packets to Npcap, so the dashboard receives matching local-only scenario events
through its own API.

## Lab topology

```text
Attacker-PC ─ ISP-Router ─ ASA-EDGE ─ Core-L3-Switch ─ Access-Switch ─ User-PCs
                                  │            │
                                  │            └──────── Admin-PC (VLAN 30)
                                  │
                                  └── DMZ-Switch ── DMZ-Web-DNS
                                               └── ISR-IDS-IPS (sensor role)

Guest-Wi-Fi/AP ──────────────────────────────────────── Core-L3-Switch
```

Use these roles in Packet Tracer:

| Label | Recommended Packet Tracer device | Purpose |
| --- | --- | --- |
| `ISP-Router` | 2911 router or cloud/router pair | Represents the untrusted outside network. |
| `ASA-EDGE` | ASA 5505/5506-X, when available | Firewall, NAT, and policy enforcement. |
| `Core-L3-Switch` | 3560 multilayer switch | VLAN gateways and internal routing. |
| `DMZ-Switch` / `Access-Switch` | 2960 switches | Separate server and user traffic. |
| `DMZ-Web-DNS` | Server-PT | HTTPS/HTTP and DNS service in the DMZ. |
| `ISR-IDS-IPS` | ISR router with IPS feature, if offered in your version | Visual IDS/IPS sensor; mirror/inspect the DMZ path. |
| `Attacker-PC` | PC-PT | Controlled, fictional outside test host. |
| `Admin-PC`, `User-PC-1`, `User-PC-2` | PC-PT | Normal office/admin endpoints. |
| `Guest-AP` / `Guest-Laptop` | Access Point + Laptop-PT | Isolated guest Wi-Fi segment. |

## Address plan

| Zone/VLAN | Network | Gateway | Important devices |
| --- | --- | --- |
| Outside | `198.18.0.0/24` | `198.18.0.1` (ASA) | Attacker-PC `198.18.0.10`, ISP-Router `198.18.0.254` |
| DMZ | `172.16.40.0/24` | `172.16.40.1` | DMZ-Web-DNS `172.16.40.10` |
| VLAN 10 Users | `10.10.10.0/24` | `10.10.10.1` | User PCs |
| VLAN 20 Services | `10.10.20.0/24` | `10.10.20.1` | Optional internal services |
| VLAN 30 Management | `10.10.30.0/24` | `10.10.30.1` | Admin-PC `10.10.30.25` |
| VLAN 50 Guest Wi-Fi | `10.10.50.0/24` | `10.10.50.1` | Guest AP/Laptop |
| Firewall/Core transit | `10.10.254.0/30` | ASA `10.10.254.1`, core `10.10.254.2` | Routed inside link |

`198.18.0.0/15` is a reserved benchmarking range, so this lab’s outside
addresses are deliberately not real Internet destinations.

## Firewall policy story

Configure the concepts below in ASA CLI or the Packet Tracer firewall interface
available in your version:

1. Outside → DMZ: allow only HTTP/HTTPS to `172.16.40.10`; deny all other inbound traffic.
2. Outside → internal VLANs: deny.
3. Users → DMZ: allow DNS and HTTPS; allow web only if you want to demonstrate it.
4. Management VLAN → network devices: allow SSH/HTTPS administration only.
5. Guest Wi-Fi → internal/management/DMZ: deny; allow only DNS, DHCP, and outside web access.
6. Add NAT/PAT for internal networks toward the outside router.
7. Enable logging where Packet Tracer provides it, and use Simulation Mode to show a permit and a deny.

Never use the topology to scan, attack, or contact a real IP address. The
`Attacker-PC` exists only to make the story understandable in the simulator.

## Matching Network Sentinel scenarios

Start Network Sentinel, then use the dashboard’s **Run Packet Tracer scene**
control after you visually perform the matching action in Packet Tracer. It
creates local sample records only; it never sends network traffic.

| Packet Tracer scene | Dashboard scenario | Expected alert |
| --- | --- | --- |
| Repeated TCP attempts from Attacker-PC to DMZ-Web | `dmz-port-scan` | Port scan, medium at 50 ports |
| Login failure story, then Admin-PC success | `login-brute-force` | Authentication failure burst and suspicious sequence, high |
| Two ARP replies claim gateway `10.10.10.1` | `arp-conflict` | Possible ARP spoofing, medium; validate before acting |
| Traffic through ISR IDS/IPS sensor | `ids-signature` | Suricata-style signature match, high |

The same scenarios are available to automation or a future Node-RED bridge:

```powershell
Invoke-RestMethod -Method Post -Uri 'http://127.0.0.1:8000/api/demo/packet-tracer/dmz-port-scan'
```

List all scenarios at `GET /api/demo/packet-tracer/scenarios`.

## Observed-device information

The Network Sentinel device list can show MAC and IP addresses, packet count,
protocols, a limited offline MAC-prefix vendor match, observed well-known source
services, and a cautious likely-role hint. It does **not** claim to know a
device’s physical location from network packets. Use **Label / location** in
the dashboard to save a name such as `DMZ-Web-DNS` and a human-verified location
such as `Lab rack A`. These labels are stored locally in the SQLite database.

## Suggested presentation sequence

1. Show the zones and firewall rules in the Packet Tracer topology.
2. Prove normal User-PC → DMZ-Web HTTPS is allowed.
3. Switch to Simulation Mode and show an outside attempt being denied or limited.
4. Run the matching Packet Tracer scene in Network Sentinel.
5. Open the alert evidence: it shows the traffic type, source/destination,
   ports/service labels, confidence, and recommended next step.
6. Explain that the dashboard event is synthetic because Packet Tracer is a
   simulator; real deployments feed the same dashboard from packet capture,
   Zeek, Suricata, firewall logs, and Windows events.

## What is real versus simulated

Packet Tracer can realistically demonstrate topology, VLAN separation, routing,
NAT, ACL/firewall policy, and supported protocol flows. Network Sentinel’s
scenario events mirror those flows safely but are not captured Packet Tracer
frames. This keeps the demo repeatable and makes that limitation explicit.
