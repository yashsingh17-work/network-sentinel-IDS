# Network Sentinel Packet Tracer topology — canonical lab specification

This is the one authoritative topology for `simulation interface.pkt`,
[`config.packet-tracer.yaml`](../../config.packet-tracer.yaml), replay, and
the Packet Tracer dashboard scenes. Do not combine it with a router-on-a-stick,
core-switch, firewall, NAT, VLAN, `10.x.x.x`, `172.16.x.x`, `198.18.x.x`, or
`192.168.40.1` design. Those are not part of this lab.

## Devices and roles

| Identifier | Packet Tracer type | Zone | Role / service |
| --- | --- | --- | --- |
| `R1` | Cisco 2911 ISR | routing core | Three physical L3 interfaces, ICMP control plane. |
| `Switch_A` | Catalyst 2960-24TT | attacker | Layer-2 access switch. |
| `Kali_Attacker` | PC-PT / Laptop-PT | attacker | Controlled source for ICMP, TCP, FTP and DNS test traffic. |
| `Switch_DMZ` | Catalyst 2960-24TT | DMZ | Layer-2 access switch. |
| `Web_Server` | Server-PT | DMZ | HTTP TCP/80 and HTTPS TCP/443. |
| `Switch_B` | Catalyst 2960-24TT | internal | Layer-2 access switch and local SPAN source. |
| `Windows_Target` | PC-PT | internal | Workstation; web client and ICMP Echo responder. |
| `Linux_Target` | Server-PT / PC-PT | internal | FTP TCP/21 and SSH TCP/22. |
| `DNS_Server` | Server-PT | internal | DNS UDP/TCP 53. |
| `Switch_C_SPAN` | Catalyst 2960-24TT | monitoring | Distributes mirrored frames. |
| `Sniffer0` | PT Packet Sniffer | monitoring | Unnumbered, promiscuous packet analyser. |
| `Monitoring_PC` | PC-PT | monitoring | Security workstation, isolated from R1. |

## Exact physical links

Use 100BASE-TX / 1000BASE-T copper straight-through (UTP) for every link.

| Link | Device / port A | Device / port B | Purpose |
| --- | --- | --- | --- |
| L01 | `Kali_Attacker` `FastEthernet0` | `Switch_A` `FastEthernet0/1` | attacker access |
| L02 | `Switch_A` `GigabitEthernet0/1` | `R1` `GigabitEthernet0/0` | attacker uplink |
| L03 | `Web_Server` `FastEthernet0` | `Switch_DMZ` `FastEthernet0/1` | DMZ access |
| L04 | `Switch_DMZ` `GigabitEthernet0/1` | `R1` `GigabitEthernet0/1` | DMZ uplink |
| L05 | `Windows_Target` `FastEthernet0` | `Switch_B` `FastEthernet0/1` | internal host 1 |
| L06 | `Linux_Target` `FastEthernet0` | `Switch_B` `FastEthernet0/2` | internal host 2 |
| L07 | `DNS_Server` `FastEthernet0` | `Switch_B` `FastEthernet0/3` | internal DNS |
| L08 | `Switch_B` `GigabitEthernet0/1` | `R1` `GigabitEthernet0/2` | internal uplink |
| L09 | `Switch_B` `FastEthernet0/24` | `Switch_C_SPAN` `FastEthernet0/1` | dedicated SPAN delivery |
| L10 | `Switch_C_SPAN` `FastEthernet0/2` | `Sniffer0` `FastEthernet0` | packet-analyser tap |
| L11 | `Switch_C_SPAN` `FastEthernet0/3` | `Monitoring_PC` `FastEthernet0` | security workstation |

## IPv4 configuration

Every numbered interface has mask `255.255.255.0` (`/24`).

| Device | Interface | IPv4 / gateway / DNS |
| --- | --- | --- |
| `R1` | `GigabitEthernet0/0` | `192.168.10.1/24` |
| `R1` | `GigabitEthernet0/1` | `192.168.30.1/24` |
| `R1` | `GigabitEthernet0/2` | `192.168.20.1/24` |
| `Kali_Attacker` | `FastEthernet0` | `192.168.10.10/24`; gateway `192.168.10.1`; DNS `192.168.20.53` |
| `Web_Server` | `FastEthernet0` | `192.168.30.10/24`; gateway `192.168.30.1` |
| `Windows_Target` | `FastEthernet0` | `192.168.20.10/24`; gateway `192.168.20.1`; DNS `192.168.20.53` |
| `Linux_Target` | `FastEthernet0` | `192.168.20.20/24`; gateway `192.168.20.1`; DNS `192.168.20.53` |
| `DNS_Server` | `FastEthernet0` | `192.168.20.53/24`; gateway and DNS `192.168.20.1` / `192.168.20.53` |
| `Monitoring_PC` | `FastEthernet0` | `192.168.40.10/24`; **no gateway and no DNS** |
| `Sniffer0` | `FastEthernet0` | unnumbered, promiscuous mode |

R1 therefore has only these connected routes: `192.168.10.0/24` via `Gi0/0`,
`192.168.30.0/24` via `Gi0/1`, and `192.168.20.0/24` via `Gi0/2`.
`192.168.40.0/24` is an isolated monitoring segment—not a routed R1 network.

## Switch B SPAN

Configure Local SPAN session 1 with source interfaces `Fa0/1`, `Fa0/2`,
`Fa0/3`, and `Gi0/1`, direction `both`, destination `Fa0/24`. The destination
is dedicated mirror output; it is not a normal user port.

```text
monitor session 1 source interface Fa0/1, Fa0/2, Fa0/3, Gi0/1 both
monitor session 1 destination interface Fa0/24
```

## Services and deterministic test flows

| DNS name / flow | Destination | Service or signature |
| --- | --- | --- |
| `web.corp.local` | `192.168.30.10` | HTTP TCP/80; HTTPS TCP/443 |
| `target.corp.local` | `192.168.20.10` | Windows target; example probes TCP/80, 445, 8080 |
| `files.corp.local` | `192.168.20.20` | FTP TCP/21; SSH TCP/22 |
| DNS authority | `192.168.20.53` | DNS UDP/TCP 53 |
| ICMP sweep | `.10.10` → `.20.10`, `.20.20`, `.20.53` | ICMP Echo Request type 8; 3 destinations in 10 s |
| TCP scan | `.10.10` → `.20.10` | TCP SYN to ports 80, 445, 8080; RST/ACK response |
| FTP brute force | `.10.10` → `.20.20` | TCP/21; repeated `USER` / `PASS`, then `530 User cannot log in` |
| DNS burst | `.10.10` → `.20.53` | at least 5 UDP/53 queries in 5 s |
| normal baseline | `.20.10` → `.30.10` | TCP handshake, HTTP `GET /`, `200 OK` |

The local collector/replay integration is described in
[`IDS_BRIDGE.md`](IDS_BRIDGE.md). It truthfully labels replay records as local
demonstration records: Packet Tracer simulated frames do not automatically
appear in Windows Npcap capture.
