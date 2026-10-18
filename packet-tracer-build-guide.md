# Network Sentinel Packet Tracer build guide

This guide builds the one Network Sentinel demonstration lab. The full
machine-readable reference, including every link, is
[`docs/packet-tracer/TOPOLOGY.md`](docs/packet-tracer/TOPOLOGY.md). Do not add
a core switch, VLAN trunk, router subinterfaces, firewall, or a gateway on the
monitoring segment: none belong to this topology.

## 1. Place and cable the devices

Place one Cisco 2911 router (`R1`); four 2960-24TT switches (`Switch_A`,
`Switch_DMZ`, `Switch_B`, `Switch_C_SPAN`); `Kali_Attacker`, `Windows_Target`,
`Linux_Target`, `DNS_Server`, `Web_Server`, `Monitoring_PC`, and `Sniffer0`.

Use copper straight-through cables for these exact links:

| Link | Connection |
| --- | --- |
| L01 | `Kali_Attacker Fa0` ↔ `Switch_A Fa0/1` |
| L02 | `Switch_A Gi0/1` ↔ `R1 Gi0/0` |
| L03 | `Web_Server Fa0` ↔ `Switch_DMZ Fa0/1` |
| L04 | `Switch_DMZ Gi0/1` ↔ `R1 Gi0/1` |
| L05 | `Windows_Target Fa0` ↔ `Switch_B Fa0/1` |
| L06 | `Linux_Target Fa0` ↔ `Switch_B Fa0/2` |
| L07 | `DNS_Server Fa0` ↔ `Switch_B Fa0/3` |
| L08 | `Switch_B Gi0/1` ↔ `R1 Gi0/2` |
| L09 | `Switch_B Fa0/24` ↔ `Switch_C_SPAN Fa0/1` |
| L10 | `Switch_C_SPAN Fa0/2` ↔ `Sniffer0 Fa0` |
| L11 | `Switch_C_SPAN Fa0/3` ↔ `Monitoring_PC Fa0` |

## 2. Configure R1

R1 uses three ordinary physical Layer-3 interfaces; it does not use VLAN
subinterfaces. Enter the following in the R1 CLI:

```text
enable
configure terminal
hostname R1
interface GigabitEthernet0/0
 ip address 192.168.10.1 255.255.255.0
 no shutdown
exit
interface GigabitEthernet0/1
 ip address 192.168.30.1 255.255.255.0
 no shutdown
exit
interface GigabitEthernet0/2
 ip address 192.168.20.1 255.255.255.0
 no shutdown
end
write memory
```

`show ip route` must show exactly three directly connected networks:
`192.168.10.0/24`, `192.168.20.0/24`, and `192.168.30.0/24`.

## 3. Configure the endpoints

Every numbered interface uses mask `255.255.255.0`.

| Host | Address | Gateway | DNS |
| --- | --- | --- | --- |
| `Kali_Attacker` | `192.168.10.10` | `192.168.10.1` | `192.168.20.53` |
| `Web_Server` | `192.168.30.10` | `192.168.30.1` | not required |
| `Windows_Target` | `192.168.20.10` | `192.168.20.1` | `192.168.20.53` |
| `Linux_Target` | `192.168.20.20` | `192.168.20.1` | `192.168.20.53` |
| `DNS_Server` | `192.168.20.53` | `192.168.20.1` | `192.168.20.53` |
| `Monitoring_PC` | `192.168.40.10` | **leave blank** | **leave blank** |

Leave `Sniffer0` unnumbered and use promiscuous analysis mode. The monitoring
segment is Layer-2-only: `192.168.40.0/24` has no R1 interface, no `.40.1`
gateway, and no normal routed access to the other three networks.

## 4. Configure Switch B Local SPAN

On `Switch_B`, mirror all three victim ports and the router uplink in both
directions to the dedicated output port `Fa0/24`:

```text
enable
configure terminal
monitor session 1 source interface Fa0/1, Fa0/2, Fa0/3, Gi0/1 both
monitor session 1 destination interface Fa0/24
end
show monitor session 1
```

Packet Tracer version support for SPAN commands varies. If a command is not
available in your simulator, retain the physical L09–L11 layout and use
Simulation Mode/Sniffer0 to demonstrate the mirrored-frame path. Do not turn
`Fa0/24` into an ordinary access uplink.

## 5. Enable services and validate normal traffic

- On `DNS_Server`, create `web.corp.local` → `192.168.30.10`,
  `target.corp.local` → `192.168.20.10`, and `files.corp.local` →
  `192.168.20.20`.
- On `Web_Server`, enable HTTP (TCP/80) and HTTPS (TCP/443).
- On `Linux_Target`, enable FTP (TCP/21) and SSH (TCP/22) if your selected
  Packet Tracer device exposes those services.
- Browse from `Windows_Target` to `web.corp.local`. This is the normal
  baseline: TCP handshake, HTTP request, and response; it should not create an
  IDS attack alert.

## 6. Run safe, local IDS demonstrations

All test addresses are private lab addresses. Use Packet Tracer Simulation
Mode and the dashboard scene/replay controls only for this lab.

| Test | Wire-level target | Expected IDS finding |
| --- | --- | --- |
| ICMP sweep | `.10.10` → `.20.10`, `.20.20`, `.20.53` | `ICMP_SWEEP` |
| TCP scan | `.10.10` → `.20.10` ports 80, 445, 8080 | `PORT_SCAN` |
| FTP failures | `.10.10` → `.20.20:21`, three FTP 530 responses | `AUTH_FAILURE_BURST` |
| DNS burst | `.10.10` → `.20.53:53`, five queries within 5 s | `DNS_QUERY_ANOMALY` |
| Internal ARP conflict | two MACs claiming `192.168.20.1` | `ARP_SPOOFING_SUSPECTED` |

Start Network Sentinel using `config.packet-tracer.yaml` and use
[`docs/packet-tracer/IDS_BRIDGE.md`](docs/packet-tracer/IDS_BRIDGE.md) for the
collector/replay connection. Packet Tracer does not directly forward simulated
frames into Windows Npcap, so live dashboard records arrive through an export,
syslog/JSON bridge, or the explicitly labelled local replay path.
