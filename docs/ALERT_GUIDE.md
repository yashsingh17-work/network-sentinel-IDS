# Alert guide

Network Sentinel ranks alerts by **severity** (how much harm the event could
cause) and **confidence** (how strongly the observed evidence fits that rule).
They answer different questions. A high-confidence alert can still be harmless;
an urgent low-confidence alert still deserves a quick check.

## Priority order

`CRITICAL` → `HIGH` → `MEDIUM` → `LOW`

| Level | Meaning | Recommended response |
| --- | --- | --- |
| Critical | A source system such as Suricata labelled a signature severity `1`. | Investigate immediately; contain only after validation. |
| High | Repeated suspicious activity, or a source signature with severity `2`. | Review promptly, validate the host/user, and inspect related evidence. |
| Medium | The base threshold is reached, but the activity has not doubled it. | Triage in normal security review. |
| Low | A source signature with severity `4`. | Keep for context and investigate if correlated with other alerts. |

## Current local packet rules

Each packet rule becomes **medium** at its threshold and **high** at twice the
threshold. Alerts are rate-limited for 60 seconds per rule/subject so one burst
does not flood the dashboard.

| Alert | Medium threshold | High threshold | Time window |
| --- | ---: | ---: | ---: |
| Port scan | 50 distinct destination ports from one IP | 100 ports | 10 seconds |
| SYN flood | 100 initial TCP SYN packets from one IP | 200 SYNs | 1 second |
| Traffic-rate anomaly | 1,000 total packets | 2,000 packets | 1 second |
| ICMP sweep | 20 destinations sent echo requests by one IP | 40 destinations | 10 seconds |
| DNS query anomaly | 100 DNS queries from one IP | 200 queries | 10 seconds |
| ARP spoofing suspected | One IP claimed by 2 MAC addresses | 3 MAC addresses | 120 seconds |

The ARP rule is intentionally cautious: a duplicate claim can be a legitimate
router failover or network change, not necessarily an attacker.

## Events from other security tools

| Alert | Rule | Severity | Confidence |
| --- | --- | --- | ---: |
| Authentication failure burst | 5 failed attempts for the same user/source in 5 minutes | High | 80% |
| Suspicious authentication sequence | A success after one or more recent failures within 10 minutes | High | 75% |
| Suricata signature | Suricata severity 1/2/3/4 maps to Critical/High/Medium/Low | Source-provided | 90% |
| Zeek network anomaly | Zeek emits a notice | Medium | 70% |

## What confidence means

Confidence is a simple, explainable score in this version. It is **not** a
machine-learning prediction and it does not prove an attack. For example, 90%
on a Suricata alert means a specific signature matched the supplied event; it
does not mean there is a 90% mathematical chance that the organisation was
hacked. Use the evidence, source/destination, and recommended next step before
taking disruptive action.
