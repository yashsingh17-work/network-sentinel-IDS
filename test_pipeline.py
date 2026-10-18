"""End-to-end smoke test for a running local Packet Tracer IDS profile.

Run after starting Network Sentinel with ``config.packet-tracer.yaml``.  The
test posts only JSON to 127.0.0.1; it does not contact any simulated or real
lab host.  It verifies the required ping sweep, TCP probes, and FTP failure
alert trail through the public API and SQLite-backed alert service.
"""

from __future__ import annotations

import argparse

from pt_collector import DEFAULT_API, post_events
from pt_traffic_replay import scenario_events


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify the local Packet Tracer IDS API pipeline.")
    parser.add_argument("--api", default=DEFAULT_API)
    args = parser.parse_args()
    cases = {
        "icmp-sweep": "ICMP_SWEEP",
        "port-scan": "PORT_SCAN",
        "ftp-failures": "AUTH_FAILURE_BURST",
    }
    observed: set[str] = set()
    for scenario, expected in cases.items():
        result = post_events(args.api, scenario_events(scenario))
        found = {item["detection_type"] for item in result["alerts"]}
        observed.update(found)
        if expected not in found:
            raise RuntimeError(f"{scenario} did not trigger {expected}; received {sorted(found)}")
        print(f"PASS {scenario}: {expected}")
    print(f"Pipeline verified. Alert types seen: {', '.join(sorted(observed))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
