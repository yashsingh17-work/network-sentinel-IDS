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
