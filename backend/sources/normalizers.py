"""Pure adapters for common open-source and host telemetry formats.

They parse supplied records only. Reading Zeek, Suricata, or Windows logs is a
separate deployment choice, so this application remains useful without them.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping

from backend.events import SecurityEvent


def _timestamp(value: Any) -> datetime:
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)
    if isinstance(value, str):
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc)


def _integer(value: Any) -> int | None:
    try:
        return int(value) if value not in {None, "-", ""} else None
    except (TypeError, ValueError):
        return None


class ZeekNormalizer:
    """Normalize a Zeek JSON/JSONL connection or notice record."""

    source_name = "zeek"

    def normalize(self, record: Mapping[str, Any], stream: str = "conn") -> SecurityEvent:
        origin = record.get("id.orig_h")
        response = record.get("id.resp_h")
        event_type = "zeek_notice" if stream == "notice" else "network_connection"
        return SecurityEvent(
            timestamp=_timestamp(record.get("ts")),
            source=self.source_name,
            event_type=event_type,
            source_ip=str(origin) if origin else None,
            destination_ip=str(response) if response else None,
            source_port=_integer(record.get("id.orig_p")),
            destination_port=_integer(record.get("id.resp_p")),
            protocol=str(record.get("proto", "")).upper() or None,
            bytes_count=(_integer(record.get("orig_bytes")) or 0) + (_integer(record.get("resp_bytes")) or 0),
            packets_count=(_integer(record.get("orig_pkts")) or 0) + (_integer(record.get("resp_pkts")) or 0),
            metadata={key: value for key, value in record.items() if key not in {"ts", "id.orig_h", "id.resp_h", "id.orig_p", "id.resp_p", "proto", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts"}},
        )


class SuricataNormalizer:
    """Normalize one Suricata EVE JSON record, preserving signature metadata."""

    source_name = "suricata"

    def normalize(self, record: Mapping[str, Any]) -> SecurityEvent:
        alert = record.get("alert") if isinstance(record.get("alert"), Mapping) else {}
        return SecurityEvent(
            timestamp=_timestamp(record.get("timestamp")),
            source=self.source_name,
            event_type="ids_alert" if record.get("event_type") == "alert" else f"suricata_{record.get('event_type', 'event')}",
            source_ip=str(record["src_ip"]) if record.get("src_ip") else None,
            destination_ip=str(record["dest_ip"]) if record.get("dest_ip") else None,
            source_port=_integer(record.get("src_port")),
            destination_port=_integer(record.get("dest_port")),
            protocol=str(record.get("proto", "")).upper() or None,
            metadata={"signature": alert.get("signature"), "signature_id": alert.get("signature_id"), "severity": alert.get("severity"), "category": alert.get("category"), "raw_event_type": record.get("event_type")},
        )


class WindowsEventNormalizer:
    """Normalize Windows security-authentication records without Windows-only imports."""

    source_name = "windows_event_log"

    def normalize(self, record: Mapping[str, Any]) -> SecurityEvent:
        event_id = _integer(record.get("event_id") or record.get("EventID"))
        event_type = "authentication_failure" if event_id == 4625 else "authentication_success" if event_id == 4624 else "windows_event"
        user = record.get("target_user") or record.get("TargetUserName")
        source_ip = record.get("ip_address") or record.get("IpAddress")
        return SecurityEvent(
            timestamp=_timestamp(record.get("timestamp") or record.get("TimeCreated")),
            source=self.source_name,
            event_type=event_type,
            source_ip=str(source_ip) if source_ip and source_ip != "-" else None,
            metadata={"event_id": event_id, "user": user, "computer": record.get("computer") or record.get("Computer"), "logon_type": record.get("logon_type") or record.get("LogonType")},
        )
