"""Read recent Windows authentication events using the built-in wevtutil command."""

from __future__ import annotations

import platform
import subprocess
import xml.etree.ElementTree as element_tree
from typing import Any


class WindowsEventReadError(RuntimeError):
    pass


class WindowsSecurityEventReader:
    """Read-only adapter; it does not enable auditing or alter Windows logs."""

    def read_recent_authentication_events(self, limit: int = 100) -> list[dict[str, Any]]:
        if platform.system() != "Windows":
            raise WindowsEventReadError("Windows Event Log import is available only on Windows.")
        command = [
            "wevtutil", "qe", "Security", "/q:*[System[(EventID=4624 or EventID=4625)]]",
            "/f:RenderedXml", f"/c:{limit}", "/rd:true",
        ]
        completed = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace", check=False, timeout=20)
        if completed.returncode != 0:
            detail = completed.stderr.strip() or "Windows denied access to the Security event log."
            raise WindowsEventReadError(detail)
        return self._parse_rendered_xml(completed.stdout)

    @staticmethod
    def _parse_rendered_xml(output: str) -> list[dict[str, Any]]:
        cleaned = output.replace('<?xml version="1.0" encoding="utf-8" standalone="yes"?>', "")
        try:
            root = element_tree.fromstring(f"<Events>{cleaned}</Events>")
        except element_tree.ParseError as exc:
            raise WindowsEventReadError(f"Windows returned unreadable event XML: {exc}") from exc
        namespace = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
        records: list[dict[str, Any]] = []
        for event in root.findall("e:Event", namespace):
            event_id = event.findtext("e:System/e:EventID", namespaces=namespace)
            time_created = event.find("e:System/e:TimeCreated", namespace)
            data = {
                node.attrib.get("Name", ""): node.text
                for node in event.findall("e:EventData/e:Data", namespace)
            }
            records.append(
                {
                    "EventID": event_id,
                    "TimeCreated": time_created.attrib.get("SystemTime") if time_created is not None else None,
                    "TargetUserName": data.get("TargetUserName"),
                    "IpAddress": data.get("IpAddress"),
                    "LogonType": data.get("LogonType"),
                    "Computer": event.findtext("e:System/e:Computer", namespaces=namespace),
                }
            )
        return records
