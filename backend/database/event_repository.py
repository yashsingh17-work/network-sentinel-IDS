"""SQLite storage for source-neutral events used during investigation."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path

from backend.events import SecurityEvent


class EventRepository:
    def __init__(self, database_path: str | Path) -> None:
        self._database_path = str(database_path)

    def initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS security_events (
                    id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    source TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    source_ip TEXT,
                    destination_ip TEXT,
                    source_port INTEGER,
                    destination_port INTEGER,
                    protocol TEXT,
                    bytes_count INTEGER,
                    packets_count INTEGER,
                    metadata_json TEXT NOT NULL
                )
                """
            )
            connection.execute("CREATE INDEX IF NOT EXISTS idx_security_events_timestamp ON security_events(timestamp DESC)")

    def save(self, event: SecurityEvent) -> SecurityEvent:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR IGNORE INTO security_events (
                    id, timestamp, source, event_type, source_ip, destination_ip,
                    source_port, destination_port, protocol, bytes_count, packets_count, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_id, event.timestamp.isoformat(), event.source, event.event_type,
                    event.source_ip, event.destination_ip, event.source_port, event.destination_port,
                    event.protocol, event.bytes_count, event.packets_count, json.dumps(dict(event.metadata), default=str),
                ),
            )
        return event

    def recent(self, limit: int = 100) -> list[SecurityEvent]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM security_events ORDER BY timestamp DESC, id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [
            SecurityEvent(
                event_id=row["id"], timestamp=datetime.fromisoformat(row["timestamp"]), source=row["source"],
                event_type=row["event_type"], source_ip=row["source_ip"], destination_ip=row["destination_ip"],
                source_port=row["source_port"], destination_port=row["destination_port"], protocol=row["protocol"],
                bytes_count=row["bytes_count"], packets_count=row["packets_count"], metadata=json.loads(row["metadata_json"]),
            )
            for row in rows
        ]

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._database_path)
        connection.row_factory = sqlite3.Row
        return connection
