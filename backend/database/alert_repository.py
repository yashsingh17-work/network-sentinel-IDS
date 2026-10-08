"""SQLite persistence for alerts; each operation uses a short-lived connection."""

from __future__ import annotations

import sqlite3
from datetime import datetime
from pathlib import Path
from threading import RLock

from backend.alerts.models import Alert


class AlertNotFoundError(LookupError):
    """Raised when an alert identifier is absent from SQLite."""


class AlertRepository:
    def __init__(self, database_path: str | Path) -> None:
        self._database_path = str(database_path)
        self._lock = RLock()

    def initialize(self) -> None:
        try:
            with self._lock, self._connect() as connection:
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS alerts (
                        id TEXT PRIMARY KEY,
                        timestamp TEXT NOT NULL,
                        detection_type TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        source_ip TEXT,
                        destination_ip TEXT,
                        observed_value REAL NOT NULL,
                        threshold REAL NOT NULL,
                        evidence TEXT NOT NULL,
                        confidence REAL NOT NULL DEFAULT 0.7,
                        recommended_investigation TEXT NOT NULL DEFAULT '',
                        source TEXT NOT NULL DEFAULT 'python_detection'
                    )
                    """
                )
                connection.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp DESC)")
                columns = {row["name"] for row in connection.execute("PRAGMA table_info(alerts)")}
                for name, statement in {
                    "confidence": "ALTER TABLE alerts ADD COLUMN confidence REAL NOT NULL DEFAULT 0.7",
                    "recommended_investigation": "ALTER TABLE alerts ADD COLUMN recommended_investigation TEXT NOT NULL DEFAULT ''",
                    "source": "ALTER TABLE alerts ADD COLUMN source TEXT NOT NULL DEFAULT 'python_detection'",
                }.items():
                    if name not in columns:
                        connection.execute(statement)
        except sqlite3.Error as exc:
            raise RuntimeError(f"Unable to initialize alert database: {exc}") from exc

    def save(self, alert: Alert) -> Alert:
        try:
            with self._lock, self._connect() as connection:
                connection.execute(
                    """
                    INSERT INTO alerts (
                        id, timestamp, detection_type, severity, source_ip, destination_ip,
                        observed_value, threshold, evidence, confidence, recommended_investigation, source
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        alert.id,
                        alert.timestamp.isoformat(),
                        alert.detection_type,
                        alert.severity,
                        alert.source_ip,
                        alert.destination_ip,
                        alert.observed_value,
                        alert.threshold,
                        alert.evidence,
                        alert.confidence,
                        alert.recommended_investigation,
                        alert.source,
                    ),
                )
            return alert
        except sqlite3.Error as exc:
            raise RuntimeError(f"Unable to save alert: {exc}") from exc

    def get_recent(self, limit: int = 50) -> list[Alert]:
        return self.get_history(limit=limit, offset=0)

    def get_history(self, limit: int = 50, offset: int = 0) -> list[Alert]:
        if limit < 1 or offset < 0:
            raise ValueError("limit must be positive and offset cannot be negative")
        try:
            with self._lock, self._connect() as connection:
                rows = connection.execute(
                    "SELECT * FROM alerts ORDER BY timestamp DESC, id DESC LIMIT ? OFFSET ?", (limit, offset)
                ).fetchall()
            return [self._from_row(row) for row in rows]
        except sqlite3.Error as exc:
            raise RuntimeError(f"Unable to read alert history: {exc}") from exc

    def get_by_id(self, alert_id: str) -> Alert:
        try:
            with self._lock, self._connect() as connection:
                row = connection.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
            if row is None:
                raise AlertNotFoundError(alert_id)
            return self._from_row(row)
        except sqlite3.Error as exc:
            raise RuntimeError(f"Unable to read alert: {exc}") from exc

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._database_path)
        connection.row_factory = sqlite3.Row
        return connection

    @staticmethod
    def _from_row(row: sqlite3.Row) -> Alert:
        return Alert(
            id=row["id"],
            timestamp=datetime.fromisoformat(row["timestamp"]),
            detection_type=row["detection_type"],  # type: ignore[arg-type]
            severity=row["severity"],  # type: ignore[arg-type]
            source_ip=row["source_ip"],
            destination_ip=row["destination_ip"],
            observed_value=row["observed_value"],
            threshold=row["threshold"],
            evidence=row["evidence"],
            confidence=row["confidence"] if "confidence" in row.keys() else 0.7,
            recommended_investigation=row["recommended_investigation"] if "recommended_investigation" in row.keys() else "",
            source=row["source"] if "source" in row.keys() else "python_detection",
        )
