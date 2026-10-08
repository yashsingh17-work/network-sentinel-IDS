"""Small user-managed labels for devices that passive traffic cannot identify."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class DeviceProfile:
    mac_address: str
    display_name: str | None
    physical_location: str | None


class DeviceProfileRepository:
    def __init__(self, database_path: str | Path) -> None:
        self._database_path = str(database_path)

    def initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS device_profiles (
                    mac_address TEXT PRIMARY KEY,
                    display_name TEXT,
                    physical_location TEXT
                )
                """
            )

    def upsert(self, mac_address: str, display_name: str | None, physical_location: str | None) -> DeviceProfile:
        normalized = mac_address.lower()
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO device_profiles (mac_address, display_name, physical_location)
                VALUES (?, ?, ?)
                ON CONFLICT(mac_address) DO UPDATE SET
                    display_name = excluded.display_name,
                    physical_location = excluded.physical_location
                """,
                (normalized, display_name, physical_location),
            )
        return DeviceProfile(normalized, display_name, physical_location)

    def profiles(self) -> dict[str, DeviceProfile]:
        with self._connect() as connection:
            rows = connection.execute("SELECT mac_address, display_name, physical_location FROM device_profiles").fetchall()
        return {
            row["mac_address"]: DeviceProfile(row["mac_address"], row["display_name"], row["physical_location"])
            for row in rows
        }

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._database_path)
        connection.row_factory = sqlite3.Row
        return connection
