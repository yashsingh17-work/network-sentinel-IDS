"""Optional, read-only Windows authentication event importer."""

from __future__ import annotations

from dataclasses import dataclass

from backend.alerts import Alert
from backend.services.event_ingestion_service import EventIngestionService
from backend.sources import WindowsEventNormalizer, WindowsSecurityEventReader


@dataclass(frozen=True, slots=True)
class WindowsImportResult:
    events_imported: int
    alerts: list[Alert]


class WindowsImportService:
    def __init__(self, reader: WindowsSecurityEventReader, normalizer: WindowsEventNormalizer, ingestion: EventIngestionService) -> None:
        self._reader = reader
        self._normalizer = normalizer
        self._ingestion = ingestion

    def import_recent(self, limit: int = 100) -> WindowsImportResult:
        alerts: list[Alert] = []
        records = self._reader.read_recent_authentication_events(limit)
        for record in records:
            result = self._ingestion.ingest(self._normalizer.normalize(record))
            alerts.extend(result.alerts)
        return WindowsImportResult(events_imported=len(records), alerts=alerts)
