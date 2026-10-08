"""Adapters that translate external telemetry into ``SecurityEvent`` objects."""

from backend.sources.normalizers import SuricataNormalizer, WindowsEventNormalizer, ZeekNormalizer
from backend.sources.windows_event_reader import WindowsEventReadError, WindowsSecurityEventReader
from backend.sources.windows_download_monitor import DownloadMonitorStatus, DownloadObservation, WindowsDownloadMonitor

__all__ = ["DownloadMonitorStatus", "DownloadObservation", "SuricataNormalizer", "WindowsDownloadMonitor", "WindowsEventNormalizer", "WindowsEventReadError", "WindowsSecurityEventReader", "ZeekNormalizer"]
