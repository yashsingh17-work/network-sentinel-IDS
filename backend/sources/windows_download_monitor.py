"""Read-only, local-first observation of files arriving in Windows Downloads folders."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock

from backend.config import Settings


RISKY_EXTENSIONS = {".bat", ".cmd", ".com", ".dll", ".exe", ".hta", ".iso", ".js", ".jse", ".lnk", ".msi", ".msix", ".ps1", ".scr", ".vbe", ".vbs"}
SIGNED_EXTENSIONS = {".cat", ".dll", ".exe", ".msi", ".msix", ".ps1", ".sys"}


@dataclass(frozen=True, slots=True)
class DownloadObservation:
    path: str
    filename: str
    extension: str
    size_bytes: int
    modified_at_ns: int
    sha256: str | None
    hash_status: str
    mark_of_the_web: bool | None
    signature_status: str
    publisher: str | None
    risky_file_type: bool


@dataclass(frozen=True, slots=True)
class DownloadMonitorStatus:
    enabled: bool
    initialized: bool
    directories: list[str]
    tracked_files: int
    last_scan_at: str | None


class WindowsDownloadMonitor:
    """Poll configured folders without reading document contents or executing files."""

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or Settings.from_env()
        self._seen: dict[str, tuple[int, int]] = {}
        self._lock = RLock()
        self._initialized = False
        self._last_scan_at: str | None = None

    def scan(self, include_known: bool = False) -> list[DownloadObservation]:
        """Return new/changed files, or audit all current files when explicitly asked."""
        if not self._settings.download_monitor_enabled or platform.system() != "Windows":
            return []
        candidates: list[Path] = []
        for directory in self._settings.download_directories:
            folder = Path(directory).expanduser()
            try:
                candidates.extend(path for path in folder.iterdir() if path.is_file())
            except OSError:
                continue
        try:
            candidates.sort(key=lambda path: path.stat().st_mtime_ns, reverse=True)
        except OSError:
            candidates = []
        observations: list[DownloadObservation] = []
        with self._lock:
            initial = not self._initialized
            for path in candidates[: self._settings.download_max_files]:
                try:
                    stat = path.stat()
                except OSError:
                    continue
                fingerprint = (stat.st_mtime_ns, stat.st_size)
                key = str(path.resolve()).lower()
                known = self._seen.get(key) == fingerprint
                if known and not include_known:
                    continue
                self._seen[key] = fingerprint
                if not initial or include_known:
                    observations.append(self._observe(path, stat.st_size, stat.st_mtime_ns))
            active = {str(path.resolve()).lower() for path in candidates[: self._settings.download_max_files] if path.exists()}
            self._seen = {key: value for key, value in self._seen.items() if key in active}
            self._initialized = True
            self._last_scan_at = datetime.now(timezone.utc).isoformat()
        return observations

    def status(self) -> DownloadMonitorStatus:
        with self._lock:
            return DownloadMonitorStatus(
                enabled=self._settings.download_monitor_enabled and platform.system() == "Windows",
                initialized=self._initialized,
                directories=list(self._settings.download_directories), tracked_files=len(self._seen),
                last_scan_at=self._last_scan_at,
            )

    def _observe(self, path: Path, size_bytes: int, modified_at_ns: int) -> DownloadObservation:
        extension = path.suffix.lower()
        sha256, hash_status = self._sha256(path, size_bytes)
        signature_status, publisher = self._signature(path, extension)
        return DownloadObservation(
            path=str(path), filename=path.name, extension=extension or "(no extension)", size_bytes=size_bytes,
            modified_at_ns=modified_at_ns, sha256=sha256, hash_status=hash_status,
            mark_of_the_web=self._mark_of_the_web(path), signature_status=signature_status,
            publisher=publisher, risky_file_type=extension in RISKY_EXTENSIONS,
        )

    def _sha256(self, path: Path, size_bytes: int) -> tuple[str | None, str]:
        if size_bytes > self._settings.download_hash_max_bytes:
            return None, "Skipped: file exceeds local hashing limit"
        digest = hashlib.sha256()
        try:
            with path.open("rb") as handle:
                for block in iter(lambda: handle.read(1_048_576), b""):
                    digest.update(block)
            return digest.hexdigest(), "SHA-256 calculated locally"
        except OSError as exc:
            return None, f"Hash unavailable: {exc.__class__.__name__}"

    @staticmethod
    def _mark_of_the_web(path: Path) -> bool | None:
        try:
            with open(f"{path}:Zone.Identifier", encoding="utf-8", errors="replace") as handle:
                contents = handle.read()
                return "ZoneId=3" in contents or "ZoneId=4" in contents
        except OSError:
            return False

    @staticmethod
    def _signature(path: Path, extension: str) -> tuple[str, str | None]:
        if extension not in SIGNED_EXTENSIONS:
            return "Not applicable", None
        if platform.system() != "Windows":
            return "Unavailable outside Windows", None
        command = (
            "$signature = Get-AuthenticodeSignature -LiteralPath $env:NETWORK_SENTINEL_DOWNLOAD_FILE; "
            "[pscustomobject]@{Status=[string]$signature.Status;Publisher=[string]$signature.SignerCertificate.Subject} | ConvertTo-Json -Compress"
        )
        try:
            environment = {**os.environ, "NETWORK_SENTINEL_DOWNLOAD_FILE": str(path)}
            output = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", command], capture_output=True,
                text=True, timeout=10, check=False, env=environment,
            ).stdout.strip()
            payload = json.loads(output) if output else {}
            return str(payload.get("Status") or "Unknown"), str(payload.get("Publisher") or "") or None
        except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
            return "Unavailable", None
