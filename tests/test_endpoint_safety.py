from pathlib import Path

from backend.config import Settings
from backend.sources import WindowsDownloadMonitor


def test_download_monitor_baselines_then_observes_new_file(tmp_path: Path) -> None:
    monitor = WindowsDownloadMonitor(
        Settings(download_directories=(str(tmp_path),), download_max_files=20, download_hash_max_bytes=1_000_000)
    )
    (tmp_path / "older.txt").write_text("already there", encoding="utf-8")

    assert monitor.scan() == []
    (tmp_path / "new-file.exe").write_bytes(b"not executable content")
    observations = monitor.scan()

    assert len(observations) == 1
    assert observations[0].filename == "new-file.exe"
    assert observations[0].risky_file_type is True
    assert observations[0].sha256 is not None
    assert monitor.status().initialized is True


def test_download_monitor_audit_includes_existing_files(tmp_path: Path) -> None:
    monitor = WindowsDownloadMonitor(Settings(download_directories=(str(tmp_path),), download_max_files=20))
    (tmp_path / "existing.txt").write_text("inspect me", encoding="utf-8")

    observations = monitor.scan(include_known=True)

    assert [item.filename for item in observations] == ["existing.txt"]
