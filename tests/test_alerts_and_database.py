from datetime import datetime, timedelta, timezone

import pytest

from backend.alerts import AlertManager
from backend.database import AlertNotFoundError, AlertRepository
from backend.detection import DetectionFinding
from backend.config import Settings


NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def finding(**overrides: object) -> DetectionFinding:
    values: dict[str, object] = {
        "timestamp": NOW,
        "detection_type": "PORT_SCAN",
        "severity": "MEDIUM",
        "source_ip": "10.0.0.10",
        "destination_ip": "10.0.0.20",
        "observed_value": 50,
        "threshold": 50,
        "evidence": "Test evidence",
    }
    values.update(overrides)
    return DetectionFinding(**values)  # type: ignore[arg-type]


def repository(tmp_path) -> AlertRepository:
    subject = AlertRepository(tmp_path / "alerts.db")
    subject.initialize()
    return subject


def test_manager_creates_complete_persistent_alert(tmp_path) -> None:
    store = repository(tmp_path)
    manager = AlertManager(store, Settings(alert_cooldown_seconds=10))

    alert = manager.create_from_finding(finding())

    assert alert is not None
    assert alert.id
    assert alert.evidence == "Test evidence"
    assert store.get_by_id(alert.id) == alert


def test_manager_deduplicates_then_allows_after_cooldown(tmp_path) -> None:
    manager = AlertManager(repository(tmp_path), Settings(alert_cooldown_seconds=10))

    first = manager.create_from_finding(finding())
    duplicate = manager.create_from_finding(finding(timestamp=NOW + timedelta(seconds=9)))
    later = manager.create_from_finding(finding(timestamp=NOW + timedelta(seconds=10)))

    assert first is not None
    assert duplicate is None
    assert later is not None


def test_repository_history_is_persistent_and_newest_first(tmp_path) -> None:
    path = tmp_path / "alerts.db"
    manager = AlertManager(repository(tmp_path), Settings(alert_cooldown_seconds=1))
    older = manager.create_from_finding(finding())
    newer = manager.create_from_finding(finding(timestamp=NOW + timedelta(seconds=2)))

    reopened = AlertRepository(path)
    reopened.initialize()

    assert [alert.id for alert in reopened.get_history()] == [newer.id, older.id]  # type: ignore[union-attr]


def test_missing_alert_has_a_clear_error(tmp_path) -> None:
    with pytest.raises(AlertNotFoundError):
        repository(tmp_path).get_by_id("does-not-exist")
