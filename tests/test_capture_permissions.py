from backend.capture.scapy_capture import ScapyPacketCapture


def test_windows_capture_returns_actionable_error_when_not_elevated(monkeypatch) -> None:
    capture = ScapyPacketCapture()
    monkeypatch.setattr("backend.capture.scapy_capture.platform.system", lambda: "Windows")
    monkeypatch.setattr(capture, "_is_elevated", lambda: False)

    status = capture.start(lambda packet: None, "Wi-Fi")

    assert status.running is False
    assert "Administrator" in (status.error or "")
