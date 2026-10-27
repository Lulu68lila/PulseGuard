"""Unit tests for the real-time filesystem watcher and debouncing."""

import time
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock

from pulseguard.core.models import QuarantineRecord, ScanResult, ScanStatus, ThreatInfo, ThreatSeverity
from pulseguard.watcher.fs_watcher import FileSystemWatcher, PulseGuardEventHandler


def test_event_handler_ignore_rules() -> None:
    handler = PulseGuardEventHandler()

    assert handler.should_ignore(Path("tempfile.tmp")) is True
    assert handler.should_ignore(Path("download.crdownload")) is True
    assert handler.should_ignore(Path("file.pgvault")) is True
    assert handler.should_ignore(Path("~document.docx")) is True
    assert handler.should_ignore(Path(".git/config")) is True
    assert handler.should_ignore(Path(".pulseguard_vault/catalog.json")) is True

    # Benign target files should not be ignored
    assert handler.should_ignore(Path("executable.exe")) is False
    assert handler.should_ignore(Path("script.ps1")) is False
    assert handler.should_ignore(Path("document.pdf")) is False


def test_event_handler_debounced_scan(tmp_path: Path) -> None:
    target_file = tmp_path / "test_debounced.txt"
    target_file.write_text("initial content", encoding="utf-8")

    mock_scanner = MagicMock()
    mock_scanner.return_value = ScanResult(
        file_path=target_file,
        status=ScanStatus.CLEAN,
        is_infected=False,
        file_hash="dummy_hash",
        timestamp=datetime.now(timezone.utc),
    )

    events_received = []

    def on_event(res: ScanResult, q_rec: any) -> None:
        events_received.append((res, q_rec))

    handler = PulseGuardEventHandler(
        debounce_seconds=0.1,
        auto_quarantine=False,
        scanner_fn=mock_scanner,
        on_event_callback=on_event,
    )

    # Schedule multiple rapid modifications
    event_mock = MagicMock()
    event_mock.is_directory = False
    event_mock.src_path = str(target_file)

    handler.on_modified(event_mock)
    handler.on_modified(event_mock)
    handler.on_modified(event_mock)

    # Sleep longer than debounce time (0.1s)
    time.sleep(0.3)

    # Should only scan once due to debouncing
    assert mock_scanner.call_count == 1
    assert len(events_received) == 1
    assert events_received[0][0].status == ScanStatus.CLEAN


def test_event_handler_auto_quarantine(tmp_path: Path) -> None:
    infected_file = tmp_path / "infected.bin"
    infected_file.write_bytes(b"bad content")

    mock_threat = ThreatInfo(
        threat_name="Trojan.Test",
        threat_type="signature",
        severity=ThreatSeverity.CRITICAL,
        rule_matched="rule_trojan",
        file_hash="fake_hash",
    )
    mock_scanner = MagicMock(
        return_value=ScanResult(
            file_path=infected_file,
            status=ScanStatus.INFECTED,
            is_infected=True,
            file_hash="fake_hash",
            timestamp=datetime.now(timezone.utc),
            threat=mock_threat,
        )
    )
    mock_quarantine = MagicMock(
        return_value=QuarantineRecord(
            record_id="rec-test-123",
            original_path=infected_file,
            vault_path=tmp_path / ".vault" / "rec-test-123.pgvault",
            quarantined_at=datetime.now(timezone.utc),
            threat=mock_threat,
            file_hash="fake_hash",
        )
    )

    events = []
    handler = PulseGuardEventHandler(
        debounce_seconds=0.05,
        auto_quarantine=True,
        scanner_fn=mock_scanner,
        quarantine_fn=mock_quarantine,
        on_event_callback=lambda res, q_rec: events.append((res, q_rec)),
    )

    event_mock = MagicMock()
    event_mock.is_directory = False
    event_mock.src_path = str(infected_file)

    handler.on_created(event_mock)
    time.sleep(0.2)

    assert mock_scanner.call_count == 1
    assert mock_quarantine.call_count == 1
    assert len(events) == 1
    assert events[0][1].record_id == "rec-test-123"


def test_filesystem_watcher_start_stop(tmp_path: Path) -> None:
    watcher = FileSystemWatcher(watch_paths=[tmp_path], debounce_seconds=0.1)
    assert watcher.is_running is False

    watcher.start()
    assert watcher.is_running is True

    # Calling start again when already running does nothing
    watcher.start()
    assert watcher.is_running is True

    watcher.stop()
    assert watcher.is_running is False
