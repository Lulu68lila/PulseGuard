"""Unit tests for reporting, audit logging, and formatters."""

import json
from datetime import datetime, timezone
from pathlib import Path

from pulseguard.core.models import QuarantineRecord, ScanResult, ScanStatus, ThreatInfo, ThreatSeverity
from pulseguard.reporting.audit import AuditLogger
from pulseguard.reporting.formatter import (
    format_quarantine_table,
    format_scan_result_row,
    format_scan_summary_table,
    format_status_panel,
    scan_results_to_json,
)


def test_audit_logger_records_events(tmp_path: Path) -> None:
    log_file = tmp_path / "test_audit.log"
    logger = AuditLogger(log_path=log_file)

    event = logger.log_event("TEST_EVENT", "Test message", details={"key": "value"})
    assert event["event_type"] == "TEST_EVENT"
    assert event["message"] == "Test message"
    assert event["details"]["key"] == "value"

    assert log_file.exists()
    content = log_file.read_text(encoding="utf-8")
    assert "TEST_EVENT" in content
    assert "Test message" in content


def test_audit_logger_convenience_methods(tmp_path: Path) -> None:
    log_file = tmp_path / "test_audit2.log"
    logger = AuditLogger(log_path=log_file)

    s_res = logger.log_scan(
        file_path=Path("sample.exe"),
        status="INFECTED",
        file_hash="abcd1234ef",
        threat_name="EICAR-Test",
        duration_ms=12.5,
    )
    assert s_res["event_type"] == "SCAN_RESULT"
    assert s_res["details"]["threat_name"] == "EICAR-Test"

    q_res = logger.log_quarantine(
        record_id="rec-001",
        original_path=Path("sample.exe"),
        threat_name="EICAR-Test",
        file_hash="abcd1234ef",
    )
    assert q_res["event_type"] == "QUARANTINE_ISOLATE"

    r_res = logger.log_restore("rec-001", Path("restored.exe"))
    assert r_res["event_type"] == "QUARANTINE_RESTORE"

    d_res = logger.log_delete("rec-001")
    assert d_res["event_type"] == "QUARANTINE_DELETE"


def test_format_scan_result_row_and_summary_table() -> None:
    clean_res = ScanResult(
        file_path=Path("clean.txt"),
        status=ScanStatus.CLEAN,
        is_infected=False,
        file_hash="aaaabbbbcccc",
        timestamp=datetime.now(timezone.utc),
        scan_duration_ms=5.0,
    )
    infected_res = ScanResult(
        file_path=Path("virus.exe"),
        status=ScanStatus.INFECTED,
        is_infected=True,
        file_hash="111122223333",
        timestamp=datetime.now(timezone.utc),
        threat=ThreatInfo(
            threat_name="Trojan.Generic",
            threat_type="signature",
            severity=ThreatSeverity.CRITICAL,
            rule_matched="rule_trojan",
            file_hash="111122223333",
        ),
        scan_duration_ms=15.0,
    )

    clean_row = format_scan_result_row(clean_res)
    assert "clean.txt" in clean_row[0]
    assert "CLEAN" in clean_row[1]

    infected_row = format_scan_result_row(infected_res)
    assert "virus.exe" in infected_row[0]
    assert "INFECTED" in infected_row[1]
    assert "Trojan.Generic" in infected_row[2]

    table = format_scan_summary_table([clean_res, infected_res])
    assert table.row_count == 2


def test_format_quarantine_table_and_status_panel() -> None:
    rec = QuarantineRecord(
        record_id="rec-12345678",
        original_path=Path("malware.bin"),
        vault_path=Path(".vault/rec-12345678.pgvault"),
        quarantined_at=datetime.now(timezone.utc),
        threat=ThreatInfo(
            threat_name="Malware.Payload",
            threat_type="heuristic",
            severity=ThreatSeverity.HIGH,
            rule_matched="entropy_rule",
            file_hash="hash123",
        ),
        file_hash="hash123",
        is_restored=False,
    )

    q_table = format_quarantine_table([rec])
    assert q_table.row_count == 1

    panel = format_status_panel(
        active_signatures=42,
        quarantine_count=1,
        vault_path=Path("C:/vault"),
        is_watcher_running=True,
    )
    assert "Signatures Loaded" in panel.renderable


def test_scan_results_to_json() -> None:
    res = ScanResult(
        file_path=Path("doc.pdf"),
        status=ScanStatus.CLEAN,
        is_infected=False,
        file_hash="hash_pdf",
        timestamp=datetime.now(timezone.utc),
        scan_duration_ms=8.2,
    )
    json_str = scan_results_to_json([res])
    data = json.loads(json_str)
    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]["file_path"] == "doc.pdf"
    assert data[0]["status"] == "CLEAN"
