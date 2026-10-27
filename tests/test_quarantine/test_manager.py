"""Unit tests for QuarantineManager workflow."""

import pytest
from pathlib import Path

from pulseguard.core.models import ThreatInfo, ThreatSeverity
from pulseguard.quarantine.manager import QuarantineError, QuarantineManager


def test_quarantine_round_trip_workflow(tmp_path: Path):
    vault_dir = tmp_path / "vault"
    manager = QuarantineManager(vault_dir=vault_dir)

    # 1. Create a dummy infected file in user space
    infected_file = tmp_path / "work" / "suspicious.exe"
    infected_file.parent.mkdir(parents=True, exist_ok=True)
    payload = b"MZ\x90\x00MALICIOUS_SIMULATION_BYTES_FOR_QUARANTINE"
    infected_file.write_bytes(payload)

    threat = ThreatInfo(
        threat_name="Trojan.PulseGuard.TestExecutable",
        threat_type="trojan",
        severity=ThreatSeverity.CRITICAL,
        rule_matched="SIG_TEST_001",
        file_hash="",
    )

    # 2. Quarantine the file
    record = manager.quarantine_file(infected_file, threat)

    assert record is not None
    assert record.is_restored is False
    # Original file must no longer exist at original path
    assert not infected_file.exists()
    # Encrypted vault file must exist
    assert record.vault_path.exists()

    # 3. List quarantined records
    active = manager.list_quarantine()
    assert len(active) == 1
    assert active[0].record_id == record.record_id

    # 4. Restore the file to original path
    restored_path = manager.restore_file(record.record_id)
    assert restored_path.exists()
    assert restored_path.read_bytes() == payload

    # Active list should now be empty (since file was restored)
    assert len(manager.list_quarantine(include_restored=False)) == 0

    # 5. Restore to custom destination
    custom_dest = tmp_path / "sandbox" / "recovered.bin"
    manager.restore_file(record.record_id, destination=custom_dest)
    assert custom_dest.exists()
    assert custom_dest.read_bytes() == payload

    # 6. Delete quarantine record permanently
    deleted = manager.delete_quarantine(record.record_id)
    assert deleted is True
    assert not record.vault_path.exists()
    assert len(manager.list_quarantine(include_restored=True)) == 0


def test_quarantine_nonexistent_file(tmp_path: Path):
    manager = QuarantineManager(vault_dir=tmp_path / "vault")
    threat = ThreatInfo(
        threat_name="Test",
        threat_type="test",
        severity=ThreatSeverity.LOW,
        rule_matched="TEST",
        file_hash="",
    )
    with pytest.raises(QuarantineError):
        manager.quarantine_file(tmp_path / "ghost.txt", threat)
