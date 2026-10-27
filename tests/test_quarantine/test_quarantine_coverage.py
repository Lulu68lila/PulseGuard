"""Targeted coverage tests for Quarantine Manager and Vault."""

import pytest
from pathlib import Path

from pulseguard.core.models import ThreatInfo, ThreatSeverity
from pulseguard.quarantine.manager import (
    QuarantineManager,
    delete_quarantine,
    list_quarantine,
    quarantine_file,
    restore_file,
)
from pulseguard.quarantine.vault import QuarantineVault, VaultEncryptionError


def test_vault_key_persistence(tmp_path: Path):
    vault_dir = tmp_path / "vault"
    vault1 = QuarantineVault(vault_dir=vault_dir)
    key1 = vault1._key

    # Reopening vault should load existing key
    vault2 = QuarantineVault(vault_dir=vault_dir)
    assert vault2._key == key1


def test_vault_short_file_error(tmp_path: Path):
    vault = QuarantineVault(vault_dir=tmp_path / "vault")
    short_file = tmp_path / "vault" / "corrupt.pgvault"
    short_file.write_bytes(b"too_short")

    with pytest.raises(VaultEncryptionError, match="corrupted or truncated"):
        vault.decrypt_and_read("some_id", short_file)


def test_vault_missing_file_error(tmp_path: Path):
    vault = QuarantineVault(vault_dir=tmp_path / "vault")
    with pytest.raises(VaultEncryptionError, match="not found"):
        vault.decrypt_and_read("some_id", tmp_path / "vault" / "nonexistent.pgvault")


def test_manager_catalog_reload(tmp_path: Path):
    vault_dir = tmp_path / "vault"
    manager1 = QuarantineManager(vault_dir=vault_dir)

    target = tmp_path / "threat.bin"
    target.write_bytes(b"VIRUS_CONTENT")

    threat = ThreatInfo(
        threat_name="Test.ReloadThreat",
        threat_type="test",
        severity=ThreatSeverity.MEDIUM,
        rule_matched="RULE_RELOAD",
        file_hash="hash_reload",
    )
    record = manager1.quarantine_file(target, threat)

    # Instantiate manager2 on same vault directory to test catalog reload
    manager2 = QuarantineManager(vault_dir=vault_dir)
    records = manager2.list_quarantine()
    assert len(records) == 1
    assert records[0].record_id == record.record_id
    assert records[0].threat.threat_name == "Test.ReloadThreat"


def test_quarantine_module_level_helpers(tmp_path: Path):
    target = tmp_path / "dummy_threat.txt"
    target.write_bytes(b"PAYLOAD_HELPER_TEST")

    threat = ThreatInfo(
        threat_name="Test.HelperThreat",
        threat_type="test",
        severity=ThreatSeverity.LOW,
        rule_matched="RULE_HELPER",
        file_hash="hash_helper",
    )

    rec = quarantine_file(target, threat)
    assert not target.exists()

    all_q = list_quarantine()
    assert any(r.record_id == rec.record_id for r in all_q)

    restored = restore_file(rec.record_id)
    assert restored.exists()
    assert restored.read_bytes() == b"PAYLOAD_HELPER_TEST"

    deleted = delete_quarantine(rec.record_id)
    assert deleted is True


def test_manager_corrupted_catalog_preservation(tmp_path: Path):
    vault_dir = tmp_path / "vault"
    vault_dir.mkdir(parents=True, exist_ok=True)
    catalog = vault_dir / "catalog.json"
    catalog.write_text("{invalid_json_content", encoding="utf-8")

    from pulseguard.quarantine.manager import QuarantineError
    with pytest.raises(QuarantineError, match="corrupted and backed up"):
        QuarantineManager(vault_dir=vault_dir)

    # Verify backup file was created
    backups = list(vault_dir.glob("*.corrupt.*.json"))
    assert len(backups) == 1
