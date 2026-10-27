"""Unit tests for QuarantineVault encryption and isolation."""

import pytest
from pathlib import Path

from pulseguard.quarantine.vault import QuarantineVault, VaultEncryptionError


def test_vault_encrypt_and_decrypt(tmp_path: Path):
    vault = QuarantineVault(vault_dir=tmp_path / "vault")
    original_data = b"MALWARE_PAYLOAD_BINARY_CONTENT_FOR_ISOLATION_TEST"
    record_id = "rec_test_001"

    # Encrypt and store
    vault_file = vault.encrypt_and_store(record_id, original_data)
    assert vault_file.exists()
    assert vault_file.suffix == ".pgvault"

    # Verify encrypted data is NOT plain text
    encrypted_bytes = vault_file.read_bytes()
    assert original_data not in encrypted_bytes

    # Decrypt and verify round-trip integrity
    decrypted_data = vault.decrypt_and_read(record_id, vault_file)
    assert decrypted_data == original_data


def test_vault_tamper_detection(tmp_path: Path):
    vault = QuarantineVault(vault_dir=tmp_path / "vault")
    record_id = "rec_tamper_001"
    vault_file = vault.encrypt_and_store(record_id, b"sensitive data")

    # Corrupt a byte in the ciphertext
    raw = bytearray(vault_file.read_bytes())
    raw[-1] ^= 0xFF
    vault_file.write_bytes(bytes(raw))

    # Expect authentication tag verification to fail
    with pytest.raises(VaultEncryptionError):
        vault.decrypt_and_read(record_id, vault_file)


def test_vault_secure_shred(tmp_path: Path):
    vault = QuarantineVault(vault_dir=tmp_path / "vault")
    record_id = "rec_shred_001"
    vault_file = vault.encrypt_and_store(record_id, b"data to shred")
    assert vault_file.exists()

    shredded = vault.secure_shred(vault_file)
    assert shredded is True
    assert not vault_file.exists()
