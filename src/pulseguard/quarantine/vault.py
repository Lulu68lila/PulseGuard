"""PulseGuard Secure Quarantine Vault Encryption Subsystem."""

import os
import secrets
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class VaultEncryptionError(Exception):
    """Raised when encryption or decryption fails inside the quarantine vault."""
    pass


class QuarantineVault:
    """Secure encrypted storage for isolated threats.

    Each quarantined file is encrypted using AES-256-GCM with a unique 96-bit nonce
    and stored with the extension `.pgvault` to prevent accidental execution.
    """

    def __init__(self, vault_dir: Path, key: Optional[bytes] = None) -> None:
        self.vault_dir = Path(vault_dir)
        self.vault_dir.mkdir(parents=True, exist_ok=True)
        self.key_file = self.vault_dir / ".vault.key"

        if key is not None:
            self._key = key
        else:
            self._key = self._load_or_create_key()

        self._aesgcm = AESGCM(self._key)

    def _load_or_create_key(self) -> bytes:
        """Load the 256-bit AES master key or generate a cryptographically secure key."""
        if self.key_file.exists():
            key = self.key_file.read_bytes()
            if len(key) == 32:
                return key

        # Generate fresh 256-bit key (32 bytes)
        new_key = secrets.token_bytes(32)
        # Write key and restrict permissions
        self.key_file.write_bytes(new_key)
        try:
            os.chmod(self.key_file, 0o600)
        except (AttributeError, OSError):
            pass
        return new_key

    def encrypt_and_store(self, record_id: str, plain_bytes: bytes) -> Path:
        """Encrypt plain file bytes and store in vault.

        Storage format: [12 bytes nonce] + [ciphertext + 16 bytes auth tag]
        """
        nonce = secrets.token_bytes(12)
        try:
            ciphertext = self._aesgcm.encrypt(nonce, plain_bytes, associated_data=record_id.encode("utf-8"))
        except Exception as exc:
            raise VaultEncryptionError(f"Failed to encrypt file for vault: {exc}") from exc

        vault_file_path = self.vault_dir / f"{record_id}.pgvault"
        with open(vault_file_path, "wb") as f:
            f.write(nonce + ciphertext)

        try:
            os.chmod(vault_file_path, 0o600)
        except (AttributeError, OSError):
            pass

        return vault_file_path

    def decrypt_and_read(self, record_id: str, vault_file_path: Path) -> bytes:
        """Decrypt a quarantined payload back to its original plain bytes."""
        target_path = Path(vault_file_path)
        if not target_path.exists():
            raise VaultEncryptionError(f"Quarantine vault file not found: {target_path}")

        encrypted_data = target_path.read_bytes()
        if len(encrypted_data) < 28:  # 12 bytes nonce + 16 bytes auth tag
            raise VaultEncryptionError("Quarantine vault file is corrupted or truncated.")

        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]

        try:
            plain_bytes = self._aesgcm.decrypt(nonce, ciphertext, associated_data=record_id.encode("utf-8"))
            return plain_bytes
        except Exception as exc:
            raise VaultEncryptionError(f"Failed to decrypt vault file (authentication tag mismatch or corrupted data): {exc}") from exc

    def secure_shred(self, vault_file_path: Path) -> bool:
        """Securely overwrite vault file contents with random data before unlinking."""
        target_path = Path(vault_file_path)
        if not target_path.exists():
            return False

        try:
            file_size = target_path.stat().st_size
            # Overwrite with random bytes
            with open(target_path, "wb") as f:
                f.write(secrets.token_bytes(file_size))
                f.flush()
                os.fsync(f.fileno())

            # Overwrite with zeros
            with open(target_path, "wb") as f:
                f.write(b"\x00" * file_size)
                f.flush()
                os.fsync(f.fileno())

            target_path.unlink()
            return True
        except OSError:
            if target_path.exists():
                try:
                    target_path.unlink()
                    return True
                except OSError:
                    return False
            return True
