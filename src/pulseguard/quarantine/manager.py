"""PulseGuard Quarantine Manager Subsystem."""

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from pulseguard.core.models import QuarantineRecord, ThreatInfo, ThreatSeverity
from pulseguard.engine.signatures import compute_sha256
from pulseguard.quarantine.vault import QuarantineVault, VaultEncryptionError


class QuarantineError(Exception):
    """General exception for quarantine operations."""
    pass


class QuarantineManager:
    """Manages threat containment, catalog tracking, file restoration, and deletion."""

    def __init__(self, vault_dir: Optional[Path] = None) -> None:
        if vault_dir is None:
            # Default vault directory under local user profile
            local_appdata = Path.home() / ".pulseguard" / "vault"
            self.vault_dir = local_appdata
        else:
            self.vault_dir = Path(vault_dir)

        self.vault = QuarantineVault(self.vault_dir)
        self.catalog_file = self.vault_dir / "catalog.json"
        self._records: Dict[str, QuarantineRecord] = {}
        self._load_catalog()

    def _load_catalog(self) -> None:
        """Load catalog from disk if present. Preserves corrupted catalog files."""
        if not self.catalog_file.exists():
            return

        try:
            with open(self.catalog_file, "r", encoding="utf-8") as f:
                raw_data = json.load(f)

            for item in raw_data:
                threat_data = item["threat"]
                threat = ThreatInfo(
                    threat_name=threat_data["threat_name"],
                    threat_type=threat_data["threat_type"],
                    severity=ThreatSeverity(threat_data["severity"]),
                    rule_matched=threat_data["rule_matched"],
                    file_hash=threat_data["file_hash"],
                    details=threat_data.get("details"),
                )
                record = QuarantineRecord(
                    record_id=item["record_id"],
                    original_path=Path(item["original_path"]),
                    vault_path=Path(item["vault_path"]),
                    quarantined_at=datetime.fromisoformat(item["quarantined_at"]),
                    threat=threat,
                    file_hash=item["file_hash"],
                    is_restored=item.get("is_restored", False),
                )
                self._records[record.record_id] = record
        except Exception as exc:
            # Preserve corrupted catalog file to prevent data loss on subsequent saves
            backup_path = self.catalog_file.with_suffix(f".corrupt.{int(datetime.now().timestamp())}.json")
            try:
                self.catalog_file.replace(backup_path)
            except OSError:
                pass
            raise QuarantineError(
                f"Quarantine catalog was corrupted and backed up to '{backup_path.name}'. "
                f"Error details: {exc}"
            ) from exc

    def _save_catalog(self) -> None:
        """Persist catalog to disk."""
        serialized = []
        for r in self._records.values():
            serialized.append({
                "record_id": r.record_id,
                "original_path": str(r.original_path),
                "vault_path": str(r.vault_path),
                "quarantined_at": r.quarantined_at.isoformat(),
                "file_hash": r.file_hash,
                "is_restored": r.is_restored,
                "threat": {
                    "threat_name": r.threat.threat_name,
                    "threat_type": r.threat.threat_type,
                    "severity": r.threat.severity.value,
                    "rule_matched": r.threat.rule_matched,
                    "file_hash": r.threat.file_hash,
                    "details": r.threat.details,
                },
            })
        temp_file = self.catalog_file.with_suffix(".tmp")
        with open(temp_file, "w", encoding="utf-8") as f:
            json.dump(serialized, f, indent=2)
        temp_file.replace(self.catalog_file)

    def quarantine_file(self, file_path: Path, threat: ThreatInfo) -> QuarantineRecord:
        """Isolate and encrypt an infected file, removing it from its original path."""
        target = Path(file_path).resolve()
        if not target.exists() or not target.is_file():
            raise QuarantineError(f"Target file does not exist or is not a file: {target}")

        plain_bytes = target.read_bytes()
        # Compute hash directly from the in-memory payload being vaulted
        file_hash = compute_sha256_bytes(plain_bytes)

        record_id = uuid.uuid4().hex[:12]
        vault_path = self.vault.encrypt_and_store(record_id, plain_bytes)

        record = QuarantineRecord(
            record_id=record_id,
            original_path=target,
            vault_path=vault_path,
            quarantined_at=datetime.now(timezone.utc),
            threat=threat,
            file_hash=file_hash,
            is_restored=False,
        )

        # Register and persist in catalog BEFORE removing source file
        self._records[record_id] = record
        try:
            self._save_catalog()
        except Exception as exc:
            # Catalog write failed: shred encrypted vault copy and rollback
            del self._records[record_id]
            self.vault.secure_shred(vault_path)
            raise QuarantineError(f"Failed to persist quarantine catalog: {exc}") from exc

        # Once catalog persistence is confirmed, safely unlink original infected file
        try:
            target.unlink()
        except OSError as exc:
            # Unlinking failed: rollback catalog entry and vault file
            del self._records[record_id]
            try:
                self._save_catalog()
            except Exception:
                pass
            self.vault.secure_shred(vault_path)
            raise QuarantineError(f"Failed to remove original file from filesystem: {exc}") from exc

        return record

    def restore_file(self, record_id: str, destination: Optional[Path] = None) -> Path:
        """Decrypt and restore a quarantined file to original or custom destination."""
        record = self._records.get(record_id)
        if not record:
            raise QuarantineError(f"Quarantine record with ID '{record_id}' not found.")

        target_path = Path(destination) if destination else record.original_path
        target_path = target_path.resolve()

        plain_bytes = self.vault.decrypt_and_read(record_id, record.vault_path)

        # Integrity verification
        hasher = compute_sha256_bytes(plain_bytes)
        if hasher != record.file_hash:
            raise QuarantineError("Integrity check failed: decrypted file hash does not match original quarantined hash.")

        target_path.parent.mkdir(parents=True, exist_ok=True)
        with open(target_path, "wb") as f:
            f.write(plain_bytes)

        record.is_restored = True
        self._save_catalog()
        return target_path

    def delete_quarantine(self, record_id: str) -> bool:
        """Permanently shred and delete a quarantined file and remove it from catalog."""
        record = self._records.get(record_id)
        if not record:
            return False

        shredded = self.vault.secure_shred(record.vault_path)
        del self._records[record_id]
        self._save_catalog()
        return shredded

    def list_quarantine(self, include_restored: bool = False) -> List[QuarantineRecord]:
        """List all quarantined files in the catalog."""
        if include_restored:
            return list(self._records.values())
        return [r for r in self._records.values() if not r.is_restored]


def compute_sha256_bytes(data: bytes) -> str:
    """Compute SHA-256 hex digest of in-memory bytes."""
    import hashlib
    return hashlib.sha256(data).hexdigest().lower()


# Module-level convenience functions using default manager
_default_manager: Optional[QuarantineManager] = None


def get_default_manager() -> QuarantineManager:
    global _default_manager
    if _default_manager is None:
        _default_manager = QuarantineManager()
    return _default_manager


def quarantine_file(file_path: Path, threat: ThreatInfo) -> QuarantineRecord:
    return get_default_manager().quarantine_file(file_path, threat)


def restore_file(record_id: str, destination: Optional[Path] = None) -> Path:
    return get_default_manager().restore_file(record_id, destination)


def delete_quarantine(record_id: str) -> bool:
    return get_default_manager().delete_quarantine(record_id)


def list_quarantine() -> List[QuarantineRecord]:
    return get_default_manager().list_quarantine()
