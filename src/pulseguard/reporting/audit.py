"""Audit logging subsystem for PulseGuard operations."""

import json
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

DEFAULT_LOG_PATH = Path("pulseguard.log")


class AuditLogger:
    """Thread-safe structured audit logger for antivirus events."""

    def __init__(self, log_path: Path = DEFAULT_LOG_PATH) -> None:
        self.log_path = Path(log_path)
        self._lock = threading.Lock()
        self._logger = logging.getLogger(f"pulseguard.audit.{id(self)}")
        self._logger.setLevel(logging.INFO)
        self._logger.propagate = False

        if not self._logger.handlers:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            handler = logging.FileHandler(self.log_path, encoding="utf-8")
            formatter = logging.Formatter(
                "%(asctime)s [%(levelname)s] [Event:%(event_type)s] %(message)s"
            )
            handler.setFormatter(formatter)
            self._logger.addHandler(handler)

    def log_event(
        self,
        event_type: str,
        message: str,
        level: int = logging.INFO,
        details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Record an audit event to the log file and return the structured record."""
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "message": message,
            "details": details or {},
        }

        with self._lock:
            self._logger.log(
                level,
                message,
                extra={
                    "event_type": event_type,
                    "payload_json": json.dumps(record, default=str),
                },
            )

        return record

    def log_scan(
        self,
        file_path: Path,
        status: str,
        file_hash: str,
        threat_name: Optional[str] = None,
        duration_ms: float = 0.0,
    ) -> Dict[str, Any]:
        """Record a scan result event."""
        details = {
            "file_path": str(file_path),
            "status": status,
            "file_hash": file_hash,
            "threat_name": threat_name,
            "duration_ms": duration_ms,
        }
        level = logging.WARNING if status == "INFECTED" else logging.INFO
        msg = f"Scanned {file_path} -> {status}"
        if threat_name:
            msg += f" (Threat: {threat_name})"
        return self.log_event("SCAN_RESULT", msg, level=level, details=details)

    def log_quarantine(
        self,
        record_id: str,
        original_path: Path,
        threat_name: str,
        file_hash: str,
    ) -> Dict[str, Any]:
        """Record a file quarantine event."""
        details = {
            "record_id": record_id,
            "original_path": str(original_path),
            "threat_name": threat_name,
            "file_hash": file_hash,
        }
        return self.log_event(
            "QUARANTINE_ISOLATE",
            f"File isolated to vault: {original_path} (ID: {record_id})",
            level=logging.WARNING,
            details=details,
        )

    def log_restore(self, record_id: str, destination_path: Path) -> Dict[str, Any]:
        """Record a file restoration event."""
        details = {
            "record_id": record_id,
            "destination_path": str(destination_path),
        }
        return self.log_event(
            "QUARANTINE_RESTORE",
            f"Restored file {record_id} to {destination_path}",
            level=logging.INFO,
            details=details,
        )

    def log_delete(self, record_id: str) -> Dict[str, Any]:
        """Record a permanent shredding/deletion event."""
        details = {"record_id": record_id}
        return self.log_event(
            "QUARANTINE_DELETE",
            f"Permanently destroyed quarantine record: {record_id}",
            level=logging.INFO,
            details=details,
        )


_DEFAULT_AUDIT_LOGGER: Optional[AuditLogger] = None


def get_audit_logger(log_path: Optional[Path] = None) -> AuditLogger:
    """Retrieve or initialize the global audit logger singleton."""
    global _DEFAULT_AUDIT_LOGGER
    if _DEFAULT_AUDIT_LOGGER is None or log_path is not None:
        _DEFAULT_AUDIT_LOGGER = AuditLogger(log_path=log_path or DEFAULT_LOG_PATH)
    return _DEFAULT_AUDIT_LOGGER
