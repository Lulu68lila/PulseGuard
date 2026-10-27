"""Real-time filesystem event listener with debouncing and threat mitigation."""

import fnmatch
import logging
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from pulseguard.core.models import QuarantineRecord, ScanResult, ScanStatus
from pulseguard.engine.scanner import scan_file
from pulseguard.quarantine.manager import quarantine_file
from pulseguard.reporting.audit import get_audit_logger

logger = logging.getLogger(__name__)

DEFAULT_DEBOUNCE_SECONDS = 0.35
DEFAULT_IGNORED_EXTENSIONS: Set[str] = {
    ".tmp",
    ".temp",
    ".crdownload",
    ".part",
    ".swp",
    ".swo",
    ".pgvault",
}
DEFAULT_IGNORED_PATTERNS: List[str] = [
    "*~",
    "~*",
    "*.log",
    "*.lock",
    "*.pytest_cache*",
    "*/.git/*",
    "*\\.git\\*",
    "*/__pycache__/*",
    "*\\__pycache__\\*",
    "*/.pulseguard_vault/*",
    "*\\.pulseguard_vault\\*",
]


class PulseGuardEventHandler(FileSystemEventHandler):
    """Event handler that filters, debounces, and scans modified or created files."""

    def __init__(
        self,
        debounce_seconds: float = DEFAULT_DEBOUNCE_SECONDS,
        auto_quarantine: bool = False,
        ignored_extensions: Optional[Set[str]] = None,
        ignored_patterns: Optional[List[str]] = None,
        on_event_callback: Optional[Callable[[ScanResult, Optional[QuarantineRecord]], None]] = None,
        scanner_fn: Callable[[Path], ScanResult] = scan_file,
        quarantine_fn: Callable[[Path, Any], QuarantineRecord] = quarantine_file,
    ) -> None:
        super().__init__()
        self.debounce_seconds = debounce_seconds
        self.auto_quarantine = auto_quarantine
        self.ignored_extensions = ignored_extensions or set(DEFAULT_IGNORED_EXTENSIONS)
        self.ignored_patterns = ignored_patterns or list(DEFAULT_IGNORED_PATTERNS)
        self.on_event_callback = on_event_callback
        self.scanner_fn = scanner_fn
        self.quarantine_fn = quarantine_fn

        self._timers: Dict[Path, threading.Timer] = {}
        self._lock = threading.Lock()
        self._audit = get_audit_logger()

    def should_ignore(self, path: Path) -> bool:
        """Evaluate if the target path matches exclusion criteria."""
        path_str = str(path)
        name = path.name

        if any(part.startswith(".") and not part.startswith(".pg") for part in path.parts):
            return True

        if path.suffix.lower() in self.ignored_extensions:
            return True

        for pattern in self.ignored_patterns:
            if fnmatch.fnmatch(name, pattern) or fnmatch.fnmatch(path_str, pattern):
                return True

        return False

    def on_created(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._schedule_scan(Path(event.src_path))

    def on_modified(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._schedule_scan(Path(event.src_path))

    def _schedule_scan(self, path: Path) -> None:
        """Schedule a debounced scan invocation for the target path."""
        try:
            resolved_path = path.resolve()
        except Exception:
            resolved_path = path

        if self.should_ignore(resolved_path):
            return

        with self._lock:
            existing_timer = self._timers.get(resolved_path)
            if existing_timer is not None:
                existing_timer.cancel()

            timer = threading.Timer(
                self.debounce_seconds,
                self._execute_scan,
                args=(resolved_path,),
            )
            self._timers[resolved_path] = timer
            timer.daemon = True
            timer.start()

    def _execute_scan(self, path: Path) -> None:
        """Perform scan after debounce delay."""
        with self._lock:
            self._timers.pop(path, None)

        if not path.exists() or not path.is_file():
            return

        try:
            result = self.scanner_fn(path)
        except Exception as exc:
            logger.error("Error executing watcher scan on %s: %s", path, exc)
            return

        quarantine_record: Optional[QuarantineRecord] = None
        if result.is_infected and result.threat:
            self._audit.log_scan(
                file_path=result.file_path,
                status=result.status.value,
                file_hash=result.file_hash,
                threat_name=result.threat.threat_name,
                duration_ms=result.scan_duration_ms,
            )

            if self.auto_quarantine:
                try:
                    quarantine_record = self.quarantine_fn(result.file_path, result.threat)
                    self._audit.log_quarantine(
                        record_id=quarantine_record.record_id,
                        original_path=quarantine_record.original_path,
                        threat_name=result.threat.threat_name,
                        file_hash=quarantine_record.file_hash,
                    )
                except Exception as q_exc:
                    logger.error("Failed to auto-quarantine %s: %s", path, q_exc)
        else:
            self._audit.log_scan(
                file_path=result.file_path,
                status=result.status.value,
                file_hash=result.file_hash,
                duration_ms=result.scan_duration_ms,
            )

        if self.on_event_callback:
            try:
                self.on_event_callback(result, quarantine_record)
            except Exception as cb_exc:
                logger.error("Error in watcher event callback: %s", cb_exc)


class FileSystemWatcher:
    """Manages real-time directory observation using watchdog."""

    def __init__(
        self,
        watch_paths: List[Path],
        recursive: bool = True,
        auto_quarantine: bool = False,
        debounce_seconds: float = DEFAULT_DEBOUNCE_SECONDS,
        on_event_callback: Optional[Callable[[ScanResult, Optional[QuarantineRecord]], None]] = None,
    ) -> None:
        self.watch_paths = [Path(p).resolve() for p in watch_paths]
        self.recursive = recursive
        self.auto_quarantine = auto_quarantine
        self.debounce_seconds = debounce_seconds
        self.on_event_callback = on_event_callback

        self._handler = PulseGuardEventHandler(
            debounce_seconds=debounce_seconds,
            auto_quarantine=auto_quarantine,
            on_event_callback=on_event_callback,
        )
        self._observer: Optional[Observer] = None
        self._is_running = False
        self._lock = threading.Lock()

    @property
    def is_running(self) -> bool:
        return self._is_running

    def start(self) -> None:
        """Start directory observation threads."""
        with self._lock:
            if self._is_running:
                return

            self._observer = Observer()
            for path in self.watch_paths:
                if path.exists() and path.is_dir():
                    self._observer.schedule(self._handler, str(path), recursive=self.recursive)

            self._observer.start()
            self._is_running = True
            logger.info("PulseGuard FileSystemWatcher started on %s", self.watch_paths)

    def stop(self, timeout: float = 2.0) -> None:
        """Stop directory observation threads."""
        with self._lock:
            if not self._is_running or self._observer is None:
                return

            self._observer.stop()
            self._observer.join(timeout=timeout)
            self._is_running = False
            logger.info("PulseGuard FileSystemWatcher stopped")
