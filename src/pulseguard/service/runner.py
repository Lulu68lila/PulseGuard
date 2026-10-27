"""Daemon and background service runner for continuous endpoint protection."""

import logging
import signal
import threading
import time
from pathlib import Path
from types import FrameType
from typing import Callable, List, Optional

from pulseguard.core.models import QuarantineRecord, ScanResult
from pulseguard.reporting.audit import get_audit_logger
from pulseguard.watcher.fs_watcher import FileSystemWatcher

logger = logging.getLogger(__name__)


class PulseGuardService:
    """Manages continuous background antivirus protection daemon."""

    def __init__(
        self,
        watch_paths: List[Path],
        auto_quarantine: bool = True,
        on_event_callback: Optional[Callable[[ScanResult, Optional[QuarantineRecord]], None]] = None,
        poll_interval_seconds: float = 0.5,
    ) -> None:
        self.watch_paths = [Path(p) for p in watch_paths]
        self.auto_quarantine = auto_quarantine
        self.poll_interval = poll_interval_seconds
        self.on_event_callback = on_event_callback

        self._watcher = FileSystemWatcher(
            watch_paths=self.watch_paths,
            auto_quarantine=self.auto_quarantine,
            on_event_callback=self.on_event_callback,
        )
        self._stop_event = threading.Event()
        self._audit = get_audit_logger()
        self._registered_signals = False

    @property
    def is_running(self) -> bool:
        return not self._stop_event.is_set() and self._watcher.is_running

    def _handle_signal(self, signum: int, frame: Optional[FrameType]) -> None:
        """Handle termination signals gracefully."""
        sig_name = signal.Signals(signum).name if hasattr(signal, "Signals") else str(signum)
        logger.info("Received termination signal %s, initiating shutdown...", sig_name)
        self.stop()

    def register_signal_handlers(self) -> None:
        """Register OS signal handlers for graceful shutdown."""
        if threading.current_thread() is threading.main_thread():
            try:
                signal.signal(signal.SIGINT, self._handle_signal)
                if hasattr(signal, "SIGTERM"):
                    signal.signal(signal.SIGTERM, self._handle_signal)
                if hasattr(signal, "SIGBREAK"):
                    signal.signal(signal.SIGBREAK, self._handle_signal)
                self._registered_signals = True
            except (ValueError, AttributeError) as exc:
                logger.warning("Could not register signal handlers: %s", exc)

    def start(self, block: bool = True) -> None:
        """Start the background protection service."""
        self._stop_event.clear()
        self._audit.log_event(
            "SERVICE_START",
            f"PulseGuard service started watching {len(self.watch_paths)} directories",
            details={"watch_paths": [str(p) for p in self.watch_paths], "auto_quarantine": self.auto_quarantine},
        )

        self._watcher.start()

        if block:
            self.register_signal_handlers()
            logger.info("PulseGuard service running. Press Ctrl+C to stop.")
            try:
                while not self._stop_event.is_set():
                    time.sleep(self.poll_interval)
            except KeyboardInterrupt:
                logger.info("Keyboard interrupt caught in service loop.")
            finally:
                self.stop()

    def stop(self) -> None:
        """Stop the service and release resources."""
        if self._stop_event.is_set():
            return

        self._stop_event.set()
        self._watcher.stop()
        self._audit.log_event(
            "SERVICE_STOP",
            "PulseGuard service stopped cleanly",
        )
        logger.info("PulseGuard service shutdown complete.")
