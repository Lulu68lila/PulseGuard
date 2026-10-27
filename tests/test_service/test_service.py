"""Unit tests for the background service daemon."""

import threading
import time
from pathlib import Path

from pulseguard.service.runner import PulseGuardService


def test_service_lifecycle_non_blocking(tmp_path: Path) -> None:
    service = PulseGuardService(
        watch_paths=[tmp_path],
        auto_quarantine=False,
        poll_interval_seconds=0.05,
    )

    # Start service in background thread
    t = threading.Thread(target=service.start, kwargs={"block": True}, daemon=True)
    t.start()

    time.sleep(0.2)
    assert service.is_running is True

    service.stop()
    t.join(timeout=2.0)
    assert service.is_running is False


def test_service_signal_handling(tmp_path: Path) -> None:
    service = PulseGuardService(watch_paths=[tmp_path])
    service.register_signal_handlers()

    # Trigger internal signal handler
    service._handle_signal(signum=2, frame=None)
    assert service._stop_event.is_set()
