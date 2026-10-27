"""Unit tests for ProcessScanner."""

import os
from pulseguard.engine.process_scanner import ProcessScanner, scan_process, scan_running_processes


def test_scan_current_process():
    scanner = ProcessScanner()
    current_pid = os.getpid()

    result = scanner.scan_process(current_pid)
    assert result.pid == current_pid
    assert result.name != ""
    assert result.is_infected is False


def test_scan_nonexistent_process():
    scanner = ProcessScanner()
    result = scanner.scan_process(9999999)
    assert result.is_infected is False
    assert result.name == "<terminated>"
    assert "no longer exists" in result.error_message


def test_scan_running_processes_stream():
    scanner = ProcessScanner()
    procs = []
    # Sample first 5 processes
    for p in scanner.scan_running_processes():
        procs.append(p)
        if len(procs) >= 5:
            break

    assert len(procs) == 5
    for p in procs:
        assert p.pid >= 0  # PID 0 is System Idle Process on Windows


def test_process_module_level_helpers():
    current_pid = os.getpid()
    res = scan_process(current_pid)
    assert res.pid == current_pid

    # Test sampling running process without iterating entire 350+ system processes
    first_running = next(iter(scan_running_processes()))
    assert first_running.pid >= 0
