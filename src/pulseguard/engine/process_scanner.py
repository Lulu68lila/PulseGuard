"""PulseGuard Running Process Memory and Executable Scanner."""

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional

import psutil

from pulseguard.core.models import ScanResult, ScanStatus, ThreatInfo, ThreatSeverity
from pulseguard.engine.scanner import ScannerEngine, _default_engine


@dataclass
class ProcessThreatResult:
    pid: int
    name: str
    exe_path: Optional[Path]
    cmdline: List[str]
    scan_result: Optional[ScanResult]
    is_infected: bool
    threat: Optional[ThreatInfo] = None
    error_message: Optional[str] = None


class ProcessScanner:
    """Scans running system processes, executable paths, and command lines for active threats."""

    def __init__(self, scanner_engine: Optional[ScannerEngine] = None) -> None:
        self.engine = scanner_engine or _default_engine

    def scan_process(self, pid: int) -> ProcessThreatResult:
        """Scan a single running process by PID."""
        try:
            proc = psutil.Process(pid)
            name = proc.name()
            try:
                exe = proc.exe()
                exe_path = Path(exe) if exe else None
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                exe_path = None

            try:
                cmdline = proc.cmdline()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                cmdline = []

        except psutil.NoSuchProcess:
            return ProcessThreatResult(
                pid=pid,
                name="<terminated>",
                exe_path=None,
                cmdline=[],
                scan_result=None,
                is_infected=False,
                error_message="Process no longer exists.",
            )
        except psutil.AccessDenied:
            return ProcessThreatResult(
                pid=pid,
                name="<system_protected>",
                exe_path=None,
                cmdline=[],
                scan_result=None,
                is_infected=False,
                error_message="Access denied (system-protected process).",
            )

        # 1. Inspect backing executable file if accessible
        scan_res: Optional[ScanResult] = None
        if exe_path and exe_path.exists():
            scan_res = self.engine.scan_file(exe_path)
            if scan_res.is_infected and scan_res.threat:
                return ProcessThreatResult(
                    pid=pid,
                    name=name,
                    exe_path=exe_path,
                    cmdline=cmdline,
                    scan_result=scan_res,
                    is_infected=True,
                    threat=scan_res.threat,
                )

        # 2. Inspect command-line arguments for living-off-the-land malware
        joined_cmd = " ".join(cmdline).lower()
        if "delete shadows" in joined_cmd:
            cmd_threat = ThreatInfo(
                threat_name="Heuristic.Process.ActiveRansomwareExecution",
                threat_type="active_process",
                severity=ThreatSeverity.CRITICAL,
                rule_matched="PROC_RANSOMWARE_CMDLINE",
                file_hash="",
                details=f"Process PID {pid} executed with shadow deletion command: {joined_cmd}",
            )
            return ProcessThreatResult(
                pid=pid,
                name=name,
                exe_path=exe_path,
                cmdline=cmdline,
                scan_result=scan_res,
                is_infected=True,
                threat=cmd_threat,
            )

        return ProcessThreatResult(
            pid=pid,
            name=name,
            exe_path=exe_path,
            cmdline=cmdline,
            scan_result=scan_res,
            is_infected=False,
        )

    def scan_running_processes(self) -> Iterable[ProcessThreatResult]:
        """Scan all accessible running processes on the system."""
        for proc in psutil.process_iter(["pid"]):
            try:
                yield self.scan_process(proc.pid)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def terminate_process(self, pid: int, force: bool = True) -> bool:
        """Terminate a malicious process by PID."""
        try:
            proc = psutil.Process(pid)
            if force:
                proc.kill()
            else:
                proc.terminate()
            return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False


_default_process_scanner = ProcessScanner()


def scan_process(pid: int) -> ProcessThreatResult:
    return _default_process_scanner.scan_process(pid)


def scan_running_processes() -> Iterable[ProcessThreatResult]:
    return _default_process_scanner.scan_running_processes()
