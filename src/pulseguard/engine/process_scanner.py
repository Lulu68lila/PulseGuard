"""PulseGuard Running Process Memory and Executable Scanner.

Performs static and live behavioral inspection of active Windows processes,
detecting process masquerading, living-off-the-land commands, cryptominers,
and code-injection primitives.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional

import psutil

from pulseguard.core.models import ScanResult, ScanStatus, ThreatInfo, ThreatSeverity
from pulseguard.engine.scanner import ScannerEngine, _default_engine

# Core Windows system binaries and their authorized parent directories
SYSTEM_CORE_BINARIES = {
    "svchost.exe": {"system32", "syswow64"},
    "lsass.exe": {"system32"},
    "csrss.exe": {"system32"},
    "services.exe": {"system32"},
    "smss.exe": {"system32"},
    "winlogon.exe": {"system32"},
    "taskhostw.exe": {"system32"},
    "explorer.exe": {"windows"},
}

SUSPICIOUS_CMDLINE_RULES = [
    ("delete shadows", "Heuristic.Process.ActiveRansomwareExecution", ThreatSeverity.CRITICAL, "PROC_RANSOMWARE_CMDLINE", "Process executed with volume shadow copy wiper command."),
    ("delete catalog -quiet", "Heuristic.Process.BackupWiper", ThreatSeverity.CRITICAL, "PROC_BACKUP_WIPER_CMDLINE", "Process attempting to wipe Windows backup catalog."),
    ("stratum+tcp://", "Heuristic.Process.ActiveCryptominer", ThreatSeverity.HIGH, "PROC_CRYPTOMINER_STRATUM", "Active process connected to stratum cryptocurrency mining pool."),
    ("xmrig", "Heuristic.Process.ActiveCryptominerXmrig", ThreatSeverity.HIGH, "PROC_CRYPTOMINER_XMRIG", "Active execution of XMRig cryptomining binary."),
    ("comsvcs.dll, minidump", "Heuristic.Process.LsassDumper", ThreatSeverity.CRITICAL, "PROC_LSASS_COMSVCS_DUMP", "Process attempting memory dumping of LSASS credentials."),
    ("sekurlsa", "Heuristic.Process.MimikatzExecution", ThreatSeverity.CRITICAL, "PROC_MIMIKATZ_SEKURLSA", "Active execution of Mimikatz credential extraction."),
    ("new-object system.net.sockets.tcpclient", "Heuristic.Process.ReverseShell", ThreatSeverity.CRITICAL, "PROC_PS_REVERSE_SHELL", "Active PowerShell interactive TCP reverse shell."),
    ("set-mppreference -disablerealtimemonitoring", "Heuristic.Process.DisableDefender", ThreatSeverity.CRITICAL, "PROC_DISABLE_DEFENDER_CMDLINE", "Command line disabling Windows Defender real-time protection."),
]


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

        # 1. Check for Core System Binary Masquerading (e.g., svchost running from Temp)
        if exe_path and name.lower() in SYSTEM_CORE_BINARIES:
            parent_name = exe_path.parent.name.lower()
            allowed_dirs = SYSTEM_CORE_BINARIES[name.lower()]
            if parent_name not in allowed_dirs:
                masq_threat = ThreatInfo(
                    threat_name=f"Trojan.Masquerade.{name.replace('.exe', '').capitalize()}",
                    threat_type="process_masquerade",
                    severity=ThreatSeverity.CRITICAL,
                    rule_matched="PROC_SYSTEM_MASQUERADE",
                    file_hash="",
                    details=f"Core system binary '{name}' running from illegitimate path: '{exe_path}'. Expected '{'/'.join(allowed_dirs)}'.",
                )
                return ProcessThreatResult(
                    pid=pid,
                    name=name,
                    exe_path=exe_path,
                    cmdline=cmdline,
                    scan_result=None,
                    is_infected=True,
                    threat=masq_threat,
                )

        # 2. Inspect backing executable file if accessible
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

        # 3. Inspect command-line arguments for living-off-the-land malware
        joined_cmd = " ".join(cmdline).lower()
        for pattern, threat_name, severity, rule_id, details in SUSPICIOUS_CMDLINE_RULES:
            if pattern in joined_cmd:
                cmd_threat = ThreatInfo(
                    threat_name=threat_name,
                    threat_type="active_process",
                    severity=severity,
                    rule_matched=rule_id,
                    file_hash="",
                    details=f"Process PID {pid} executed with suspicious command: '{pattern}'. {details}",
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
