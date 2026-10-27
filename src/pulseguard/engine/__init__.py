"""PulseGuard Detection Engine."""

from pulseguard.engine.heuristics import HeuristicAnalyzer, calculate_entropy
from pulseguard.engine.process_scanner import (
    ProcessScanner,
    ProcessThreatResult,
    scan_process,
    scan_running_processes,
)
from pulseguard.engine.scanner import ScannerEngine, load_signatures, scan_directory, scan_file
from pulseguard.engine.signatures import SignatureDatabase, compute_sha256

__all__ = [
    "HeuristicAnalyzer",
    "ProcessScanner",
    "ProcessThreatResult",
    "ScannerEngine",
    "SignatureDatabase",
    "calculate_entropy",
    "compute_sha256",
    "load_signatures",
    "scan_directory",
    "scan_file",
    "scan_process",
    "scan_running_processes",
]
