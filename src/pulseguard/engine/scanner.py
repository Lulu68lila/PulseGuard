"""PulseGuard Core Scanning Engine."""

import concurrent.futures
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, List, Optional

from pulseguard.core.models import ScanResult, ScanStatus, ThreatInfo
from pulseguard.engine.heuristics import HeuristicAnalyzer
from pulseguard.engine.signatures import SignatureDatabase, compute_sha256


class ScannerEngine:
    """Core scanning engine orchestrating signature checks and heuristic evaluations."""

    def __init__(
        self,
        signature_db: Optional[SignatureDatabase] = None,
        heuristic_analyzer: Optional[HeuristicAnalyzer] = None,
        max_file_size_bytes: int = 100 * 1024 * 1024,  # 100 MB default cap
    ) -> None:
        self.signature_db = signature_db or SignatureDatabase(include_defaults=True)
        self.heuristic_analyzer = heuristic_analyzer or HeuristicAnalyzer()
        self.max_file_size_bytes = max_file_size_bytes

    def load_signatures(self, signature_file: Path) -> int:
        """Load external signatures into the engine's database."""
        return self.signature_db.load_from_json(signature_file)

    def scan_file(self, file_path: Path) -> ScanResult:
        """Scan a single file against signatures and heuristics.

        Returns a ScanResult containing detection status, threat info, and hash.
        """
        start_time = time.perf_counter()
        target = Path(file_path)

        # 1. Existence and Type Validation
        if not target.exists():
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            return ScanResult(
                file_path=target,
                status=ScanStatus.ERROR,
                is_infected=False,
                file_hash="",
                timestamp=datetime.now(timezone.utc),
                error_message="File does not exist.",
                scan_duration_ms=duration_ms,
            )

        if not target.is_file():
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            return ScanResult(
                file_path=target,
                status=ScanStatus.SKIPPED,
                is_infected=False,
                file_hash="",
                timestamp=datetime.now(timezone.utc),
                error_message="Target is not a regular file.",
                scan_duration_ms=duration_ms,
            )

        # 2. File Read and SHA-256 Computation
        try:
            stat = target.stat()
            if stat.st_size > self.max_file_size_bytes:
                duration_ms = (time.perf_counter() - start_time) * 1000.0
                return ScanResult(
                    file_path=target,
                    status=ScanStatus.SKIPPED,
                    is_infected=False,
                    file_hash="",
                    timestamp=datetime.now(timezone.utc),
                    error_message=f"File exceeds maximum scanning size ({stat.st_size} > {self.max_file_size_bytes} bytes).",
                    scan_duration_ms=duration_ms,
                )

            file_hash = compute_sha256(target)
            with open(target, "rb") as f:
                file_bytes = f.read()

        except PermissionError as exc:
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            return ScanResult(
                file_path=target,
                status=ScanStatus.ERROR,
                is_infected=False,
                file_hash="",
                timestamp=datetime.now(timezone.utc),
                error_message=f"Access denied: {exc}",
                scan_duration_ms=duration_ms,
            )
        except OSError as exc:
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            return ScanResult(
                file_path=target,
                status=ScanStatus.ERROR,
                is_infected=False,
                file_hash="",
                timestamp=datetime.now(timezone.utc),
                error_message=f"I/O error during scan: {exc}",
                scan_duration_ms=duration_ms,
            )

        # 3. Exact Hash Signature Lookup
        matched_threat = self.signature_db.match_hash(file_hash)
        if matched_threat:
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            return ScanResult(
                file_path=target,
                status=ScanStatus.INFECTED,
                is_infected=True,
                file_hash=file_hash,
                timestamp=datetime.now(timezone.utc),
                threat=matched_threat,
                scan_duration_ms=duration_ms,
            )

        # 4. Byte Pattern Signature Matching
        matched_threat = self.signature_db.match_bytes(file_bytes)
        if matched_threat:
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            enriched_threat = ThreatInfo(
                threat_name=matched_threat.threat_name,
                threat_type=matched_threat.threat_type,
                severity=matched_threat.severity,
                rule_matched=matched_threat.rule_matched,
                file_hash=file_hash,
                details=matched_threat.details,
            )
            return ScanResult(
                file_path=target,
                status=ScanStatus.INFECTED,
                is_infected=True,
                file_hash=file_hash,
                timestamp=datetime.now(timezone.utc),
                threat=enriched_threat,
                scan_duration_ms=duration_ms,
            )

        # 5. Heuristic and Behavioral Inspection
        matched_threat = self.heuristic_analyzer.analyze_file(target, file_bytes, file_hash)
        if matched_threat:
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            return ScanResult(
                file_path=target,
                status=ScanStatus.INFECTED,
                is_infected=True,
                file_hash=file_hash,
                timestamp=datetime.now(timezone.utc),
                threat=matched_threat,
                scan_duration_ms=duration_ms,
            )

        # 6. File is Clean
        duration_ms = (time.perf_counter() - start_time) * 1000.0
        return ScanResult(
            file_path=target,
            status=ScanStatus.CLEAN,
            is_infected=False,
            file_hash=file_hash,
            timestamp=datetime.now(timezone.utc),
            threat=None,
            scan_duration_ms=duration_ms,
        )

    def scan_directory(
        self,
        dir_path: Path,
        recursive: bool = True,
        max_workers: int = 1,
    ) -> Iterable[ScanResult]:
        """Scan all files in a directory sequentially or in parallel using a thread pool."""
        target_dir = Path(dir_path)
        if not target_dir.exists() or not target_dir.is_dir():
            return

        pattern = "**/*" if recursive else "*"
        file_paths: List[Path] = [p for p in target_dir.glob(pattern) if p.is_file()]

        if max_workers <= 1 or len(file_paths) <= 1:
            for file_path in file_paths:
                yield self.scan_file(file_path)
        else:
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {executor.submit(self.scan_file, path): path for path in file_paths}
                for future in concurrent.futures.as_completed(futures):
                    yield future.result()


# Global default engine instance for module-level convenience
_default_engine = ScannerEngine()


def scan_file(file_path: Path) -> ScanResult:
    """Convenience function: scan a single file using default engine."""
    return _default_engine.scan_file(file_path)


def scan_directory(dir_path: Path, recursive: bool = True, max_workers: int = 1) -> Iterable[ScanResult]:
    """Convenience function: scan a directory using default engine."""
    return _default_engine.scan_directory(dir_path, recursive=recursive, max_workers=max_workers)


def load_signatures(signature_file: Path) -> int:
    """Convenience function: load signatures into default engine."""
    return _default_engine.load_signatures(signature_file)
