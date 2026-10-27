"""Targeted coverage tests for ScannerEngine and Heuristics."""

import os
from pathlib import Path

from pulseguard.core.models import ScanStatus
from pulseguard.engine.heuristics import HeuristicAnalyzer
from pulseguard.engine.scanner import ScannerEngine, load_signatures, scan_directory, scan_file


def test_oversized_file_skipped(tmp_path: Path):
    engine = ScannerEngine(max_file_size_bytes=100)
    large_file = tmp_path / "big.bin"
    large_file.write_bytes(b"A" * 200)

    result = engine.scan_file(large_file)
    assert result.status == ScanStatus.SKIPPED
    assert "exceeds maximum scanning size" in result.error_message


def test_directory_as_file_skipped(tmp_path: Path):
    engine = ScannerEngine()
    sub_dir = tmp_path / "somedir"
    sub_dir.mkdir()

    result = engine.scan_file(sub_dir)
    assert result.status == ScanStatus.SKIPPED
    assert "not a regular file" in result.error_message


def test_scanner_module_level_helpers(tmp_path: Path):
    clean = tmp_path / "clean.txt"
    clean.write_bytes(b"Simple test content\n")

    res = scan_file(clean)
    assert res.status == ScanStatus.CLEAN

    results = list(scan_directory(tmp_path))
    assert len(results) == 1

    fixtures_json = Path(__file__).parent.parent / "fixtures" / "test_signatures.json"
    loaded = load_signatures(fixtures_json)
    assert loaded == 2


def test_heuristic_high_entropy_binary():
    analyzer = HeuristicAnalyzer(entropy_threshold=7.0, min_bytes_for_entropy=512)
    high_entropy_bytes = os.urandom(2048)
    threat = analyzer.analyze_file(Path("packed.exe"), high_entropy_bytes, "entropy_hash_1")
    assert threat is not None
    assert threat.threat_type == "packed_pe"
