"""Unit tests for ScannerEngine orchestrator."""

from pathlib import Path

from pulseguard.core.models import ScanStatus
from pulseguard.engine.scanner import ScannerEngine


def test_scan_infected_signature_file(tmp_path: Path):
    engine = ScannerEngine()
    test_infected = tmp_path / "threat_sample.bin"
    # Contains default registered ransomware test pattern
    test_infected.write_bytes(b"DATA_HEADER::PULSEGUARD_TEST_RANSOM_MARKER::DATA_FOOTER")

    result = engine.scan_file(test_infected)
    assert result.status == ScanStatus.INFECTED
    assert result.is_infected is True
    assert result.threat is not None
    assert result.threat.threat_name == "Ransom.PulseGuard.TestPayload"
    assert result.scan_duration_ms >= 0.0


def test_scan_infected_heuristic_file(tmp_path: Path):
    engine = ScannerEngine()
    script_file = tmp_path / "ransom_wipe.bat"
    script_file.write_bytes(b"@echo off\r\nvssadmin.exe delete shadows /all /quiet\r\n")

    result = engine.scan_file(script_file)
    assert result.status == ScanStatus.INFECTED
    assert result.is_infected is True
    assert result.threat is not None
    assert result.threat.threat_name == "Heuristic.Ransomware.ShadowCopyDeletion"


def test_scan_clean_file():
    engine = ScannerEngine()
    clean_fixture = Path(__file__).parent.parent / "fixtures" / "clean_sample.txt"

    result = engine.scan_file(clean_fixture)
    assert result.status == ScanStatus.CLEAN
    assert result.is_infected is False
    assert result.threat is None


def test_scan_nonexistent_file(tmp_path: Path):
    engine = ScannerEngine()
    fake_path = tmp_path / "does_not_exist.bin"

    result = engine.scan_file(fake_path)
    assert result.status == ScanStatus.ERROR
    assert result.is_infected is False
    assert "does not exist" in result.error_message


def test_scan_directory(tmp_path: Path):
    engine = ScannerEngine()

    # Create directory with 1 clean file and 1 infected file
    clean_file = tmp_path / "good.txt"
    clean_file.write_bytes(b"All good here without any malware markers.\n")

    bad_file = tmp_path / "bad.bin"
    bad_file.write_bytes(b"PREFIX::PULSEGUARD_TEST_RANSOM_MARKER::SUFFIX")

    results = list(engine.scan_directory(tmp_path, recursive=False))
    assert len(results) == 2

    infected = [r for r in results if r.is_infected]
    clean = [r for r in results if not r.is_infected]

    assert len(infected) == 1
    assert len(clean) == 1
    assert infected[0].threat.threat_name == "Ransom.PulseGuard.TestPayload"
