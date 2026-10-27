"""Unit tests for HeuristicAnalyzer and entropy calculations."""

import os
from pathlib import Path

from pulseguard.core.models import ThreatSeverity
from pulseguard.engine.heuristics import HeuristicAnalyzer, calculate_entropy


def test_calculate_entropy():
    # 1. Null data
    assert calculate_entropy(b"") == 0.0

    # 2. Monotonous data (single repeated byte -> minimum entropy 0.0)
    assert calculate_entropy(b"A" * 1000) == 0.0

    # 3. High entropy data (pseudo-random bytes -> close to 8.0)
    random_bytes = os.urandom(4096)
    entropy = calculate_entropy(random_bytes)
    assert 7.7 <= entropy <= 8.0


def test_extension_masquerading_detection():
    analyzer = HeuristicAnalyzer()

    # Create synthetic file: .jpg with PE executable header (MZ)
    fake_jpg = Path("invoice.jpg")
    fake_jpg_bytes = b"MZ" + b"\x90" * 128  # MZ DOS header

    threat = analyzer.analyze_file(fake_jpg, fake_jpg_bytes, "test_hash_123")
    assert threat is not None
    assert threat.threat_type == "masquerade"
    assert threat.severity == ThreatSeverity.CRITICAL
    assert "invoice.jpg" in threat.details or "JPG" in threat.details


def test_suspicious_script_detection():
    analyzer = HeuristicAnalyzer()

    # VSSAdmin shadow copy deletion pattern
    script_content = b"@echo off\r\nvssadmin.exe delete shadows /all /quiet\r\n"
    threat = analyzer.analyze_file(Path("wiper.bat"), script_content, "hash_vssadmin")
    assert threat is not None
    assert threat.threat_name == "Heuristic.Ransomware.ShadowCopyDeletion"
    assert threat.severity == ThreatSeverity.CRITICAL

    # Encoded PowerShell command
    ps_content = b"powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAA="
    threat_ps = analyzer.analyze_file(Path("launcher.ps1"), ps_content, "hash_ps")
    assert threat_ps is not None
    assert threat_ps.threat_name == "Heuristic.Dropper.EncodedPowerShell"


def test_benign_file_not_flagged():
    analyzer = HeuristicAnalyzer()
    clean_text = b"echo Hello, world! This is a benign build script for testing.\n"
    threat = analyzer.analyze_file(Path("build.bat"), clean_text, "hash_clean")
    assert threat is None
