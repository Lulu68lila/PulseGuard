"""Unit tests for SignatureDatabase and hash matching."""

import hashlib
from pathlib import Path

from pulseguard.core.models import ThreatSeverity
from pulseguard.engine.signatures import (
    EICAR_BYTE_STRING,
    EICAR_SHA256,
    SignatureDatabase,
    compute_sha256,
)


def test_compute_sha256(tmp_path: Path):
    sample = tmp_path / "sample.txt"
    sample.write_bytes(b"hello world\n")

    expected = hashlib.sha256(b"hello world\n").hexdigest()
    assert compute_sha256(sample) == expected


def test_eicar_signature_detection():
    db = SignatureDatabase(include_defaults=True)

    # Hash match
    threat = db.match_hash(EICAR_SHA256)
    assert threat is not None
    assert threat.threat_name == "EICAR.StandardAntivirusTestFile"
    assert threat.severity == ThreatSeverity.HIGH
    assert threat.threat_type == "eicar"

    # Byte match
    byte_threat = db.match_bytes(EICAR_BYTE_STRING)
    assert byte_threat is not None
    assert byte_threat.threat_name == "EICAR.StandardAntivirusTestFile"


def test_byte_pattern_detection():
    db = SignatureDatabase(include_defaults=True)
    payload = b"junk_prefix" + b"::PULSEGUARD_TEST_RANSOM_MARKER::" + b"junk_suffix"
    matched = db.match_bytes(payload)
    assert matched is not None
    assert matched.threat_type == "ransomware"
    assert matched.threat_name == "Ransom.PulseGuard.TestPayload"


def test_clean_file_no_match():
    db = SignatureDatabase(include_defaults=True)
    random_hash = "11" * 32
    assert db.match_hash(random_hash) is None
    assert db.match_bytes(b"completely benign text without any malicious marker") is None


def test_load_external_json_signatures(tmp_path: Path):
    db = SignatureDatabase(include_defaults=False)
    fixtures_json = Path(__file__).parent.parent / "fixtures" / "test_signatures.json"

    count = db.load_from_json(fixtures_json)
    assert count == 2

    # Verify loaded item
    loaded = db.match_hash("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    assert loaded is not None
    assert loaded.threat_name == "Trojan.PulseGuard.ExternalMock"
    assert loaded.severity == ThreatSeverity.CRITICAL
