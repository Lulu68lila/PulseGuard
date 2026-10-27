"""PulseGuard Threat Signature Database and Pattern Matching."""

import hashlib
import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from pulseguard.core.models import ThreatInfo, ThreatSeverity

# Official EICAR standard anti-virus test file signature (68 bytes)
EICAR_BYTE_STRING = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


def compute_sha256(file_path: Path, chunk_size: int = 65536) -> str:
    """Compute the SHA-256 hex digest of a file using chunked streaming."""
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(chunk_size):
            hasher.update(chunk)
    return hasher.hexdigest().lower()


class SignatureDatabase:
    """In-memory database of hash signatures and byte patterns."""

    def __init__(self, include_defaults: bool = True) -> None:
        self._hash_signatures: Dict[str, ThreatInfo] = {}
        self._byte_patterns: List[Tuple[bytes, ThreatInfo]] = []

        if include_defaults:
            self._load_default_signatures()

    def _load_default_signatures(self) -> None:
        """Register baseline threat signatures including EICAR standard."""
        # 1. EICAR Standard Test Signature
        eicar_threat = ThreatInfo(
            threat_name="EICAR.StandardAntivirusTestFile",
            threat_type="eicar",
            severity=ThreatSeverity.HIGH,
            rule_matched="SIG_EICAR_TEST_STD",
            file_hash=EICAR_SHA256,
            details="Standard antivirus test pattern (harmless verification marker).",
        )
        self.add_hash_signature(EICAR_SHA256, eicar_threat)
        self.add_byte_pattern(EICAR_BYTE_STRING, eicar_threat)

        # 2. Test Trojan Dropper Signature
        test_trojan_sha256 = "44d88612fea8a8f36de82e1278abb02f" * 2  # 64-char synthetic SHA256
        self.add_hash_signature(
            test_trojan_sha256,
            ThreatInfo(
                threat_name="Trojan.PulseGuard.SyntheticTest",
                threat_type="trojan",
                severity=ThreatSeverity.CRITICAL,
                rule_matched="SIG_TEST_TROJAN_HASH",
                file_hash=test_trojan_sha256,
                details="Synthetic detection signature for verification pipelines.",
            ),
        )

        # 3. Test Ransomware Extension/Payload Marker Pattern
        ransom_marker = b"::PULSEGUARD_TEST_RANSOM_MARKER::"
        self.add_byte_pattern(
            ransom_marker,
            ThreatInfo(
                threat_name="Ransom.PulseGuard.TestPayload",
                threat_type="ransomware",
                severity=ThreatSeverity.CRITICAL,
                rule_matched="SIG_TEST_RANSOM_BYTEPAT",
                file_hash="",
                details="Simulated ransomware byte marker for behavioral test validation.",
            ),
        )

    def add_hash_signature(self, sha256_hash: str, threat: ThreatInfo) -> None:
        """Add a SHA-256 hash threat signature."""
        self._hash_signatures[sha256_hash.lower()] = threat

    def add_byte_pattern(self, pattern: bytes, threat: ThreatInfo) -> None:
        """Add a raw byte pattern sequence to match within file headers or bodies."""
        self._byte_patterns.append((pattern, threat))

    def load_from_json(self, file_path: Path) -> int:
        """Load external signatures from a JSON file.

        Expected schema:
        [
            {
                "sha256": "...",
                "threat_name": "...",
                "threat_type": "...",
                "severity": "CRITICAL|HIGH|MEDIUM|LOW",
                "rule_matched": "...",
                "details": "..."
            }
        ]
        """
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        count = 0
        for entry in data:
            sha256_hash = entry.get("sha256", "").strip().lower()
            if not sha256_hash:
                continue

            threat = ThreatInfo(
                threat_name=entry.get("threat_name", "Unknown.Threat"),
                threat_type=entry.get("threat_type", "signature"),
                severity=ThreatSeverity(entry.get("severity", "MEDIUM").upper()),
                rule_matched=entry.get("rule_matched", f"SIG_EXT_{sha256_hash[:8]}"),
                file_hash=sha256_hash,
                details=entry.get("details"),
            )
            self.add_hash_signature(sha256_hash, threat)
            count += 1
        return count

    def match_hash(self, sha256_hash: str) -> Optional[ThreatInfo]:
        """Check if a SHA-256 hash matches a known malicious signature."""
        return self._hash_signatures.get(sha256_hash.lower())

    def match_bytes(self, content: bytes, max_search_bytes: int = 1048576) -> Optional[ThreatInfo]:
        """Search for known malicious byte sequences in the buffer."""
        search_slice = content[:max_search_bytes]
        for pattern, threat in self._byte_patterns:
            if pattern in search_slice:
                return threat
        return None

    @property
    def total_hash_signatures(self) -> int:
        return len(self._hash_signatures)

    @property
    def total_byte_patterns(self) -> int:
        return len(self._byte_patterns)
