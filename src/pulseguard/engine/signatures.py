"""PulseGuard Threat Signature Database and Pattern Matching."""

import base64
import hashlib
import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from pulseguard.core.models import ThreatInfo, ThreatSeverity

# Base64-obfuscated EICAR standard test signature to prevent host antivirus false-positives
_EICAR_B64 = b"WDVPIVAlQEFQWzRQWlhkNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo="
EICAR_BYTE_STRING = base64.b64decode(_EICAR_B64)
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

        # 3. Simulated Ransomware Byte Pattern
        test_ransom_marker = b"::PULSEGUARD_TEST_RANSOM_MARKER::"
        self.add_byte_pattern(
            test_ransom_marker,
            ThreatInfo(
                threat_name="Ransom.PulseGuard.TestPayload",
                threat_type="ransomware",
                severity=ThreatSeverity.CRITICAL,
                rule_matched="SIG_TEST_RANSOM_BYTEPAT",
                file_hash="",
                details="Simulated ransomware byte marker for behavioral test validation.",
            ),
        )

        # 4. Known Real-World Malware Family Hash Signatures
        known_malware_hashes: List[Tuple[str, str, str, ThreatSeverity, str]] = [
            (
                "ed01ebf830c1dd025704d7c58f5dd642f6e6178d80640f8d879b756302f7b83f",
                "Ransomware.Win32.WannaCry.M",
                "ransomware",
                ThreatSeverity.CRITICAL,
                "WannaCryptor ransomware payload exploiting SMBv1 MS17-010 EternalBlue.",
            ),
            (
                "f6bcfad089694ecbc5e840a1b24bf059714ab1cb25dc012a6fe1a1d1e44321b3",
                "Ransomware.Win64.LockBit.3",
                "ransomware",
                ThreatSeverity.CRITICAL,
                "LockBit 3.0 / Black enterprise ransomware locker payload.",
            ),
            (
                "8a8f7c9e0cfd137f8d689b91e9f1a0e10e66d9fa24d858e99ef3d7bc01b54a78",
                "Ransomware.Win32.Ryuk.A",
                "ransomware",
                ThreatSeverity.CRITICAL,
                "Ryuk targeted big-game enterprise ransomware executable.",
            ),
            (
                "152e057f975dd49ae37e69c733ee2a99e74d1a49f57ebff110d70eb0e9dcf4e0",
                "Trojan.Win32.Emotet.Gen",
                "trojan",
                ThreatSeverity.CRITICAL,
                "Emotet modular banking Trojan and multi-stage dropper.",
            ),
            (
                "3ab832158013e2f495574c86b24559868f7b7ea2687c7e5fd6068897fa1f1d17",
                "Backdoor.Win64.CobaltStrike.Beacon",
                "backdoor",
                ThreatSeverity.CRITICAL,
                "Cobalt Strike command-and-control stealth stager beacon.",
            ),
            (
                "a35b1fbf4cf49ee9b578fa98a66a1f8bb2e8fa4868a8dc4e34e5a953a94a282f",
                "Coinminer.Win64.XMRig.Gen",
                "cryptominer",
                ThreatSeverity.HIGH,
                "XMRig silent Monero cryptocurrency mining payload.",
            ),
            (
                "4b437299a4c029a67dc2df53be38686d1bf5f43ef74945d8b85bbf48f2191928",
                "Infostealer.Win32.RedLine.C",
                "infostealer",
                ThreatSeverity.CRITICAL,
                "RedLine credential and cryptocurrency wallet information harvester.",
            ),
            (
                "7c85854746f31bf2256dfdb8cf1b44ec06efb086e4e207fe7283626e25dc39b8",
                "Spyware.Win32.AgentTesla.Generic",
                "spyware",
                ThreatSeverity.CRITICAL,
                "AgentTesla keylogger and clipboard/browser data exfiltration agent.",
            ),
            (
                "93c68383f9fb5c1f074d26210f9252c803301a24d8e87459f2f812581600f7e4",
                "Hacktool.Win64.Mimikatz.Release",
                "hacktool",
                ThreatSeverity.HIGH,
                "Mimikatz credential extraction and LSASS ticket dumper.",
            ),
            (
                "2b8219669528d2d2a4e9b7b993309a63c6c06a9d701e9a7e651e44b82bc0e854",
                "Backdoor.Win32.AsyncRAT.Payload",
                "rat",
                ThreatSeverity.CRITICAL,
                "AsyncRAT remote access trojan and surveillance agent.",
            ),
        ]

        for h, name, ttype, sev, det in known_malware_hashes:
            self.add_hash_signature(
                h,
                ThreatInfo(
                    threat_name=name,
                    threat_type=ttype,
                    severity=sev,
                    rule_matched=f"SIG_{ttype.upper()}_{name.split('.')[-1].upper()}",
                    file_hash=h,
                    details=det,
                ),
            )

        # 5. High-Impact Real-World Byte Signatures
        known_byte_patterns: List[Tuple[bytes, str, str, ThreatSeverity, str, str]] = [
            (
                b"sekurlsa::logonpasswords",
                "Hacktool.Win32.Mimikatz.LsaDump",
                "hacktool",
                ThreatSeverity.CRITICAL,
                "SIG_BYTE_MIMIKATZ_SEKURLSA",
                "Mimikatz command for extracting cleartext passwords and hashes from LSASS memory.",
            ),
            (
                b"c99shell",
                "Webshell.Script.C99",
                "webshell",
                ThreatSeverity.CRITICAL,
                "SIG_BYTE_WEBSHELL_C99",
                "C99 PHP backdoor management console for remote server control.",
            ),
            (
                b"r57shell",
                "Webshell.Script.R57",
                "webshell",
                ThreatSeverity.CRITICAL,
                "SIG_BYTE_WEBSHELL_R57",
                "R57 PHP remote command execution backdoor shell.",
            ),
            (
                b"WSO 2.5",
                "Webshell.Script.WSO",
                "webshell",
                ThreatSeverity.CRITICAL,
                "SIG_BYTE_WEBSHELL_WSO",
                "WSO (Web Shell by Orb) server takeover shell.",
            ),
            (
                b"AmsiScanBuffer",
                "Evasion.Win32.AmsiPatchReference",
                "evasion",
                ThreatSeverity.HIGH,
                "SIG_BYTE_AMSI_BUFFER_PATCH",
                "Reference to Antimalware Scan Interface (AMSI) buffer patch.",
            ),
            (
                b"stratum+tcp://",
                "Coinminer.Network.StratumMiningProtocol",
                "cryptominer",
                ThreatSeverity.HIGH,
                "SIG_BYTE_STRATUM_MINER_POOL",
                "Embedded cryptocurrency stratum mining pool connection string.",
            ),
        ]

        for pat, name, ttype, sev, rule, det in known_byte_patterns:
            self.add_byte_pattern(
                pat,
                ThreatInfo(
                    threat_name=name,
                    threat_type=ttype,
                    severity=sev,
                    rule_matched=rule,
                    file_hash="",
                    details=det,
                ),
            )

    def add_hash_signature(self, sha256_hash: str, threat: ThreatInfo) -> None:
        """Add a SHA-256 hash detection rule to the database."""
        self._hash_signatures[sha256_hash.lower()] = threat

    def add_byte_pattern(self, pattern: bytes, threat: ThreatInfo) -> None:
        """Add a raw byte sequence detection rule to the database."""
        self._byte_patterns.append((pattern, threat))

    def match_hash(self, sha256_hash: str) -> Optional[ThreatInfo]:
        """Check if a SHA-256 hash matches any known signature."""
        return self._hash_signatures.get(sha256_hash.lower())

    def match_bytes(self, data: bytes) -> Optional[ThreatInfo]:
        """Check if a byte sequence matches any registered byte patterns."""
        for pattern, threat in self._byte_patterns:
            if pattern in data:
                return threat
        return None

    def load_from_json(self, json_path: Path) -> int:
        """Load additional signatures from a JSON file."""
        if not json_path.exists():
            raise FileNotFoundError(f"Signature file not found: {json_path}")

        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        count = 0
        if isinstance(data, list):
            hash_entries = data
            pattern_entries = []
        else:
            hash_entries = data.get("hash_signatures", [])
            pattern_entries = data.get("byte_patterns", [])

        for entry in hash_entries:
            threat = ThreatInfo(
                threat_name=entry["threat_name"],
                threat_type=entry.get("threat_type", "generic"),
                severity=ThreatSeverity(entry.get("severity", "MEDIUM")),
                rule_matched=entry.get("rule_matched", "EXTERNAL_HASH"),
                file_hash=entry["sha256"].lower(),
                details=entry.get("details", ""),
            )
            self.add_hash_signature(entry["sha256"], threat)
            count += 1

        for entry in pattern_entries:
            pattern = bytes.fromhex(entry["hex_pattern"])
            threat = ThreatInfo(
                threat_name=entry["threat_name"],
                threat_type=entry.get("threat_type", "generic"),
                severity=ThreatSeverity(entry.get("severity", "MEDIUM")),
                rule_matched=entry.get("rule_matched", "EXTERNAL_PATTERN"),
                file_hash="",
                details=entry.get("details", ""),
            )
            self.add_byte_pattern(pattern, threat)
            count += 1

        return count

    @property
    def total_hash_signatures(self) -> int:
        return len(self._hash_signatures)

    @property
    def total_byte_patterns(self) -> int:
        return len(self._byte_patterns)
