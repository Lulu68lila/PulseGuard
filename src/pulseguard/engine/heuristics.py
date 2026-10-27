"""PulseGuard Heuristic and Behavioral Threat Analysis."""

import math
import os
import re
from pathlib import Path
from typing import List, Optional, Tuple

from pulseguard.core.models import ThreatInfo, ThreatSeverity

# Known masquerading extensions that should never be PE executables
DECEPTIVE_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp",
    ".mp3", ".wav", ".mp4", ".avi", ".mkv",
    ".txt", ".pdf", ".docx", ".xlsx", ".pptx",
    ".zip", ".rar", ".7z", ".tar", ".gz",
}

# Suspicious script patterns (regex, threat_name, severity, rule_id)
SUSPICIOUS_SCRIPT_PATTERNS: List[Tuple[re.Pattern, str, ThreatSeverity, str]] = [
    (
        re.compile(rb"vssadmin(\.exe)?\s+delete\s+shadows", re.IGNORECASE),
        "Heuristic.Ransomware.ShadowCopyDeletion",
        ThreatSeverity.CRITICAL,
        "HEUR_VSSADMIN_DELETE_SHADOWS",
    ),
    (
        re.compile(rb"bcdedit(\.exe)?\s+/set\s+.*(recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)", re.IGNORECASE),
        "Heuristic.Ransomware.BootRecoveryDisabler",
        ThreatSeverity.CRITICAL,
        "HEUR_BCDEDIT_DISABLE_RECOVERY",
    ),
    (
        re.compile(rb"wbadmin(\.exe)?\s+delete\s+catalog\s+-quiet", re.IGNORECASE),
        "Heuristic.Ransomware.BackupCatalogWiper",
        ThreatSeverity.CRITICAL,
        "HEUR_WBADMIN_DELETE_CATALOG",
    ),
    (
        re.compile(rb"powershell(\.exe)?\s+.*-(enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}", re.IGNORECASE),
        "Heuristic.Dropper.EncodedPowerShell",
        ThreatSeverity.HIGH,
        "HEUR_POWERSHELL_ENCODED_CMD",
    ),
    (
        re.compile(rb"new-object\s+net\.webclient.*\.download(file|string)\(", re.IGNORECASE),
        "Heuristic.Dropper.WebClientDownloadCradle",
        ThreatSeverity.HIGH,
        "HEUR_PS_WEBCLIENT_DOWNLOAD",
    ),
    (
        re.compile(rb"invoke-expression.*downloadstring", re.IGNORECASE),
        "Heuristic.Dropper.IEXDownloadCradle",
        ThreatSeverity.HIGH,
        "HEUR_IEX_DOWNLOAD_CRADLE",
    ),
]


def calculate_entropy(data: bytes) -> float:
    """Calculate the Shannon entropy of a byte sequence (0.0 to 8.0)."""
    if not data:
        return 0.0

    length = len(data)
    frequencies = [0] * 256
    for b in data:
        frequencies[b] += 1

    entropy = 0.0
    for count in frequencies:
        if count > 0:
            probability = count / length
            entropy -= probability * math.log2(probability)

    return entropy


class HeuristicAnalyzer:
    """Heuristic scanner for entropy, extension deception, and malicious patterns."""

    def __init__(
        self,
        entropy_threshold: float = 7.3,
        min_bytes_for_entropy: int = 1024,
    ) -> None:
        self.entropy_threshold = entropy_threshold
        self.min_bytes_for_entropy = min_bytes_for_entropy

    def analyze_file(self, file_path: Path, file_bytes: bytes, file_hash: str) -> Optional[ThreatInfo]:
        """Run heuristic checks on a file.

        Returns ThreatInfo if a suspicious/malicious indicator is triggered, or None.
        """
        # 1. Extension Deception / Masquerading Check (PE Executable in benign wrapper)
        masquerade_threat = self._check_extension_masquerading(file_path, file_bytes, file_hash)
        if masquerade_threat:
            return masquerade_threat

        # 2. Suspicious Command & Script Pattern Matching
        script_threat = self._check_script_patterns(file_bytes, file_hash)
        if script_threat:
            return script_threat

        # 3. High Entropy (Packed PE or Encrypted Payload)
        entropy_threat = self._check_entropy_packing(file_path, file_bytes, file_hash)
        if entropy_threat:
            return entropy_threat

        # 4. Deep PE Inspection (if PE file and pefile module available)
        pe_threat = self._check_pe_anomalies(file_bytes, file_hash)
        if pe_threat:
            return pe_threat

        return None

    def _check_extension_masquerading(self, file_path: Path, file_bytes: bytes, file_hash: str) -> Optional[ThreatInfo]:
        """Detect executable binaries masquerading as documents, pictures, or archives."""
        ext = file_path.suffix.lower()
        if ext in DECEPTIVE_EXTENSIONS and len(file_bytes) >= 64:
            # Check for Windows MZ header (0x4D, 0x5A)
            if file_bytes[:2] == b"MZ":
                return ThreatInfo(
                    threat_name=f"Trojan.Masquerade.Deceptive{ext.upper().replace('.', '')}",
                    threat_type="masquerade",
                    severity=ThreatSeverity.CRITICAL,
                    rule_matched="HEUR_PE_MAGIC_IN_DOCUMENT",
                    file_hash=file_hash,
                    details=f"File '{file_path.name}' with extension '{ext}' contains a Windows executable binary header (MZ).",
                )
        return None

    def _check_script_patterns(self, file_bytes: bytes, file_hash: str) -> Optional[ThreatInfo]:
        """Check for destructive commands or stealth download cradles."""
        sample_slice = file_bytes[:2097152]  # Scan first 2MB
        for pattern, threat_name, severity, rule_id in SUSPICIOUS_SCRIPT_PATTERNS:
            if pattern.search(sample_slice):
                return ThreatInfo(
                    threat_name=threat_name,
                    threat_type="heuristic",
                    severity=severity,
                    rule_matched=rule_id,
                    file_hash=file_hash,
                    details="Known malicious command sequence detected in script payload.",
                )
        return None

    def _check_entropy_packing(self, file_path: Path, file_bytes: bytes, file_hash: str) -> Optional[ThreatInfo]:
        """Flag suspiciously high entropy binaries (packed shellcode / ransomware cryptors)."""
        if len(file_bytes) < self.min_bytes_for_entropy:
            return None

        # Only evaluate entropy on executable or binary formats
        ext = file_path.suffix.lower()
        is_binary = ext in {".exe", ".dll", ".sys", ".scr"} or file_bytes[:2] == b"MZ"
        if not is_binary:
            return None

        entropy = calculate_entropy(file_bytes)
        if entropy >= self.entropy_threshold:
            return ThreatInfo(
                threat_name="Heuristic.Packed.HighEntropyBinary",
                threat_type="packed_pe",
                severity=ThreatSeverity.LOW,
                rule_matched="HEUR_HIGH_ENTROPY_PACKED",
                file_hash=file_hash,
                details=f"Calculated Shannon entropy {entropy:.2f}/8.0 exceeds threshold {self.entropy_threshold}.",
            )
        return None

    def _check_pe_anomalies(self, file_bytes: bytes, file_hash: str) -> Optional[ThreatInfo]:
        """Inspect PE header for writable and executable (W+X) sections."""
        if len(file_bytes) < 512 or file_bytes[:2] != b"MZ":
            return None

        try:
            import pefile  # optional / dynamic import
            pe = pefile.PE(data=file_bytes, fast_load=True)
            for section in pe.sections:
                # IMAGE_SCN_MEM_EXECUTE (0x20000000) and IMAGE_SCN_MEM_WRITE (0x80000000)
                characteristics = getattr(section, "Characteristics", 0)
                is_writable = bool(characteristics & 0x80000000)
                is_executable = bool(characteristics & 0x20000000)
                if is_writable and is_executable:
                    section_name = section.Name.decode("utf-8", errors="ignore").strip("\x00")
                    return ThreatInfo(
                        threat_name="Heuristic.PE.WritableExecutableSection",
                        threat_type="pe_anomaly",
                        severity=ThreatSeverity.HIGH,
                        rule_matched="HEUR_PE_WX_SECTION",
                        file_hash=file_hash,
                        details=f"PE section '{section_name}' has both write and execute permissions (W+X).",
                    )
        except Exception:
            # If pefile fails or format is corrupt, do not crash scanner
            pass
        return None
