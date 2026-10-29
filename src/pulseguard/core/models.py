"""PulseGuard shared domain models and type contracts."""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional


class ThreatSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ScanStatus(str, Enum):
    CLEAN = "CLEAN"
    INFECTED = "INFECTED"
    ERROR = "ERROR"
    SKIPPED = "SKIPPED"


class VulnerabilityCategory(str, Enum):
    SYSTEM_CONFIG = "SYSTEM_CONFIG"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    NETWORK_EXPOSURE = "NETWORK_EXPOSURE"
    CREDENTIAL_LEAK = "CREDENTIAL_LEAK"
    DEFENSE_EVASION = "DEFENSE_EVASION"
    PERSISTENCE_RISK = "PERSISTENCE_RISK"


@dataclass(frozen=True)
class ThreatInfo:
    threat_name: str
    threat_type: str        # e.g., "eicar", "signature", "heuristic", "packed_pe"
    severity: ThreatSeverity
    rule_matched: str
    file_hash: str          # SHA-256 string
    details: Optional[str] = None


@dataclass
class VulnerabilityFinding:
    vuln_id: str
    category: VulnerabilityCategory
    severity: ThreatSeverity
    title: str
    description: str
    affected_item: str
    cve_cwe: str
    remediation: str
    can_auto_fix: bool = False
    is_fixed: bool = False


@dataclass(frozen=True)
class ScanResult:
    file_path: Path
    status: ScanStatus
    is_infected: bool
    file_hash: str
    timestamp: datetime
    threat: Optional[ThreatInfo] = None
    error_message: Optional[str] = None
    scan_duration_ms: float = 0.0


@dataclass
class QuarantineRecord:
    record_id: str
    original_path: Path
    vault_path: Path
    quarantined_at: datetime
    threat: ThreatInfo
    file_hash: str
    is_restored: bool = False
