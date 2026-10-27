"""PulseGuard Core domain models and interfaces."""

from pulseguard.core.models import (
    QuarantineRecord,
    ScanResult,
    ScanStatus,
    ThreatInfo,
    ThreatSeverity,
)

__all__ = [
    "QuarantineRecord",
    "ScanResult",
    "ScanStatus",
    "ThreatInfo",
    "ThreatSeverity",
]
