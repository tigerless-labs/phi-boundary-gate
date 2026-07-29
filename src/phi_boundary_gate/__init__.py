"""PHI boundary gating, redaction, and audit reporting."""

__version__ = "0.4.0"

from .api import GuardDecision, GuardMode, ScanFinding, guard_text, redact_text, scan_text
from .compliance import (
    ComplianceContext,
    ComplianceDecision,
    CompliancePolicy,
    ServiceProfile,
    guard_compliance,
    load_compliance_policy,
)
from .policy import load_policy

__all__ = [
    "ComplianceContext",
    "ComplianceDecision",
    "CompliancePolicy",
    "GuardDecision",
    "GuardMode",
    "ScanFinding",
    "ServiceProfile",
    "guard_compliance",
    "guard_text",
    "load_compliance_policy",
    "load_policy",
    "redact_text",
    "scan_text",
]
