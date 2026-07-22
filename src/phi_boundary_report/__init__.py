"""PHI context boundary reporting and redaction."""

__version__ = "0.1.0"

from .api import GuardDecision, GuardMode, ScanFinding, guard_text, redact_text, scan_text
from .policy import load_policy

__all__ = [
    "GuardDecision",
    "GuardMode",
    "ScanFinding",
    "guard_text",
    "load_policy",
    "redact_text",
    "scan_text",
]
