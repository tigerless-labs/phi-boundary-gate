"""PHI context boundary reporting and redaction."""

__version__ = "0.1.0"

from .api import GuardDecision, guard_text, redact_text, scan_text
from .policy import load_policy

__all__ = [
    "GuardDecision",
    "guard_text",
    "load_policy",
    "redact_text",
    "scan_text",
]
