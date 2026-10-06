"""Provider-neutral semantic adjudication for detected PHI candidates."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, Protocol, runtime_checkable

from .detectors import Candidate

SubjectRole = Literal["patient", "member", "beneficiary", "provider", "clinician", "unknown"]
InformationRole = Literal["clinical", "diagnosis", "treatment", "claim", "payment", "insurance", "general", "unknown"]
Linkage = Literal["linked", "unlinked", "unclear"]
SemanticDisposition = Literal["likely_phi", "likely_not_phi", "uncertain"]

SUBJECT_ROLES = frozenset({"patient", "member", "beneficiary", "provider", "clinician", "unknown"})
INFORMATION_ROLES = frozenset(
    {"clinical", "diagnosis", "treatment", "claim", "payment", "insurance", "general", "unknown"}
)
LINKAGES = frozenset({"linked", "unlinked", "unclear"})
SEMANTIC_DISPOSITIONS = frozenset({"likely_phi", "likely_not_phi", "uncertain"})


@dataclass(frozen=True)
class SemanticContext:
    """The single-event context supplied to a semantic resolver.

    ``text`` and ``candidate.value`` may contain sensitive data. Resolver
    implementations are responsible for sending them only to approved systems.
    """

    text: str
    candidate: Candidate
    layer: str


@dataclass(frozen=True)
class SemanticDecision:
    subject_role: SubjectRole
    information_role: InformationRole
    linkage: Linkage
    semantic_disposition: SemanticDisposition
    confidence: float
    reason: str

    def __post_init__(self) -> None:
        _validate_enum("subject_role", self.subject_role, SUBJECT_ROLES)
        _validate_enum("information_role", self.information_role, INFORMATION_ROLES)
        _validate_enum("linkage", self.linkage, LINKAGES)
        _validate_enum("semantic_disposition", self.semantic_disposition, SEMANTIC_DISPOSITIONS)
        if isinstance(self.confidence, bool) or not isinstance(self.confidence, (int, float)):
            raise TypeError("confidence must be a number from 0 to 1")
        if not 0.0 <= float(self.confidence) <= 1.0:
            raise ValueError("confidence must be from 0 to 1")
        if not isinstance(self.reason, str) or not self.reason.strip():
            raise ValueError("reason must be a non-empty string")

    def to_dict(self) -> dict[str, Any]:
        """Return the complete SDK decision, including its concise rationale."""

        return {
            "subject_role": self.subject_role,
            "information_role": self.information_role,
            "linkage": self.linkage,
            "semantic_disposition": self.semantic_disposition,
            "confidence": float(self.confidence),
            "reason": self.reason,
        }

    def to_report_dict(self) -> dict[str, Any]:
        """Return bounded report metadata without free-form resolver output."""

        return {
            "subject_role": self.subject_role,
            "information_role": self.information_role,
            "linkage": self.linkage,
            "disposition": self.semantic_disposition,
            "confidence": float(self.confidence),
        }


@runtime_checkable
class SemanticResolver(Protocol):
    """Provider-neutral interface for single-candidate semantic adjudication."""

    def resolve(self, context: SemanticContext) -> SemanticDecision:
        ...


class NoopSemanticResolver:
    """Fail-safe resolver that preserves detector and policy behavior."""

    def resolve(self, context: SemanticContext) -> SemanticDecision:
        return SemanticDecision(
            subject_role="unknown",
            information_role="unknown",
            linkage="unclear",
            semantic_disposition="uncertain",
            confidence=0.0,
            reason="No semantic adjudication was performed.",
        )


def resolve_semantics(
    resolver: SemanticResolver,
    *,
    text: str,
    candidate: Candidate,
    layer: str,
) -> SemanticDecision:
    """Resolve a candidate and convert resolver failures to a fail-safe result."""

    try:
        decision = resolver.resolve(SemanticContext(text=text, candidate=candidate, layer=layer))
        if not isinstance(decision, SemanticDecision):
            raise TypeError("resolver must return SemanticDecision")
        return decision
    except Exception:
        # Exception details are intentionally not copied into reports or decisions:
        # provider errors can contain prompts or other sensitive input.
        return SemanticDecision(
            subject_role="unknown",
            information_role="unknown",
            linkage="unclear",
            semantic_disposition="uncertain",
            confidence=0.0,
            reason="Semantic resolver failed; existing detector and policy results were preserved.",
        )


def _validate_enum(field_name: str, value: object, allowed: frozenset[str]) -> None:
    if value not in allowed:
        choices = ", ".join(sorted(allowed))
        raise ValueError(f"{field_name} must be one of: {choices}")
