from __future__ import annotations

import hashlib
import json
from typing import Any

from .detectors import RULES
from .policy import Policy
from .presidio_detector import DEFAULT_PRESIDIO_ENTITIES, PRESIDIO_CATEGORY_MAP


FINGERPRINT_VERSION = 1


def build_audit_context(
    policy: Policy,
    *,
    enable_presidio: bool,
    semantic_enabled: bool,
    semantic_resolver_id: str | None = None,
) -> dict[str, Any]:
    """Describe effective audit configuration without retaining caller-supplied identifiers."""

    if semantic_resolver_id is not None and not semantic_enabled:
        raise ValueError("semantic_resolver_id requires an enabled semantic_resolver")
    if semantic_resolver_id is not None:
        if not isinstance(semantic_resolver_id, str) or not semantic_resolver_id.strip():
            raise ValueError("semantic_resolver_id must be a non-empty stable identifier")
        semantic_resolver_fingerprint = _text_fingerprint(semantic_resolver_id)
    else:
        semantic_resolver_fingerprint = None

    presidio_configuration = "unknown" if enable_presidio else "not_applicable"
    return {
        "fingerprint_version": FINGERPRINT_VERSION,
        "policy_fingerprint": _json_fingerprint(_effective_policy(policy)),
        "detector_fingerprint": _json_fingerprint(_effective_detector_configuration(enable_presidio)),
        "presidio_enabled": enable_presidio,
        "presidio_configuration": presidio_configuration,
        "semantic_enabled": semantic_enabled,
        "semantic_resolver_fingerprint": semantic_resolver_fingerprint,
        "semantic_configuration": (
            "identified"
            if semantic_enabled and semantic_resolver_fingerprint is not None
            else "unknown"
            if semantic_enabled
            else "not_applicable"
        ),
    }


def _effective_policy(policy: Policy) -> dict[str, Any]:
    return {
        "version": policy.version,
        "categories": {
            name: {
                "high_risk": category.high_risk,
                "deny_layers": sorted(category.deny_layers),
                "redact_layers": sorted(category.redact_layers),
                "allow_layers": sorted(category.allow_layers),
                "redaction": category.redaction,
            }
            for name, category in sorted(policy.categories.items())
        },
    }


def _effective_detector_configuration(enable_presidio: bool) -> dict[str, Any]:
    rules = [
        {
            "category": rule.category,
            "pattern": rule.pattern.pattern,
            "flags": rule.pattern.flags,
            "reason": rule.reason,
            "confidence": rule.confidence,
            "group": rule.group,
        }
        for rule in RULES
    ]
    configuration: dict[str, Any] = {
        "built_in_regex_rules": rules,
        "presidio_enabled": enable_presidio,
    }
    if enable_presidio:
        configuration["presidio"] = {
            "language": "en",
            "entities": list(DEFAULT_PRESIDIO_ENTITIES),
            "category_map": dict(sorted(PRESIDIO_CATEGORY_MAP.items())),
            "external_analyzer_configuration": "unknown",
        }
    return configuration


def _json_fingerprint(value: Any) -> str:
    canonical = json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return _text_fingerprint(canonical)


def _text_fingerprint(value: str) -> str:
    return f"sha256:{hashlib.sha256(value.encode('utf-8')).hexdigest()}"
