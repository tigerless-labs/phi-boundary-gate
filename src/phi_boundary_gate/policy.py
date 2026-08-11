from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .exceptions import PolicyError
from .trace import SUPPORTED_LAYERS, supported_layers_text


@dataclass(frozen=True)
class PolicyDecision:
    disposition: str
    risk: str
    rule: str
    redaction: str


@dataclass(frozen=True)
class CategoryPolicy:
    description: str
    high_risk: bool
    deny_layers: frozenset[str]
    redact_layers: frozenset[str]
    allow_layers: frozenset[str]
    redaction: str


@dataclass(frozen=True)
class Policy:
    version: int
    categories: dict[str, CategoryPolicy]

    def decide(self, category: str, layer: str) -> PolicyDecision:
        category_policy = self.categories.get(category)
        if category_policy is None:
            return PolicyDecision(
                disposition="allowed",
                risk="unknown",
                rule=f"No policy configured for category {category!r}.",
                redaction="[REDACTED]",
            )

        risk = "high" if category_policy.high_risk else "standard"
        if layer in category_policy.deny_layers:
            return PolicyDecision(
                disposition="violation",
                risk=risk,
                rule=f"{category} is denied in {layer}.",
                redaction=category_policy.redaction,
            )
        if layer in category_policy.redact_layers:
            return PolicyDecision(
                disposition="redact",
                risk=risk,
                rule=f"{category} requires redaction in {layer}.",
                redaction=category_policy.redaction,
            )
        if category_policy.allow_layers and layer in category_policy.allow_layers:
            rule = f"{category} is explicitly allowed in {layer}."
        else:
            rule = f"{category} has no layer-specific restriction for {layer}."
        return PolicyDecision(
            disposition="allowed",
            risk=risk,
            rule=rule,
            redaction=category_policy.redaction,
        )


def load_policy(path: Path) -> Policy:
    with path.open("r", encoding="utf-8") as handle:
        try:
            raw = yaml.safe_load(handle)
        except yaml.YAMLError as exc:
            raise PolicyError(f"{path}: invalid YAML: {exc}") from exc

    if not isinstance(raw, dict):
        raise PolicyError(f"{path}: policy must be a YAML object")
    if raw.get("version") != 1:
        raise PolicyError(f"{path}: policy version must be 1")

    raw_categories = raw.get("categories")
    if not isinstance(raw_categories, dict) or not raw_categories:
        raise PolicyError(f"{path}: policy must define at least one category")

    categories = {}
    for name, value in raw_categories.items():
        if not isinstance(name, str) or not name:
            raise PolicyError(f"{path}: category names must be non-empty strings")
        categories[name] = _parse_category_policy(path, name, value)
    return Policy(version=1, categories=categories)


def _parse_category_policy(path: Path, name: str, raw: Any) -> CategoryPolicy:
    if not isinstance(raw, dict):
        raise PolicyError(f"{path}: category {name!r} must be an object")

    description = raw.get("description", "")
    if not isinstance(description, str):
        raise PolicyError(f"{path}: category {name!r} field 'description' must be a string")

    high_risk = raw.get("high_risk", False)
    if not isinstance(high_risk, bool):
        raise PolicyError(f"{path}: category {name!r} field 'high_risk' must be a boolean")

    redaction = raw.get("redaction")
    if not isinstance(redaction, str) or not redaction:
        raise PolicyError(f"{path}: category {name!r} must define a redaction string")

    return CategoryPolicy(
        description=description,
        high_risk=high_risk,
        deny_layers=_as_layer_set(path, name, raw.get("deny_layers", []), "deny_layers"),
        redact_layers=_as_layer_set(path, name, raw.get("redact_layers", []), "redact_layers"),
        allow_layers=_as_layer_set(path, name, raw.get("allow_layers", []), "allow_layers"),
        redaction=redaction,
    )


def _as_layer_set(path: Path, name: str, value: Any, field_name: str) -> frozenset[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise PolicyError(f"{path}: category {name!r} field {field_name!r} must be a string array")
    unsupported = sorted(set(value) - SUPPORTED_LAYERS)
    if unsupported:
        raise PolicyError(
            f"{path}: category {name!r} field {field_name!r} contains unsupported layer(s): "
            f"{', '.join(unsupported)}; expected one of: {supported_layers_text()}"
        )
    return frozenset(value)
