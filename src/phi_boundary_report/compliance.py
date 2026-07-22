from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

import yaml

from .api import GuardDecision, guard_text
from .policy import Policy


PHI_STATUSES = frozenset({"non_phi", "synthetic", "deidentified", "real_phi"})
DEFAULT_ALLOWED_LOGGING = frozenset({"none", "metadata_only", "redacted_only"})
DEFAULT_ALLOWED_STORAGE = frozenset({"none"})


@dataclass(frozen=True)
class ComplianceContext:
    phi_status: str
    vendor: str
    service: str
    endpoint: str
    model: str
    feature: str
    environment: str = "development"
    region: str | None = None
    logging: str = "metadata_only"
    storage: str = "none"
    purpose: str = "model_call"

    def to_dict(self) -> dict[str, Any]:
        return {
            "phi_status": self.phi_status,
            "vendor": self.vendor,
            "service": self.service,
            "endpoint": self.endpoint,
            "model": self.model,
            "feature": self.feature,
            "environment": self.environment,
            "region": self.region,
            "logging": self.logging,
            "storage": self.storage,
            "purpose": self.purpose,
        }


@dataclass(frozen=True)
class EnvironmentPolicy:
    require_redacted_logging: bool = False
    require_audit: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "require_redacted_logging": self.require_redacted_logging,
            "require_audit": self.require_audit,
        }


@dataclass(frozen=True)
class ServiceProfile:
    service_id: str
    vendor: str
    service: str
    covered_service: bool
    baa_executed: bool
    allowed_phi_status: frozenset[str]
    model_patterns: tuple[str, ...]
    denied_model_patterns: tuple[str, ...]
    allowed_features: frozenset[str]
    denied_features: frozenset[str]
    allowed_logging: frozenset[str]
    allowed_storage: frozenset[str]
    allow_preview: bool = False
    deny_reason: str = ""
    notes: str = ""

    def matches(self, context: ComplianceContext) -> bool:
        if self.vendor != context.vendor or self.service != context.service:
            return False
        return any(fnmatchcase(context.model, pattern) for pattern in self.model_patterns)

    def model_is_denied(self, model: str) -> bool:
        if not self.allow_preview and _looks_preview(model):
            return True
        return any(fnmatchcase(model, pattern) for pattern in self.denied_model_patterns)

    def to_dict(self) -> dict[str, Any]:
        return {
            "service_id": self.service_id,
            "vendor": self.vendor,
            "service": self.service,
            "covered_service": self.covered_service,
            "baa_executed": self.baa_executed,
            "allowed_phi_status": sorted(self.allowed_phi_status),
            "model_patterns": list(self.model_patterns),
            "denied_model_patterns": list(self.denied_model_patterns),
            "allowed_features": sorted(self.allowed_features),
            "denied_features": sorted(self.denied_features),
            "allowed_logging": sorted(self.allowed_logging),
            "allowed_storage": sorted(self.allowed_storage),
            "allow_preview": self.allow_preview,
            "deny_reason": self.deny_reason,
            "notes": self.notes,
        }


@dataclass(frozen=True)
class CompliancePolicy:
    version: int
    default_action: str
    phi_status_requires_baa: dict[str, bool]
    environments: dict[str, EnvironmentPolicy]
    services: tuple[ServiceProfile, ...]

    def match_service(self, context: ComplianceContext) -> ServiceProfile | None:
        for service in self.services:
            if service.matches(context):
                return service
        return None


@dataclass(frozen=True)
class ComplianceDecision:
    context: ComplianceContext
    text_decision: GuardDecision
    service_id: str | None
    compliance_allowed: bool
    should_block: bool
    block_reasons: list[str]
    warnings: list[str]
    required_actions: list[str]
    redacted_text: str
    audit: dict[str, Any]

    def to_dict(self, include_phi: bool = False) -> dict[str, Any]:
        return {
            "context": self.context.to_dict(),
            "text_decision": self.text_decision.to_dict() if include_phi else _safe_text_decision(self.text_decision),
            "service_id": self.service_id,
            "compliance_allowed": self.compliance_allowed,
            "should_block": self.should_block,
            "block_reasons": list(self.block_reasons),
            "warnings": list(self.warnings),
            "required_actions": list(self.required_actions),
            "redacted_text": self.redacted_text,
            "audit": dict(self.audit),
        }


def load_compliance_policy(path: Path) -> CompliancePolicy:
    with path.open("r", encoding="utf-8") as handle:
        raw = yaml.safe_load(handle)

    if not isinstance(raw, dict):
        raise ValueError(f"{path}: compliance policy must be a YAML object")
    if raw.get("version") != 1:
        raise ValueError(f"{path}: compliance policy version must be 1")

    default_action = raw.get("default_action", "block")
    if default_action not in {"block", "allow"}:
        raise ValueError(f"{path}: default_action must be 'block' or 'allow'")

    return CompliancePolicy(
        version=1,
        default_action=default_action,
        phi_status_requires_baa=_parse_phi_statuses(path, raw.get("phi_statuses", {})),
        environments=_parse_environments(path, raw.get("environments", {})),
        services=_parse_services(path, raw.get("services", {})),
    )


def guard_compliance(
    text: str,
    layer: str,
    phi_policy: Policy,
    compliance_policy: CompliancePolicy,
    context: ComplianceContext,
) -> ComplianceDecision:
    _validate_context(context)

    text_decision = guard_text(text, layer=layer, policy=phi_policy, mode="block_on_violation")
    service = compliance_policy.match_service(context)
    env_policy = compliance_policy.environments.get(context.environment, EnvironmentPolicy())

    block_reasons: list[str] = []
    warnings: list[str] = []
    required_actions: list[str] = []

    if text_decision.should_block:
        block_reasons.append("phi_policy_violation")
        required_actions.append("Redact or remove PHI before using this context layer.")

    if not text_decision.has_phi:
        if service is None and compliance_policy.default_action == "block":
            warnings.append("unknown_service_profile")
        return _decision(
            context=context,
            text_decision=text_decision,
            service=service,
            block_reasons=block_reasons,
            warnings=warnings,
            required_actions=required_actions,
            env_policy=env_policy,
        )

    if service is None:
        if compliance_policy.default_action == "block":
            block_reasons.append("unknown_service_profile")
            required_actions.append("Add an approved service profile before sending PHI.")
        else:
            warnings.append("unknown_service_profile")
    else:
        _evaluate_service(
            context=context,
            service=service,
            policy=compliance_policy,
            env_policy=env_policy,
            block_reasons=block_reasons,
            required_actions=required_actions,
        )

    return _decision(
        context=context,
        text_decision=text_decision,
        service=service,
        block_reasons=block_reasons,
        warnings=warnings,
        required_actions=required_actions,
        env_policy=env_policy,
    )


def _evaluate_service(
    context: ComplianceContext,
    service: ServiceProfile,
    policy: CompliancePolicy,
    env_policy: EnvironmentPolicy,
    block_reasons: list[str],
    required_actions: list[str],
) -> None:
    requires_baa = policy.phi_status_requires_baa.get(context.phi_status, True)
    if context.phi_status not in service.allowed_phi_status:
        block_reasons.append("phi_status_not_allowed_for_service")
        required_actions.append("Use a service profile that explicitly allows this PHI status.")
    if requires_baa and not service.covered_service:
        block_reasons.append("phi_status_requires_baa_but_service_is_not_covered")
        required_actions.append("Use a BAA-covered service before sending PHI.")
    if requires_baa and not service.baa_executed:
        block_reasons.append("phi_status_requires_baa_but_baa_is_not_confirmed")
        required_actions.append("Confirm that the BAA is executed for this service profile.")
    if service.model_is_denied(context.model):
        block_reasons.append("model_matches_denied_pattern")
        required_actions.append("Switch to an approved GA model or redact PHI before the call.")
    if context.feature in service.denied_features:
        block_reasons.append("feature_denied_for_service")
        required_actions.append("Disable the denied feature or route to an approved service profile.")
    if service.allowed_features and context.feature not in service.allowed_features:
        block_reasons.append("feature_not_allowed_for_service")
        required_actions.append("Use a feature explicitly allowed for PHI in this service profile.")
    if context.logging not in service.allowed_logging:
        block_reasons.append("logging_mode_not_allowed_for_phi")
        required_actions.append("Use metadata_only or redacted_only logging for PHI workflows.")
    if context.storage not in service.allowed_storage:
        block_reasons.append("storage_mode_not_allowed_for_phi")
        required_actions.append("Use an approved storage mode for PHI workflows.")
    if env_policy.require_redacted_logging and context.logging == "raw":
        block_reasons.append("environment_requires_redacted_logging")
        required_actions.append("Production PHI workflows must not use raw logging.")


def _decision(
    context: ComplianceContext,
    text_decision: GuardDecision,
    service: ServiceProfile | None,
    block_reasons: list[str],
    warnings: list[str],
    required_actions: list[str],
    env_policy: EnvironmentPolicy,
) -> ComplianceDecision:
    unique_reasons = _dedupe(block_reasons)
    unique_actions = _dedupe(required_actions)
    audit = {
        "has_phi": text_decision.has_phi,
        "finding_count": len(text_decision.findings),
        "service_matched": service is not None,
        "service_id": service.service_id if service else None,
        "environment_policy": env_policy.to_dict(),
        "decision_basis": "deterministic_policy",
    }
    return ComplianceDecision(
        context=context,
        text_decision=text_decision,
        service_id=service.service_id if service else None,
        compliance_allowed=not unique_reasons,
        should_block=bool(unique_reasons),
        block_reasons=unique_reasons,
        warnings=_dedupe(warnings),
        required_actions=unique_actions,
        redacted_text=text_decision.redacted_text,
        audit=audit,
    )


def _parse_phi_statuses(path: Path, raw: Any) -> dict[str, bool]:
    if not isinstance(raw, dict) or not raw:
        raise ValueError(f"{path}: compliance policy must define phi_statuses")
    parsed: dict[str, bool] = {}
    for status, value in raw.items():
        if status not in PHI_STATUSES:
            raise ValueError(f"{path}: unsupported phi_status {status!r}")
        if not isinstance(value, dict):
            raise ValueError(f"{path}: phi_status {status!r} must be an object")
        requires_baa = value.get("requires_baa")
        if not isinstance(requires_baa, bool):
            raise ValueError(f"{path}: phi_status {status!r} requires boolean requires_baa")
        parsed[status] = requires_baa
    return parsed


def _parse_environments(path: Path, raw: Any) -> dict[str, EnvironmentPolicy]:
    if not isinstance(raw, dict):
        raise ValueError(f"{path}: environments must be an object")
    environments: dict[str, EnvironmentPolicy] = {}
    for name, value in raw.items():
        if not isinstance(name, str) or not name:
            raise ValueError(f"{path}: environment names must be non-empty strings")
        if not isinstance(value, dict):
            raise ValueError(f"{path}: environment {name!r} must be an object")
        require_redacted_logging = value.get("require_redacted_logging", False)
        require_audit = value.get("require_audit", False)
        if not isinstance(require_redacted_logging, bool) or not isinstance(require_audit, bool):
            raise ValueError(f"{path}: environment {name!r} boolean fields are invalid")
        environments[name] = EnvironmentPolicy(
            require_redacted_logging=require_redacted_logging,
            require_audit=require_audit,
        )
    return environments


def _parse_services(path: Path, raw: Any) -> tuple[ServiceProfile, ...]:
    if not isinstance(raw, dict) or not raw:
        raise ValueError(f"{path}: compliance policy must define at least one service")
    services = []
    for service_id, value in raw.items():
        if not isinstance(service_id, str) or not service_id:
            raise ValueError(f"{path}: service profile ids must be non-empty strings")
        if not isinstance(value, dict):
            raise ValueError(f"{path}: service profile {service_id!r} must be an object")
        services.append(_parse_service(path, service_id, value))
    return tuple(services)


def _parse_service(path: Path, service_id: str, raw: dict[str, Any]) -> ServiceProfile:
    return ServiceProfile(
        service_id=service_id,
        vendor=_required_str(path, service_id, raw, "vendor"),
        service=_required_str(path, service_id, raw, "service"),
        covered_service=_required_bool(path, service_id, raw, "covered_service"),
        baa_executed=_required_bool(path, service_id, raw, "baa_executed"),
        allowed_phi_status=_as_phi_status_set(path, service_id, raw.get("allowed_phi_status", [])),
        model_patterns=tuple(_as_string_list(path, service_id, raw.get("model_patterns", ["*"]), "model_patterns")),
        denied_model_patterns=tuple(
            _as_string_list(path, service_id, raw.get("denied_model_patterns", []), "denied_model_patterns")
        ),
        allowed_features=frozenset(_as_string_list(path, service_id, raw.get("allowed_features", []), "allowed_features")),
        denied_features=frozenset(_as_string_list(path, service_id, raw.get("denied_features", []), "denied_features")),
        allowed_logging=frozenset(
            _as_string_list(path, service_id, raw.get("allowed_logging", sorted(DEFAULT_ALLOWED_LOGGING)), "allowed_logging")
        ),
        allowed_storage=frozenset(
            _as_string_list(path, service_id, raw.get("allowed_storage", sorted(DEFAULT_ALLOWED_STORAGE)), "allowed_storage")
        ),
        allow_preview=_optional_bool(path, service_id, raw, "allow_preview", False),
        deny_reason=str(raw.get("deny_reason", "")),
        notes=str(raw.get("notes", "")),
    )


def _validate_context(context: ComplianceContext) -> None:
    if context.phi_status not in PHI_STATUSES:
        raise ValueError(f"unsupported phi_status {context.phi_status!r}")
    for field_name in ("vendor", "service", "endpoint", "model", "feature", "environment", "logging", "storage"):
        if not getattr(context, field_name):
            raise ValueError(f"context field {field_name!r} must be non-empty")


def _required_str(path: Path, service_id: str, raw: dict[str, Any], field_name: str) -> str:
    value = raw.get(field_name)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{path}: service profile {service_id!r} field {field_name!r} must be a non-empty string")
    return value


def _required_bool(path: Path, service_id: str, raw: dict[str, Any], field_name: str) -> bool:
    value = raw.get(field_name)
    if not isinstance(value, bool):
        raise ValueError(f"{path}: service profile {service_id!r} field {field_name!r} must be a boolean")
    return value


def _optional_bool(path: Path, service_id: str, raw: dict[str, Any], field_name: str, default: bool) -> bool:
    value = raw.get(field_name, default)
    if not isinstance(value, bool):
        raise ValueError(f"{path}: service profile {service_id!r} field {field_name!r} must be a boolean")
    return value


def _as_string_list(path: Path, service_id: str, value: Any, field_name: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ValueError(f"{path}: service profile {service_id!r} field {field_name!r} must be a string array")
    return value


def _as_phi_status_set(path: Path, service_id: str, value: Any) -> frozenset[str]:
    statuses = set(_as_string_list(path, service_id, value, "allowed_phi_status"))
    unsupported = sorted(statuses - PHI_STATUSES)
    if unsupported:
        raise ValueError(
            f"{path}: service profile {service_id!r} contains unsupported PHI status(es): {', '.join(unsupported)}"
        )
    return frozenset(statuses)


def _looks_preview(model: str) -> bool:
    lowered = model.lower()
    return any(marker in lowered for marker in ("preview", "experimental", "beta"))


def _dedupe(values: list[str]) -> list[str]:
    seen = set()
    deduped = []
    for value in values:
        if value not in seen:
            deduped.append(value)
            seen.add(value)
    return deduped


def _safe_text_decision(decision: GuardDecision) -> dict[str, Any]:
    return {
        "layer": decision.layer,
        "mode": decision.mode,
        "finding_count": len(decision.findings),
        "categories": sorted({finding.category for finding in decision.findings}),
        "has_phi": decision.has_phi,
        "has_redactions": decision.has_redactions,
        "has_violations": decision.has_violations,
        "worst_disposition": decision.worst_disposition,
        "recommended_action": decision.recommended_action,
        "should_block": decision.should_block,
        "should_redact": decision.should_redact,
    }
