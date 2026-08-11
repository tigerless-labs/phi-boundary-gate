from __future__ import annotations

import json
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from typing import Any

from .compliance import CompliancePolicy, load_compliance_policy
from .exceptions import ProjectConfigError, ProjectConfigNotFoundError
from .policy import Policy, load_policy


CONFIG_DIR = ".phi-boundary-gate"
CONFIG_FILE = "config.json"
DEFAULT_POLICY_PATH = "config/phi-policy.yml"
DEFAULT_COMPLIANCE_POLICY_PATH = "config/phi-compliance-policy.yml"


@dataclass(frozen=True)
class ProjectConfig:
    root: Path
    config_path: Path
    policy_path: Path
    compliance_policy_path: Path | None = None
    enable_presidio: bool = False

    def load_policy(self) -> Policy:
        return load_policy(self.policy_path)

    def load_compliance_policy(self) -> CompliancePolicy | None:
        if self.compliance_policy_path is None:
            return None
        return load_compliance_policy(self.compliance_policy_path)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "policy": _as_config_path(self.root, self.policy_path),
            "enable_presidio": self.enable_presidio,
        }
        if self.compliance_policy_path is not None:
            payload["compliance_policy"] = _as_config_path(self.root, self.compliance_policy_path)
        return payload


def init_project(
    root: Path,
    *,
    policy_path: Path | None = None,
    compliance_policy_path: Path | None = None,
    force: bool = False,
) -> ProjectConfig:
    root = root.resolve()
    policy_path = _resolve_project_path(root, policy_path or Path(DEFAULT_POLICY_PATH))
    compliance_policy_path = _resolve_project_path(
        root,
        compliance_policy_path or Path(DEFAULT_COMPLIANCE_POLICY_PATH),
    )
    config_path = root / CONFIG_DIR / CONFIG_FILE

    _write_template("phi-policy.yml", policy_path, force=force)
    _write_template("phi-compliance-policy.yml", compliance_policy_path, force=force)

    config = ProjectConfig(
        root=root,
        config_path=config_path,
        policy_path=policy_path,
        compliance_policy_path=compliance_policy_path,
    )
    _write_json(config_path, config.to_dict(), force=force)
    return config


def discover_project_config(start: Path | None = None) -> ProjectConfig:
    start_path = (start or Path.cwd()).resolve()
    for root in (start_path, *start_path.parents):
        config_path = root / CONFIG_DIR / CONFIG_FILE
        if config_path.is_file():
            return load_project_config(config_path)
    raise ProjectConfigNotFoundError(
        f"no {CONFIG_DIR}/{CONFIG_FILE} found from {start_path}; run `phi-boundary-gate init` first"
    )


def load_project_config(config_path: Path) -> ProjectConfig:
    config_path = config_path.resolve()
    root = config_path.parent.parent
    try:
        raw = json.loads(config_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ProjectConfigError(f"{config_path}: invalid JSON: {exc.msg}") from exc
    if not isinstance(raw, dict):
        raise ProjectConfigError(f"{config_path}: project config must be a JSON object")

    policy_raw = raw.get("policy")
    if not isinstance(policy_raw, str) or not policy_raw:
        raise ProjectConfigError(f"{config_path}: field 'policy' must be a non-empty string")

    compliance_raw = raw.get("compliance_policy")
    if compliance_raw is not None and (not isinstance(compliance_raw, str) or not compliance_raw):
        raise ProjectConfigError(f"{config_path}: field 'compliance_policy' must be a non-empty string when present")

    enable_presidio = raw.get("enable_presidio", False)
    if not isinstance(enable_presidio, bool):
        raise ProjectConfigError(f"{config_path}: field 'enable_presidio' must be a boolean")

    return ProjectConfig(
        root=root,
        config_path=config_path,
        policy_path=_resolve_project_path(root, Path(policy_raw)),
        compliance_policy_path=_resolve_project_path(root, Path(compliance_raw)) if compliance_raw else None,
        enable_presidio=enable_presidio,
    )


def check_project_config(start: Path | None = None) -> ProjectConfig:
    config = discover_project_config(start)
    config.load_policy()
    if config.compliance_policy_path is not None:
        config.load_compliance_policy()
    return config


def _write_template(template_name: str, path: Path, *, force: bool) -> None:
    if path.exists() and not force:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    template = files("phi_boundary_gate").joinpath("templates", template_name)
    path.write_text(template.read_text(encoding="utf-8"), encoding="utf-8")


def _write_json(path: Path, payload: dict[str, Any], *, force: bool) -> None:
    if path.exists() and not force:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _resolve_project_path(root: Path, path: Path) -> Path:
    if path.is_absolute():
        return path
    return (root / path).resolve()


def _as_config_path(root: Path, path: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path)
