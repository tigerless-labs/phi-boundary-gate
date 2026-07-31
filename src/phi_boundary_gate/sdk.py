from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .api import GuardDecision, GuardMode, ScanFinding, guard_text, redact_text, scan_text
from .compliance import ComplianceContext, ComplianceDecision, CompliancePolicy, guard_compliance
from .policy import Policy, load_policy
from .project import ProjectConfig, discover_project_config


@dataclass(frozen=True)
class PhiBoundaryGate:
    policy: Policy
    compliance_policy: CompliancePolicy | None = None
    enable_presidio: bool = False
    project_config: ProjectConfig | None = None

    @classmethod
    def from_policy_file(
        cls,
        policy_path: Path | str,
        *,
        compliance_policy: CompliancePolicy | None = None,
        enable_presidio: bool = False,
    ) -> "PhiBoundaryGate":
        return cls(
            policy=load_policy(Path(policy_path)),
            compliance_policy=compliance_policy,
            enable_presidio=enable_presidio,
        )

    @classmethod
    def from_project(cls, start: Path | str | None = None) -> "PhiBoundaryGate":
        config = discover_project_config(Path(start) if start is not None else None)
        return cls(
            policy=config.load_policy(),
            compliance_policy=config.load_compliance_policy(),
            enable_presidio=config.enable_presidio,
            project_config=config,
        )

    def scan(self, text: str, layer: str) -> list[ScanFinding]:
        return scan_text(text, layer, self.policy, enable_presidio=self.enable_presidio)

    def guard(self, text: str, layer: str, mode: GuardMode = "report_only") -> GuardDecision:
        return guard_text(
            text,
            layer=layer,
            policy=self.policy,
            mode=mode,
            enable_presidio=self.enable_presidio,
        )

    def guard_model_input(self, text: str, mode: GuardMode = "block_on_violation") -> GuardDecision:
        return self.guard(text, layer="model_input", mode=mode)

    def redact_for_layer(self, text: str, layer: str) -> str:
        return redact_text(text, self.scan(text, layer))

    def redact_for_log(self, text: str) -> str:
        return self.redact_for_layer(text, "debug_log")

    def guard_compliance(
        self,
        text: str,
        layer: str,
        context: ComplianceContext,
        *,
        compliance_policy: CompliancePolicy | None = None,
    ) -> ComplianceDecision:
        policy = compliance_policy or self.compliance_policy
        if policy is None:
            raise ValueError(
                "no compliance policy configured; pass compliance_policy or run from a project config "
                "with 'compliance_policy'"
            )
        return guard_compliance(
            text,
            layer=layer,
            phi_policy=self.policy,
            compliance_policy=policy,
            context=context,
            enable_presidio=self.enable_presidio,
        )
