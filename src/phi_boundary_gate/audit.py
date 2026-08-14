from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .policy import Policy
from .report import ReportValueMode, build_report, render_markdown, write_json_report, write_markdown_report
from .trace import TraceEvent, load_trace


@dataclass(frozen=True)
class AuditResult:
    report: dict[str, Any]

    @property
    def summary(self) -> dict[str, Any]:
        return self.report["summary"]

    @property
    def findings(self) -> list[dict[str, Any]]:
        return self.report["findings"]

    @property
    def boundary_exposures(self) -> list[dict[str, Any]]:
        return self.report["boundary_exposures"]

    @property
    def has_findings(self) -> bool:
        return bool(self.findings)

    @property
    def has_violations(self) -> bool:
        return self.summary["by_disposition"].get("violation", 0) > 0

    def to_dict(self) -> dict[str, Any]:
        return self.report

    def to_markdown(self) -> str:
        return render_markdown(self.report)

    def write_json(self, path: Path | str) -> None:
        write_json_report(self.report, Path(path))

    def write_markdown(self, path: Path | str) -> None:
        write_markdown_report(self.report, Path(path))


def audit_events(
    events: list[TraceEvent],
    policy: Policy,
    *,
    trace_path: Path | str = "<events>",
    policy_path: Path | str = "<policy>",
    enable_presidio: bool = False,
    report_value_mode: ReportValueMode = "raw",
) -> AuditResult:
    report = build_report(
        events,
        policy,
        Path(trace_path),
        Path(policy_path),
        enable_presidio=enable_presidio,
        report_value_mode=report_value_mode,
    )
    return AuditResult(report)


def audit_trace(
    trace_path: Path | str,
    policy: Policy,
    *,
    policy_path: Path | str = "<policy>",
    enable_presidio: bool = False,
    report_value_mode: ReportValueMode = "raw",
) -> AuditResult:
    trace = load_trace(Path(trace_path))
    return audit_events(
        trace,
        policy,
        trace_path=trace_path,
        policy_path=policy_path,
        enable_presidio=enable_presidio,
        report_value_mode=report_value_mode,
    )
