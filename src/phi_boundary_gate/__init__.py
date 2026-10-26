"""PHI boundary gating, redaction, and audit reporting."""

__version__ = "0.8.3"

from .adapters import (
    TraceAdapter,
    TraceMapping,
    build_conversion_diagnostics,
    load_external_trace,
    load_trace_mapping,
    validate_trace_mapping,
    write_conversion_diagnostics,
    write_converted_trace,
)
from .api import GuardDecision, GuardMode, ScanFinding, guard_text, redact_text, scan_text
from .audit import AuditResult, audit_events, audit_trace
from .coverage import (
    AuditCoverageResult,
    build_audit_coverage,
    render_coverage_markdown,
    write_coverage_json,
    write_coverage_markdown,
)
from .external_audit import audit_external_trace
from .exposure_diff import (
    ExposureDiffResult,
    build_review_guidance,
    compare_audit_reports,
    compare_report_files,
    load_audit_report,
    render_exposure_diff_markdown,
    render_exposure_review_summary,
    write_exposure_diff_json,
    write_exposure_diff_markdown,
    write_exposure_review_summary,
)
from .compliance import (
    ComplianceContext,
    ComplianceDecision,
    CompliancePolicy,
    ServiceProfile,
    guard_compliance,
    load_compliance_policy,
)
from .exceptions import PhiBoundaryGateError, PolicyError, ProjectConfigError, ProjectConfigNotFoundError, TraceMappingError
from .policy import load_policy
from .project import ProjectConfig, check_project_config, discover_project_config, init_project, load_project_config
from .redacted_trace import redacted_trace_events, write_redacted_trace
from .report import build_report, render_markdown, write_json_report, write_markdown_report
from .semantic import (
    InformationRole,
    Linkage,
    NoopSemanticResolver,
    SemanticContext,
    SemanticDecision,
    SemanticDisposition,
    SemanticResolver,
    SubjectRole,
)
from .sdk import PhiBoundaryGate
from .trace import TraceEvent, load_trace

__all__ = [
    "ComplianceContext",
    "ComplianceDecision",
    "CompliancePolicy",
    "GuardDecision",
    "GuardMode",
    "AuditResult",
    "AuditCoverageResult",
    "ExposureDiffResult",
    "PhiBoundaryGate",
    "ProjectConfig",
    "ScanFinding",
    "ServiceProfile",
    "SemanticContext",
    "SemanticDecision",
    "SemanticDisposition",
    "SemanticResolver",
    "NoopSemanticResolver",
    "SubjectRole",
    "InformationRole",
    "Linkage",
    "PhiBoundaryGateError",
    "PolicyError",
    "ProjectConfigError",
    "ProjectConfigNotFoundError",
    "TraceAdapter",
    "TraceEvent",
    "TraceMapping",
    "TraceMappingError",
    "audit_events",
    "audit_external_trace",
    "audit_trace",
    "compare_audit_reports",
    "compare_report_files",
    "build_review_guidance",
    "build_conversion_diagnostics",
    "build_audit_coverage",
    "build_report",
    "check_project_config",
    "discover_project_config",
    "guard_compliance",
    "guard_text",
    "init_project",
    "load_compliance_policy",
    "load_audit_report",
    "load_external_trace",
    "load_policy",
    "load_project_config",
    "load_trace_mapping",
    "load_trace",
    "redact_text",
    "redacted_trace_events",
    "render_markdown",
    "render_coverage_markdown",
    "render_exposure_diff_markdown",
    "render_exposure_review_summary",
    "scan_text",
    "validate_trace_mapping",
    "write_conversion_diagnostics",
    "write_coverage_json",
    "write_coverage_markdown",
    "write_exposure_diff_json",
    "write_exposure_diff_markdown",
    "write_exposure_review_summary",
    "write_json_report",
    "write_markdown_report",
    "write_converted_trace",
    "write_redacted_trace",
]
