# Integration Cookbook

Use this guide to choose a public SDK or CLI entrypoint without depending on
Phi internals. All repository inputs are synthetic, every recipe runs offline,
and the calling project owns its policy and trace mapping.

## Which integration path should I use?

| Need | Entry point | Output |
|---|---|---|
| Inspect an existing RAG or Agent execution | `audit_external_trace()` or `scan-external-trace` | Audit Report schema v3 plus optional Coverage v1 |
| Decide whether a model request may use a configured service | `guard_compliance()` | In-memory `ComplianceDecision` |
| Remove detected values before logging or retention | `redact_text()` or `PhiBoundaryGate.redact_for_log()` | Detector-driven transformed text |
| Review observed exposure changes between revisions | `compare-reports` plus coverage sidecars | Exposure Diff v1 and Coverage Diff v1 |

These paths compose but do not replace one another. Guard is an online decision;
Audit and Compare are observational; Redact only replaces detected spans.

## A. Audit an existing Agent trace

Choose Audit when a workflow already emits JSONL and you need to inspect user
input, retrieved context, tool output, assembled model input, and provider-bound
destinations.

From the repository root, run the complete SDK example:

```bash
PYTHONPATH=src python3 examples/integrations/rag_agent_trace_audit.py \
  --out-dir /tmp/phi-rag-agent-audit \
  --report-values hashed
```

It uses the synthetic
[`generic_agent_run.jsonl`](../samples/external_traces/generic_agent_run.jsonl),
the caller-defined Mapping v1
[`generic_agent.yml`](../samples/trace_mappings/generic_agent.yml), and the
sample PHI policy. The mapping selects external fields and assigns supported Phi
layers; it is not tied to an Agent framework.

The same path is available from the CLI:

```bash
PYTHONPATH=src python3 -m phi_boundary_gate.cli scan-external-trace \
  --input samples/external_traces/generic_agent_run.jsonl \
  --mapping samples/trace_mappings/generic_agent.yml \
  --policy samples/policies/default.yml \
  --out /tmp/phi-rag-agent-audit/audit-report.md \
  --json /tmp/phi-rag-agent-audit/audit-report.json \
  --diagnostics /tmp/phi-rag-agent-audit/mapping-diagnostics.json \
  --report-values hashed \
  --coverage-json /tmp/phi-rag-agent-audit/coverage.json \
  --coverage-markdown /tmp/phi-rag-agent-audit/coverage.md \
  --expect-layer user_message \
  --expect-layer rag_context \
  --expect-layer tool_output \
  --expect-layer model_input
```

Expected result for the committed fixture: Audit Report schema v3, 15 findings,
observations for all six supported source layers, one or more provider
destinations, and no coverage warning for the four explicit expected layers.
The report contains hashed matched values; the input trace remains raw synthetic
data and should not be treated as a safe artifact pattern for real PHI.

Common mistakes include mapping a provider sink as a source layer instead of a
`model_provider` destination, assuming optional mapping fields were observed,
and treating zero findings as proof that capture was complete. Review both the
mapping diagnostics and Coverage warnings.

This proves that the supplied normalized content was mapped, scanned, and
reported. It cannot prove that the external runtime emitted every event, that
detectors found every sensitive value, or that the workflow is compliant.

## B. Guard a provider-bound request

Choose Guard immediately before an application-owned model client. The example
keeps the client behind a small protocol, performs no network request, and uses
only fictional service/model identifiers:

```bash
PYTHONPATH=src python3 examples/integrations/provider_boundary_preflight.py
```

Expected result: the configured fictional route is allowed and calls the
offline client once; the unlisted route is blocked and never reaches it. Both
requests have zero detected findings, demonstrating that the `real_phi`
declaration—not a fabricated detector match—causes service evaluation.

The essential SDK call is:

```python
decision = gate.guard_compliance(
    request_text,
    layer="model_input",
    context=context,
    enforce_declared_phi=True,
)
if decision.should_block:
    raise RuntimeError(decision.block_reasons)

# Preserve full semantics only after the route is allowed.
model_client.generate(request_text)
```

The calling project supplies both its PHI policy and compliance policy. See
[`provider_boundary_policy.yml`](../examples/integrations/provider_boundary_policy.yml)
for the tutorial shape; its coverage and BAA flags are invented fixtures, not
claims about a real service.

Original request, explicit redaction, and blocking are separate choices:

- Send `request_text` only when the application needs its full semantics and
  the configured route is allowed.
- Send `decision.redacted_text` only when the application deliberately chooses
  detector-driven redaction and accepts its limits.
- Send nothing when `decision.should_block` is true.

Keep `enforce_declared_phi=False` to retain the pre-v0.8.5 behavior. When it is
true, only `phi_status="real_phi"` bypasses the no-finding early return. A
`default_action: block` policy blocks an unknown service; `allow` records the
unknown profile as a warning.

Common mistakes are logging the complete decision, treating the tutorial policy
as real approval, or expecting `endpoint`, `region`, and `purpose` to match a
service profile. Policy v1 records those fields but matches only vendor, service,
and model pattern before evaluating the existing eligibility rules.

This proves deterministic enforcement of caller-supplied facts. It cannot
discover a contract, verify a BAA, certify a provider, or establish that a
declared payload contains or does not contain PHI.

## C. Redact logs and reports

Choose Redact when the destination should receive a transformed copy of text.
Use the same project policy that governs the destination layer:

```python
from phi_boundary_gate import PhiBoundaryGate

gate = PhiBoundaryGate.from_project()
redacted = gate.redact_for_log("debug member_id=MBR-SYN-8842")
assert redacted == "debug member_id=[REDACTED_MEMBER_ID]"
```

For report retention, select the value mode explicitly:

```python
result = gate.audit_external_trace(
    "raw-agent-events.jsonl",
    mapping="config/phi-trace-map.yml",
    report_value_mode="redacted",  # or "hashed"
)
```

Expected result: spans found by configured detectors are replaced in text, and
report finding values follow the selected storage mode. The necessary inputs
are a PHI policy and, for external traces, a Mapping v1 file.

Do not assume an object is log-safe merely because it is named `redacted_text`
or `to_safe_dict()`. With no finding, detector-driven `redacted_text` equals the
original input. Prefer a structural whitelist:

```python
log_metadata = {
    "finding_count": len(decision.findings),
    "categories": sorted({item.category for item in decision.findings}),
    "should_block": decision.should_block,
}
```

Common mistakes are logging raw traces alongside a redacted report, retaining
mapping diagnostics in an unsuitable location, and assuming missed values were
removed. Redaction proves replacement of supplied detected spans; it cannot
prove that arbitrary text contains no remaining sensitive information.

## D. Compare observed exposure between revisions

Choose Compare for an advisory PR review. Build reports and independent coverage
sidecars from two synthetic revisions, then compare them:

```bash
mkdir -p /tmp/phi-integration-compare

PYTHONPATH=src python3 -m phi_boundary_gate.cli scan-trace \
  --trace samples/traces/exposure_diff_baseline.jsonl \
  --policy samples/policies/default.yml \
  --out /tmp/phi-integration-compare/before.md \
  --json /tmp/phi-integration-compare/before.json \
  --report-values hashed \
  --coverage-json /tmp/phi-integration-compare/before-coverage.json \
  --expect-layer model_input \
  --expect-layer tool_output

PYTHONPATH=src python3 -m phi_boundary_gate.cli scan-trace \
  --trace samples/traces/exposure_diff_candidate.jsonl \
  --policy samples/policies/exposure_diff_candidate.yml \
  --out /tmp/phi-integration-compare/after.md \
  --json /tmp/phi-integration-compare/after.json \
  --report-values hashed \
  --coverage-json /tmp/phi-integration-compare/after-coverage.json \
  --expect-layer model_input \
  --expect-layer tool_output

PYTHONPATH=src python3 -m phi_boundary_gate.cli compare-reports \
  --before /tmp/phi-integration-compare/before.json \
  --after /tmp/phi-integration-compare/after.json \
  --out /tmp/phi-integration-compare/exposure-diff.md \
  --json /tmp/phi-integration-compare/exposure-diff.json \
  --review-summary /tmp/phi-integration-compare/review-summary.md \
  --before-coverage /tmp/phi-integration-compare/before-coverage.json \
  --after-coverage /tmp/phi-integration-compare/after-coverage.json \
  --coverage-review /tmp/phi-integration-compare/coverage-review.md \
  --coverage-diff-json /tmp/phi-integration-compare/coverage-diff.json
```

The inputs are Audit Report schema v3 plus paired Coverage v1 evidence. The
outputs retain Exposure Diff schema v1 and an independent Coverage Diff
sidecar. The command remains advisory and returns success for observed
regressions; a repository may publish `review-summary.md` to its PR summary
without making it a new Required Check.

Common mistakes are comparing raw traces instead of reports, ignoring
configuration-comparability warnings, and interpreting a narrower observed
scope as reduced risk. Compare proves structural differences in the two supplied
observations. It cannot attribute causality to an Agent revision, measure true
PHI recall, prove elimination, or override Guard decisions.
