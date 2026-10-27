# Coverage-Aware Exposure Diff

Coverage-Aware Exposure Diff connects the v0.8.0 Exposure Diff with the v0.8.3
Audit Coverage summary. It asks whether a change in observed PHI exposure is
accompanied by a change in the normalized trace scope that was available to the
scanner. The result is an opt-in JSON/Markdown sidecar; Audit Report schema v3
and Exposure Diff schema v1 are unchanged.

> Coverage-Aware Diff compares observed audit scope. It does not establish
> complete trace capture, causal risk changes, or HIPAA compliance.

## Design Note

The implementation consumes two already-built Coverage JSON v1 documents. It
does not rescan a trace or reconstruct coverage from findings. This keeps one
source of truth for event, layer, content-segment, expected-layer, and
blind-spot statistics.

The sidecar separates three evidence classes:

- observed scope: event/content counts, per-layer counts, and observed layer
  additions or removals;
- configured expectations: expected-layer additions/removals and changes in
  which expected layers were absent;
- unavailable evidence: missing or unsupported Coverage schema versions.

Every integer delta has a signed absolute delta. Percentage delta is relative
to the baseline; a zero baseline is represented by JSON `null` plus
`not_applicable_zero_baseline`, and rendered as `N/A`. Layers and reason codes
are drawn from bounded package vocabularies and sorted deterministically. Raw
content, report paths, trace paths, external keys, findings, matched values, and
free-form diagnostic messages are never copied.

Scope direction is `expanded`, `contracted`, `mixed`, or `unchanged`. It is a
description of observed aggregate input, not an execution-completeness or
detection-recall score. In particular:

- fewer events do not prove that events were omitted;
- a newly observed layer does not prove that detection improved;
- equal aggregate coverage does not prove equal workloads;
- no Coverage statistic measures true PHI recall.

Missing Coverage or an unsupported Coverage schema produces an `unavailable`
sidecar with `COVERAGE_COMPARISON_UNAVAILABLE`. A malformed document claiming
Coverage schema v1 remains an input error.

## CLI

First produce the normal reports and optional v0.8.3 Coverage sidecars. Then
pass both Coverage inputs to `compare-reports` and request one or both v0.8.4
sidecar outputs:

```bash
phi-boundary-gate compare-reports \
  --before baseline-report.json \
  --after candidate-report.json \
  --out exposure-diff.md \
  --json exposure-diff.json \
  --before-coverage baseline-coverage.json \
  --after-coverage candidate-coverage.json \
  --coverage-review coverage-review.md \
  --coverage-diff-json coverage-diff.json
```

`--before-coverage` and `--after-coverage` must be supplied together. Coverage
inputs also require `--coverage-review` or `--coverage-diff-json`. Omitting all
four options preserves the existing command, output files, Exposure Diff JSON,
stdout, and exit behavior.

Valid coverage warnings and observed exposure changes remain advisory and
return `0`. An unpaired option, invalid JSON, malformed Coverage v1 input, or a
real file-write failure returns `2` under the existing CLI error convention.
The command never writes a PR comment, Check Run, or GitHub Actions summary.

## SDK

The same comparison and rendering are reusable without the CLI:

```python
from phi_boundary_gate import compare_coverage_files, compare_report_files

exposure = compare_report_files("baseline-report.json", "candidate-report.json")
coverage = compare_coverage_files(
    "baseline-coverage.json",
    "candidate-coverage.json",
    exposure_diff=exposure,
)

coverage.write_json("coverage-diff.json")
coverage.write_markdown("coverage-review.md")
```

For in-memory Coverage dictionaries, use `compare_coverage(before, after,
exposure_diff=exposure)`. `CoverageDiffResult` exposes `to_dict()`,
`to_markdown()`, `write_json()`, and `write_markdown()`. Passing `None` or an
unsupported Coverage schema yields an explicit unavailable result; it never
manufactures missing metrics.

## Controlled Interpretation

Coverage reason codes describe evidence changes:

- `OBSERVATION_SCOPE_CHANGED`
- `PREVIOUSLY_OBSERVED_LAYER_MISSING`
- `NEW_LAYER_OBSERVED`
- `SCANNABLE_CONTENT_DECREASED`
- `EXPECTED_LAYER_COVERAGE_CHANGED`
- `BLIND_SPOT_DIAGNOSTICS_CHANGED`
- `COVERAGE_COMPARISON_UNAVAILABLE`
- `NO_OBSERVED_COVERAGE_CHANGE`

Exposure interpretation uses fixed templates:

- exposure decreases with contracted coverage: the observed decrease may be
  affected by narrower input scope and is not proof of improved privacy;
- exposure increases with expanded coverage: the observed increase may be
  affected by broader observation and is not proof of worse Agent behavior;
- exposure changes with unchanged aggregate coverage: the compared coverage
  statistics are stable, but workload, recall, trace completeness, and actual
  risk conditions may still differ;
- unavailable coverage: preserve the Exposure Diff and make no coverage-based
  inference.

No template creates a compliance PASS/FAIL result or overrides a Guard,
Disposition, policy, Compliance Decision, Exposure Diff, or CI status.

## Synthetic Walkthrough: Why Fewer Exposures Are Not Proof of Lower Risk

This in-memory walkthrough creates a baseline audit with three observed layers
and a candidate audit with only one. Both inputs are synthetic.

```python
from pathlib import Path

from phi_boundary_gate import (
    TraceEvent,
    build_audit_coverage,
    compare_audit_reports,
    compare_coverage,
    load_policy,
)
from phi_boundary_gate.report import build_report


def event(event_id, layer, content):
    return TraceEvent(
        event_id=event_id,
        timestamp="2026-10-27T00:00:00Z",
        layer=layer,
        content=content,
        source={"type": "synthetic"},
        destinations=[{"layer": "model_provider"}],
    )


baseline_events = [
    event("base-1", "user_message", "member_id=MBR-SYN-41001"),
    event("base-2", "tool_output", "claim_id=CLM-SYN-41001"),
    event("base-3", "model_input", "MRN: SYN-41001"),
]
candidate_events = [
    event("candidate-1", "user_message", "member_id=MBR-SYN-42001"),
]

policy = load_policy("samples/policies/default.yml")
baseline_report = build_report(
    baseline_events, policy, Path("baseline.jsonl"), Path("policy.yml"),
    report_value_mode="redacted",
)
candidate_report = build_report(
    candidate_events, policy, Path("candidate.jsonl"), Path("policy.yml"),
    report_value_mode="redacted",
)

baseline_coverage = build_audit_coverage(
    baseline_events,
    expected_layers=["user_message", "tool_output", "model_input"],
)
candidate_coverage = build_audit_coverage(
    candidate_events,
    expected_layers=["user_message", "tool_output", "model_input"],
)

exposure = compare_audit_reports(baseline_report, candidate_report)
review = compare_coverage(
    baseline_coverage.to_dict(),
    candidate_coverage.to_dict(),
    exposure_diff=exposure,
)

exposure.write_json("exposure-diff.json")
review.write_json("coverage-diff.json")
review.write_markdown("coverage-review.md")
```

The candidate has fewer exposure groups, events, scannable segments, and
observed layers. The controlled interpretation reports
`OBSERVED_EXPOSURE_DECREASE_WITH_NARROWER_SCOPE`. It does not say that PHI risk
fell: the candidate audit simply observed less input, including no
`tool_output` or `model_input` events. An investigator must establish why the
scope changed before making any risk claim.

## JSON Sidecar Stability

Coverage-Aware Diff schema v1 is independent of Coverage JSON v1, Audit Report
schema v3, and Exposure Diff schema v1. Its top-level fields are:

- `schema_version`: `1`
- `analysis_type`: `advisory_coverage_aware_exposure_diff`
- `status`: `available` or `unavailable`
- `reason_codes`: bounded coverage evidence codes
- `coverage_comparison`: aggregate deltas and evidence changes, or an explicit
  unavailable state
- `exposure_interpretation`: aggregate exposure direction, coverage direction,
  fixed reason codes, and fixed messages
- `limitations`: the fixed coverage-aware disclaimer

Future Coverage schemas are not guessed into the v1 comparison. They remain
unavailable until an explicit compatibility rule is implemented and tested.
