from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

import yaml

from phi_boundary_gate.detectors import detect_candidates
from phi_boundary_gate.report import build_report
from phi_boundary_gate.trace import load_trace
from phi_boundary_gate.policy import load_policy


def build_trace_corpus_report(
    traces_dir: Path,
    expectations_dir: Path,
    policy_path: Path,
) -> dict[str, Any]:
    expectations = _load_expectations(expectations_dir)
    trace_reports: list[dict[str, Any]] = []
    category_totals: Counter[str] = Counter()
    layer_totals: Counter[str] = Counter()
    total_events = 0
    total_findings = 0

    for trace_path in sorted(traces_dir.glob("*.jsonl")):
        if trace_path.name.startswith("invalid_"):
            continue
        expectation = expectations.get(str(trace_path))
        if expectation is None:
            expectation = expectations.get(trace_path.name)
        if expectation is None:
            raise ValueError(f"{trace_path}: missing trace expectation")

        events = load_trace(trace_path)
        categories: Counter[str] = Counter()
        layers: Counter[str] = Counter({event.layer: 0 for event in events})
        for event in events:
            findings = detect_candidates(event.content)
            layers[event.layer] += len(findings)
            categories.update(finding.category for finding in findings)

        policy = load_policy(policy_path)
        report = build_report(events, policy, trace_path, policy_path)
        finding_count = report["summary"]["total_findings"]
        exposure_count = report["summary"]["total_boundary_exposures"]
        status, failures = _evaluate_expectation(
            expectation=expectation,
            finding_count=finding_count,
            exposure_count=exposure_count,
            categories=categories,
            layers=layers,
        )

        trace_report = {
            "trace": _display_path(trace_path),
            "kind": expectation["kind"],
            "purpose": expectation["purpose"],
            "events": len(events),
            "findings": finding_count,
            "boundary_exposures": exposure_count,
            "categories": dict(sorted(categories.items())),
            "layers": dict(sorted(layers.items())),
            "expectation_status": status,
            "expectation_failures": failures,
            "known_gaps": list(expectation.get("known_gaps", [])),
        }
        trace_reports.append(trace_report)
        category_totals.update(categories)
        layer_totals.update(layers)
        total_events += len(events)
        total_findings += finding_count

    return {
        "schema_version": 1,
        "summary": {
            "trace_count": len(trace_reports),
            "event_count": total_events,
            "finding_count": total_findings,
            "categories_seen": sorted(category_totals),
            "layers_seen": sorted(layer_totals),
            "all_expectations_passed": all(
                item["expectation_status"] == "pass" for item in trace_reports
            ),
        },
        "traces": trace_reports,
    }


def write_report(report: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _load_expectations(expectations_dir: Path) -> dict[str, dict[str, Any]]:
    expectations: dict[str, dict[str, Any]] = {}
    for path in sorted(expectations_dir.glob("*.yml")):
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError(f"{path}: expectation must be a YAML object")
        trace = raw.get("trace")
        if not isinstance(trace, str) or not trace:
            raise ValueError(f"{path}: expectation must define trace")
        expectations[trace] = raw
        expectations[Path(trace).name] = raw
    return expectations


def _display_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return str(resolved.relative_to(Path.cwd().resolve()))
    except ValueError:
        return str(path)


def _evaluate_expectation(
    *,
    expectation: dict[str, Any],
    finding_count: int,
    exposure_count: int,
    categories: Counter[str],
    layers: Counter[str],
) -> tuple[str, list[str]]:
    expected = expectation.get("expected", {})
    failures: list[str] = []
    min_findings = int(expected.get("min_findings", 0))
    max_findings = int(expected.get("max_findings", 10**9))
    min_exposures = int(expected.get("min_boundary_exposures", 0))
    if finding_count < min_findings:
        failures.append(f"finding_count {finding_count} < min_findings {min_findings}")
    if finding_count > max_findings:
        failures.append(f"finding_count {finding_count} > max_findings {max_findings}")
    if exposure_count < min_exposures:
        failures.append(f"boundary_exposures {exposure_count} < min_boundary_exposures {min_exposures}")

    missing_categories = sorted(set(expected.get("required_categories", [])) - set(categories))
    if missing_categories:
        failures.append("missing required categories: " + ", ".join(missing_categories))

    missing_layers = sorted(set(expected.get("required_layers", [])) - set(layers))
    if missing_layers:
        failures.append("missing required layers: " + ", ".join(missing_layers))

    return ("fail" if failures else "pass", failures)


def main() -> int:
    parser = argparse.ArgumentParser(description="Summarize synthetic PHI trace corpus coverage.")
    parser.add_argument("--traces", type=Path, default=Path("samples/traces"))
    parser.add_argument("--expectations", type=Path, default=Path("samples/trace_expectations"))
    parser.add_argument("--policy", type=Path, default=Path("samples/policies/default.yml"))
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    report = build_trace_corpus_report(args.traces, args.expectations, args.policy)
    write_report(report, args.out)
    return 0 if report["summary"]["all_expectations_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
