# Release Checklist

Use this checklist before creating a Git tag that publishes a PyPI release.

## One-Time PyPI Setup

Configure PyPI Trusted Publishing before the first release:

1. Create or sign in to a TestPyPI account.
2. Register a pending publisher on TestPyPI:
   - project: `phi-boundary-gate`
   - owner/repo: `tigerless-labs/phi-boundary-gate`
   - workflow: `.github/workflows/publish.yml`
   - environment: `testpypi`
3. Register a pending publisher on PyPI with the same project, repository, and
   workflow, environment `pypi`.
4. In GitHub, create environments named `testpypi` and `pypi`.
5. Require manual approval for the `pypi` environment.

Trusted Publishing avoids long-lived PyPI API tokens in GitHub Secrets.

## v0.8.5

Cross-Project Integration & Source-Aware Compliance ships as one backward-
compatible feature PR. The declared-PHI option remains disabled by default and
reuses Compliance Policy v1. Do not change Audit Report schema v3, Exposure Diff
schema v1, Coverage Diff sidecars, Trace Mapping v1, CLI exit behavior, Required
Checks, or the publish workflow triggers.

Before requesting merge, run:

```bash
ruff check src tests examples .github/scripts
PYTHONPATH="$PWD/src:$PWD" python3 -m unittest discover -s tests -v
python3 -m unittest discover -s .github/scripts/tests -v
PYTHONPATH="$PWD/src:$PWD" python3 -m compileall -q src tests examples .github/scripts
python3 .github/scripts/check_release_version.py --base-ref origin/main
PYTHONPATH=src python3 examples/integrations/provider_boundary_preflight.py
PYTHONPATH=src python3 examples/integrations/rag_agent_trace_audit.py \
  --out-dir /tmp/phi-v085-integration-audit
PYTHONPATH=src python3 tools/trace_corpus_report.py \
  --traces samples/traces \
  --expectations samples/trace_expectations \
  --policy samples/policies/default.yml \
  --out /tmp/phi-v085-trace-corpus.json
diff -u reports/trace-corpus-coverage.json /tmp/phi-v085-trace-corpus.json
python3 -m build
python3 -m twine check dist/*
```

Also run the existing CLI sample smoke and install the built wheel into a clean
environment with no source-tree `PYTHONPATH`. From that environment, import the
public SDK, confirm `__version__ == "0.8.5"`, and run both integration examples.

Release sequence:

1. Complete code and documentation review on the PR.
2. Confirm all Required Checks pass.
3. Merge the reviewed PR to `main`.
4. Confirm the resulting `main` CI run succeeds.
5. Confirm the automatic TestPyPI publication and clean installation validation succeed.
6. Confirm the target version and `v0.8.5` tag do not conflict with TestPyPI, PyPI, repository tags, or GitHub Releases.
7. Create and push the `v0.8.5` tag from the merged `main` commit only.
8. Let the existing tag-triggered Trusted Publishing workflow publish to PyPI; do not upload manually.
9. After PyPI publication succeeds, create GitHub Release `v0.8.5 — Cross-Project Integration & Source-Aware Compliance`.

```bash
git switch main
git pull --ff-only origin main
git tag -a v0.8.5 -m "v0.8.5: Cross-Project Integration"
git push origin v0.8.5
```

Never tag the feature branch, merge without review, publish manually, or proceed
past a failed Required Check, main CI run, TestPyPI validation, or required
environment approval.

## v0.8.4

Coverage-Aware Exposure Diff ships in one feature PR. Its JSON/Markdown output
is an opt-in sidecar: do not change Audit Report schema v3, Exposure Diff schema
v1, default `compare-reports` output, Required Checks, or advisory exit status.
Run the complete suite, release guard, CLI sample smoke, trace-corpus golden
comparison, package smoke, and coverage-aware CLI/SDK integration tests.

Confirm v0.8.4 does not already exist on TestPyPI, PyPI, as a tag, or as a
GitHub Release. Only after review and branch-protection requirements pass, merge
the feature PR, confirm main CI and the TestPyPI publish/install, then tag the
merged main commit:

```bash
git switch main
git pull --ff-only origin main
git tag -a v0.8.4 -m "v0.8.4: Coverage-Aware Exposure Diff"
git push origin v0.8.4
```

Wait for the tag workflow's Trusted Publishing job to publish and validate
PyPI before creating GitHub Release
`v0.8.4 — Coverage-Aware Exposure Diff`. Never tag the feature branch, publish
manually, bypass review, or continue past a failed Required Check or required
environment approval.

## v0.8.3

Audit Coverage & Blind-Spot Diagnostics ships in one feature PR. The coverage
JSON/Markdown contract is separate from Audit Report schema v3, is disabled by
default, and remains advisory. Do not add a Required Check, coverage threshold,
or fail-on-warning behavior. Run the complete validation suite below, the
existing CLI/corpus/package smoke paths, and the new coverage CLI/SDK tests.

Only after required PR checks and review/branch-protection requirements pass,
merge to `main`, confirm main CI, and verify the main workflow's TestPyPI
publication and installation. Then tag the merged main commit only:

```bash
git switch main
git pull --ff-only origin main
git tag -a v0.8.3 -m "v0.8.3: Audit Coverage & Blind-Spot Diagnostics"
git push origin v0.8.3
```

Wait for the tag workflow's Trusted Publishing job to succeed before creating
GitHub Release `v0.8.3 — Audit Coverage & Blind-Spot Diagnostics`. Confirm the
tag, GitHub Release, TestPyPI version, and PyPI version do not already exist.
Never tag the feature branch, publish manually, bypass review, or continue past
a failed Required Check.

## v0.8.2

Advisory Regression Insights ships as one feature PR without changing existing
CI workflow conditions, Diff schema v1, Audit Report schema v3, Guard behavior,
or default `compare-reports` output. Before merging, run the full validation
suite, the trace corpus golden diff, package smoke, and both CLI/SDK Review
Summary smoke paths.

Only after required PR checks pass, merge to `main`, confirm main CI succeeds,
and verify the main workflow's TestPyPI publication/install. Then tag the merged
main commit only:

```bash
git switch main
git pull --ff-only origin main
git tag -a v0.8.2 -m "v0.8.2: Advisory Regression Insights"
git push origin v0.8.2
```

The tag workflow publishes to PyPI through Trusted Publishing. Confirm the tag
and package version do not already exist, do not publish manually, and create
GitHub Release `v0.8.2 — Advisory Regression Insights` only after the tag
workflow succeeds. The optional Review Summary remains advisory; it is not a
Required Check or a HIPAA compliance certification.

## v0.8.1

Trustworthy Exposure Diff and its release metadata ship together in one feature
PR. Before merging, run the full validation suite documented below, including
the synthetic scan-to-diff smoke in `docs/exposure-diff.md`, wheel installation,
and the version guard against `origin/main`.

After the PR is merged, required main checks pass, and the main publish workflow
has published and verified v0.8.1 on TestPyPI, tag the merged main commit only:

```bash
git switch main
git pull --ff-only origin main
git tag -a v0.8.1 -m "v0.8.1: Trustworthy Exposure Diff"
git push origin v0.8.1
```

The tag workflow publishes to PyPI through Trusted Publishing. Confirm the tag
does not already exist, do not publish manually, and create GitHub Release
`v0.8.1 — Trustworthy Exposure Diff` only after the tag workflow succeeds.

## v0.8.0

The Exposure Diff feature and release metadata are prepared together for v0.8.0.
Before merging, run:

```bash
python3 -m pip install -e ".[dev]"
ruff check src tests examples .github/scripts
PYTHONPATH="$PWD/src:$PWD" python3 -m unittest discover -s tests -v
python3 -m unittest discover -s .github/scripts/tests -v
PYTHONPATH="$PWD/src:$PWD" python3 -m compileall -q src tests examples .github/scripts
python3 .github/scripts/check_release_version.py --base-ref origin/main
PYTHONPATH=src python3 -m phi_boundary_gate.cli compare-reports \
  --before /tmp/phi-exposure-diff/before.json \
  --after /tmp/phi-exposure-diff/after.json \
  --out /tmp/phi-exposure-diff/diff.md \
  --json /tmp/phi-exposure-diff/diff.json
python3 -m build
python3 -m twine check dist/*
```

The two input reports in the smoke command are generated by the complete example
in `docs/exposure-diff.md`. After the PR is merged, required `main` checks pass,
and TestPyPI validation succeeds, tag the merged commit only:

```bash
git switch main
git pull --ff-only origin main
git tag -a v0.8.0 -m "v0.8.0: Exposure Diff"
git push origin v0.8.0
```

The tag workflow publishes through Trusted Publishing. Create the GitHub Release
`v0.8.0 — Exposure Diff` after the tag if repository automation does not do so.
Do not tag the feature branch, publish manually, or alter the v0.7.0 release.

## v0.7.0

Before merging the v0.7.0 release PR:

```bash
python3 -m pip install -e ".[dev]"
ruff check src tests examples .github/scripts
PYTHONPATH="$PWD/src:$PWD" python3 -m unittest discover -s tests -v
python3 -m unittest discover -s .github/scripts/tests -v
PYTHONPATH="$PWD/src:$PWD" python3 -m compileall -q src tests examples .github/scripts
python3 .github/scripts/check_release_version.py --base-ref origin/main
python3 -m build
python3 -m twine check dist/*
```

Install the v0.7.0 wheel into a clean virtual environment and verify the public
semantic API and version before merge. After the PR is merged and required
`main` checks pass, tag the merged commit only:

```bash
git switch main
git pull --ff-only origin main
git tag -a v0.7.0 -m "v0.7.0: Semantic Context Gate"
git push origin v0.7.0
```

The tag workflow publishes to PyPI through Trusted Publishing. Do not manually
upload with Twine or configure a long-lived PyPI token. Create the GitHub Release
`v0.7.0 — Semantic Context Gate` after the tag if no repository automation does
so; `.github/workflows/publish.yml` builds and publishes packages but does not
create GitHub Releases.

## v0.6.1

Before merging the v0.6.1 release PR:

```bash
python3 -m pip install -e ".[dev]"
ruff check src tests examples .github/scripts
PYTHONPATH="$PWD/src:$PWD" python3 -m unittest discover -s tests -v
PYTHONPATH="$PWD/src:$PWD" python3 -m compileall -q src tests examples .github/scripts
PYTHONPATH="$PWD/src:$PWD" python3 -m phi_boundary_gate.cli scan-external-trace \
  --input samples/external_traces/generic_agent_run.jsonl \
  --mapping samples/trace_mappings/generic_agent.yml \
  --policy samples/policies/default.yml \
  --out /tmp/phi-direct-report.md \
  --json /tmp/phi-direct-report.json \
  --diagnostics /tmp/phi-direct-diagnostics.json \
  --redacted-trace /tmp/phi-direct-redacted.jsonl
! grep -q 'MBR-SYN-8842' /tmp/phi-direct-report.md /tmp/phi-direct-report.json
python3 - <<'PY'
import json
from pathlib import Path

report = json.loads(Path("/tmp/phi-direct-report.json").read_text())
assert report["trace_path"].endswith("samples/external_traces/generic_agent_run.jsonl")
assert any(item.get("external_content_path") for item in report["findings"])
PY
PYTHONPATH="$PWD/src:$PWD" python3 examples/sdk_audit_external_trace.py
python3 -m build
python3 -m twine check dist/*
```

After the PR is merged to `main`, rerun the release-critical tests and build,
then create the release tag from merged `main`:

```bash
git tag v0.6.1
git push origin v0.6.1
```

The tag workflow publishes v0.6.1 to PyPI through Trusted Publishing. Do not
tag from the feature branch and do not manually upload the distribution with
`twine upload`.

## v0.6.0

Before merging a release PR:

```bash
python3 -m pip install -e ".[dev]"
ruff check src tests examples .github/scripts
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 -m unittest discover -s .github/scripts/tests -v
PYTHONPATH=src python3 -m compileall -q src tests examples .github/scripts
PYTHONPATH=src python3 -m phi_boundary_gate.cli scan-trace \
  --trace samples/traces/claim_agent_minimal.jsonl \
  --policy samples/policies/default.yml \
  --out reports/sample-report.md \
  --json reports/sample-report.json \
  --redacted-trace reports/sample-redacted-trace.jsonl
PYTHONPATH=src python3 -m phi_boundary_gate.cli scan-trace \
  --trace samples/traces/expanded_phi_variants.jsonl \
  --policy samples/policies/default.yml \
  --out /tmp/phi-expanded-report.md \
  --json /tmp/phi-expanded-report.json
PYTHONPATH=src python3 -m phi_boundary_gate.cli scan-trace \
  --trace samples/traces/claim_agent_minimal.jsonl \
  --policy samples/policies/default.yml \
  --out /tmp/phi-redacted-report.md \
  --json /tmp/phi-redacted-report.json \
  --report-values redacted
! grep -q 'MBR-SYN-8842' /tmp/phi-redacted-report.md /tmp/phi-redacted-report.json
PYTHONPATH=src python3 -m phi_boundary_gate.cli scan-trace \
  --trace samples/traces/claim_agent_minimal.jsonl \
  --policy samples/policies/default.yml \
  --out /tmp/phi-hashed-report.md \
  --json /tmp/phi-hashed-report.json \
  --report-values hashed
! grep -q 'MBR-SYN-8842' /tmp/phi-hashed-report.md /tmp/phi-hashed-report.json
PYTHONPATH=src python3 tools/trace_corpus_report.py \
  --traces samples/traces \
  --expectations samples/trace_expectations \
  --policy samples/policies/default.yml \
  --out /tmp/trace-corpus-coverage.json
diff -u reports/trace-corpus-coverage.json /tmp/trace-corpus-coverage.json
PYTHONPATH=src python3 -m phi_boundary_gate.cli convert-trace \
  --input samples/external_traces/generic_agent_run.jsonl \
  --mapping samples/trace_mappings/generic_agent.yml \
  --out /tmp/generic-agent-normalized.jsonl \
  --diagnostics /tmp/generic-agent-diagnostics.json
diff -u samples/normalized_traces/generic_agent_expected.jsonl /tmp/generic-agent-normalized.jsonl
diff -u samples/adapter_diagnostics/generic_agent_expected.json /tmp/generic-agent-diagnostics.json
PYTHONPATH=src python3 -m phi_boundary_gate.cli convert-trace \
  --input samples/external_traces/callback_agent_run.jsonl \
  --mapping samples/trace_mappings/callback_agent.yml \
  --out /tmp/callback-agent-normalized.jsonl \
  --diagnostics /tmp/callback-agent-diagnostics.json
diff -u samples/normalized_traces/callback_agent_expected.jsonl /tmp/callback-agent-normalized.jsonl
diff -u samples/adapter_diagnostics/callback_agent_expected.json /tmp/callback-agent-diagnostics.json
PYTHONPATH=src python3 -m phi_boundary_gate.cli validate-mapping \
  --mapping samples/trace_mappings/generic_agent.yml
PYTHONPATH=src python3 -m phi_boundary_gate.cli validate-mapping \
  --mapping samples/trace_mappings/callback_agent.yml
PYTHONPATH=src python3 -m phi_boundary_gate.cli validate-trace \
  --trace /tmp/generic-agent-normalized.jsonl
PYTHONPATH=src python3 -m phi_boundary_gate.cli validate-trace \
  --trace /tmp/callback-agent-normalized.jsonl
python3 .github/scripts/check_release_version.py --skip-bump-check
PYTHONPATH=src python3 examples/sdk_guard_model_input.py
PYTHONPATH=src python3 examples/sdk_redact_logs.py
PYTHONPATH=src python3 examples/sdk_audit_trace.py
PYTHONPATH=src python3 examples/trace_mapping_pipeline.py \
  --out /tmp/generic-agent-normalized-example.jsonl
diff -u samples/normalized_traces/generic_agent_expected.jsonl /tmp/generic-agent-normalized-example.jsonl
python3 -m build
python3 -m twine check dist/*
python3 -m pip install --no-build-isolation --no-deps --target /tmp/phi-package-smoke-v060 .
test -f /tmp/phi-package-smoke-v060/phi_boundary_gate/py.typed
test -f /tmp/phi-package-smoke-v060/phi_boundary_gate/templates/phi-policy.yml
test -f /tmp/phi-package-smoke-v060/phi_boundary_gate/adapters/generic_jsonl.py
PYTHONPATH=/tmp/phi-package-smoke-v060 python3 -c "from phi_boundary_gate import __version__, AuditResult, PhiBoundaryGate, PhiBoundaryGateError, TraceAdapter, TraceMappingError, audit_events, audit_trace, build_conversion_diagnostics, guard_text, guard_compliance, load_external_trace, validate_trace_mapping; print(__version__, AuditResult.__name__, PhiBoundaryGate.__name__, PhiBoundaryGateError.__name__, TraceAdapter.__name__, TraceMappingError.__name__, audit_events.__name__, audit_trace.__name__, build_conversion_diagnostics.__name__, guard_text.__name__, guard_compliance.__name__, load_external_trace.__name__, validate_trace_mapping.__name__)"
PYTHONPATH=/tmp/phi-package-smoke-v060 python3 examples/sdk_guard_model_input.py
PYTHONPATH=/tmp/phi-package-smoke-v060 python3 examples/sdk_redact_logs.py
PYTHONPATH=/tmp/phi-package-smoke-v060 python3 examples/sdk_audit_trace.py
PYTHONPATH=/tmp/phi-package-smoke-v060 python3 examples/trace_mapping_pipeline.py \
  --out /tmp/generic-agent-normalized-example-installed.jsonl
diff -u samples/normalized_traces/generic_agent_expected.jsonl /tmp/generic-agent-normalized-example-installed.jsonl
PYTHONPATH=/tmp/phi-package-smoke-v060 python3 -m phi_boundary_gate.cli --help
PYTHONPATH=/tmp/phi-package-smoke-v060 python3 -m phi_boundary_gate.cli validate-mapping \
  --mapping samples/trace_mappings/generic_agent.yml
PYTHONPATH=/tmp/phi-package-smoke-v060 python3 -m phi_boundary_gate.cli validate-mapping \
  --mapping samples/trace_mappings/callback_agent.yml
PYTHONPATH=/tmp/phi-package-smoke-v060 python3 -m phi_boundary_gate.cli convert-trace \
  --input samples/external_traces/generic_agent_run.jsonl \
  --mapping samples/trace_mappings/generic_agent.yml \
  --out /tmp/generic-agent-normalized-installed.jsonl \
  --diagnostics /tmp/generic-agent-diagnostics-installed.json
diff -u samples/normalized_traces/generic_agent_expected.jsonl /tmp/generic-agent-normalized-installed.jsonl
diff -u samples/adapter_diagnostics/generic_agent_expected.json /tmp/generic-agent-diagnostics-installed.json
PYTHONPATH=/tmp/phi-package-smoke-v060 python3 -m phi_boundary_gate.cli convert-trace \
  --input samples/external_traces/callback_agent_run.jsonl \
  --mapping samples/trace_mappings/callback_agent.yml \
  --out /tmp/callback-agent-normalized-installed.jsonl \
  --diagnostics /tmp/callback-agent-diagnostics-installed.json
diff -u samples/normalized_traces/callback_agent_expected.jsonl /tmp/callback-agent-normalized-installed.jsonl
diff -u samples/adapter_diagnostics/callback_agent_expected.json /tmp/callback-agent-diagnostics-installed.json
```

After checks pass on `main` and TestPyPI publishing succeeds:

```bash
git tag v0.6.0
git push origin v0.6.0
```

Downstream projects should prefer the PyPI package:

```text
phi-boundary-gate>=0.6,<0.7
```

Git tag fallback remains available when a package index cannot be used:

```text
phi-boundary-gate @ git+ssh://git@github.com/tigerless-labs/phi-boundary-gate.git@v0.6.0
```

## Notes

- Do not tag from a feature branch.
- Do not reuse a tag after pushing it.
- Do not tag if package import, CLI entrypoint, build metadata, or smoke install fails.
- Do not include real PHI in release validation.
- Do not publish to PyPI until the GitHub `pypi` environment approval gate is configured.
