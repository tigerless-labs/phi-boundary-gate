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

## v0.5.4

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
PYTHONPATH=src python3 tools/trace_corpus_report.py \
  --traces samples/traces \
  --expectations samples/trace_expectations \
  --policy samples/policies/default.yml \
  --out /tmp/trace-corpus-coverage.json
diff -u reports/trace-corpus-coverage.json /tmp/trace-corpus-coverage.json
PYTHONPATH=src python3 -m phi_boundary_gate.cli convert-trace \
  --input samples/external_traces/generic_agent_run.jsonl \
  --mapping samples/trace_mappings/generic_agent.yml \
  --out /tmp/generic-agent-normalized.jsonl
diff -u samples/normalized_traces/generic_agent_expected.jsonl /tmp/generic-agent-normalized.jsonl
PYTHONPATH=src python3 -m phi_boundary_gate.cli validate-mapping \
  --mapping samples/trace_mappings/generic_agent.yml
PYTHONPATH=src python3 -m phi_boundary_gate.cli validate-trace \
  --trace /tmp/generic-agent-normalized.jsonl
python3 .github/scripts/check_release_version.py --skip-bump-check
PYTHONPATH=src python3 examples/sdk_guard_model_input.py
PYTHONPATH=src python3 examples/sdk_redact_logs.py
PYTHONPATH=src python3 examples/trace_mapping_pipeline.py \
  --out /tmp/generic-agent-normalized-example.jsonl
diff -u samples/normalized_traces/generic_agent_expected.jsonl /tmp/generic-agent-normalized-example.jsonl
python3 -m build
python3 -m twine check dist/*
python3 -m pip install --no-build-isolation --no-deps --target /tmp/phi-package-smoke-v054 .
test -f /tmp/phi-package-smoke-v054/phi_boundary_gate/py.typed
test -f /tmp/phi-package-smoke-v054/phi_boundary_gate/templates/phi-policy.yml
test -f /tmp/phi-package-smoke-v054/phi_boundary_gate/adapters/generic_jsonl.py
PYTHONPATH=/tmp/phi-package-smoke-v054 python3 -c "from phi_boundary_gate import __version__, PhiBoundaryGate, PhiBoundaryGateError, TraceAdapter, TraceMappingError, guard_text, guard_compliance, load_external_trace, validate_trace_mapping; print(__version__, PhiBoundaryGate.__name__, PhiBoundaryGateError.__name__, TraceAdapter.__name__, TraceMappingError.__name__, guard_text.__name__, guard_compliance.__name__, load_external_trace.__name__, validate_trace_mapping.__name__)"
PYTHONPATH=/tmp/phi-package-smoke-v054 python3 examples/sdk_guard_model_input.py
PYTHONPATH=/tmp/phi-package-smoke-v054 python3 examples/sdk_redact_logs.py
PYTHONPATH=/tmp/phi-package-smoke-v054 python3 examples/trace_mapping_pipeline.py \
  --out /tmp/generic-agent-normalized-example-installed.jsonl
diff -u samples/normalized_traces/generic_agent_expected.jsonl /tmp/generic-agent-normalized-example-installed.jsonl
PYTHONPATH=/tmp/phi-package-smoke-v054 python3 -m phi_boundary_gate.cli --help
PYTHONPATH=/tmp/phi-package-smoke-v054 python3 -m phi_boundary_gate.cli validate-mapping \
  --mapping samples/trace_mappings/generic_agent.yml
PYTHONPATH=/tmp/phi-package-smoke-v054 python3 -m phi_boundary_gate.cli convert-trace \
  --input samples/external_traces/generic_agent_run.jsonl \
  --mapping samples/trace_mappings/generic_agent.yml \
  --out /tmp/generic-agent-normalized-installed.jsonl
diff -u samples/normalized_traces/generic_agent_expected.jsonl /tmp/generic-agent-normalized-installed.jsonl
```

After checks pass on `main` and TestPyPI publishing succeeds:

```bash
git tag v0.5.4
git push origin v0.5.4
```

Downstream projects should prefer the PyPI package:

```text
phi-boundary-gate>=0.5,<0.6
```

Git tag fallback remains available when a package index cannot be used:

```text
phi-boundary-gate @ git+ssh://git@github.com/tigerless-labs/phi-boundary-gate.git@v0.5.4
```

## Notes

- Do not tag from a feature branch.
- Do not reuse a tag after pushing it.
- Do not tag if package import, CLI entrypoint, build metadata, or smoke install fails.
- Do not include real PHI in release validation.
- Do not publish to PyPI until the GitHub `pypi` environment approval gate is configured.
