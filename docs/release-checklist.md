# Release Checklist

Use this checklist before creating a Git tag that consuming projects will install from.

## v0.2.0

Before tagging:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests
PYTHONPATH=src python3 -m compileall -q src tests
PYTHONPATH=src python3 -m phi_boundary_report.cli \
  --trace samples/traces/claim_agent_minimal.jsonl \
  --policy samples/policies/default.yml \
  --out reports/sample-report.md \
  --json reports/sample-report.json \
  --redacted-trace reports/sample-redacted-trace.jsonl
python3 -m pip install --no-build-isolation --no-deps --target /tmp/phi-package-smoke-v020 .
PYTHONPATH=/tmp/phi-package-smoke-v020 python3 -c "from phi_boundary_report import __version__, guard_text, guard_compliance; print(__version__, guard_text.__name__, guard_compliance.__name__)"
PYTHONPATH=/tmp/phi-package-smoke-v020 python3 -m phi_boundary_report.cli --help
```

After checks pass on `main`:

```bash
git tag v0.2.0
git push origin v0.2.0
```

Downstream projects should pin the tag:

```text
phi-context-boundary-report @ git+ssh://git@github.com/tigerless-labs/phi-context-boundary-report.git@v0.2.0
```

## Notes

- Do not tag from a feature branch.
- Do not reuse a tag after pushing it.
- Do not tag if package import, CLI entrypoint, or smoke install fails.
- Do not include real PHI in release validation.
