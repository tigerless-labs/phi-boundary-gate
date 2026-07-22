# Install and Consume as a Package

This project is a Python package. Other projects should import it through normal package installation, not by copying source files.

## Local Editable Install

Use this for local development across sibling repositories such as `ai_translation` or `lara`.

```bash
python3 -m pip install -e /home/frank/code/phi-context-boundary-report
```

Then import the package:

```python
from phi_boundary_report import guard_text, load_policy
```

Editable install is best for local integration because changes in this repository are visible immediately to the calling project's Python environment.

## Git Tag Install

Use this when another project needs a reproducible dependency without a private package registry.

```bash
python3 -m pip install \
  "phi-context-boundary-report @ git+ssh://git@github.com/tigerless-labs/phi-context-boundary-report.git@v0.2.0"
```

For short-term testing, a commit SHA is also valid:

```bash
python3 -m pip install \
  "phi-context-boundary-report @ git+ssh://git@github.com/tigerless-labs/phi-context-boundary-report.git@<commit-sha>"
```

Do not use `@main` for production or serious integration. It is not reproducible.

## requirements.txt

```text
phi-context-boundary-report @ git+ssh://git@github.com/tigerless-labs/phi-context-boundary-report.git@v0.2.0
```

Install from the consuming project:

```bash
python3 -m pip install -r requirements.txt
```

## pyproject.toml

```toml
[project]
dependencies = [
  "phi-context-boundary-report @ git+ssh://git@github.com/tigerless-labs/phi-context-boundary-report.git@v0.2.0",
]
```

## Updating the Dependency

For compatible changes:

1. Merge the PHI package changes to `main`.
2. Bump `pyproject.toml` and `src/phi_boundary_report/__init__.py`.
3. Create and push a new tag.
4. Update consuming projects to the new tag.

Example:

```bash
git tag v0.2.0
git push origin v0.2.0
```

Then update the consuming project:

```text
phi-context-boundary-report @ git+ssh://git@github.com/tigerless-labs/phi-context-boundary-report.git@v0.2.0
```

Use patch versions for compatible fixes. Use a minor version for new public API additions or behavior changes while the package is still pre-1.0.

## Release Checklist for v0.2.0

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

After the checks pass:

```bash
git tag v0.2.0
git push origin v0.2.0
```

## Future Artifact Registry Route

When infrastructure permissions are ready, publish this package to a private Python registry such as Google Artifact Registry.

Expected consuming-project dependency after that migration:

```text
phi-context-boundary-report==0.2.0
```

The versioning workflow should stay the same. Only the package source changes from Git URL to a private package index.

## Notes

- Calling projects still need GitHub SSH access when installing from a Git URL.
- This package reports PHI candidates, redacts according to policy, and can enforce organization-supplied BAA/provider eligibility policy. It does not discover contract status automatically.
- Do not commit real PHI, real traces, real logs, or real reports to this repository or consuming projects.
