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
  "phi-context-boundary-report @ git+ssh://git@github.com/tigerless-labs/phi-context-boundary-report.git@v0.1.0"
```

For short-term testing, a commit SHA is also valid:

```bash
python3 -m pip install \
  "phi-context-boundary-report @ git+ssh://git@github.com/tigerless-labs/phi-context-boundary-report.git@7774b25"
```

Do not use `@main` for production or serious integration. It is not reproducible.

## requirements.txt

```text
phi-context-boundary-report @ git+ssh://git@github.com/tigerless-labs/phi-context-boundary-report.git@v0.1.0
```

Install from the consuming project:

```bash
python3 -m pip install -r requirements.txt
```

## pyproject.toml

```toml
[project]
dependencies = [
  "phi-context-boundary-report @ git+ssh://git@github.com/tigerless-labs/phi-context-boundary-report.git@v0.1.0",
]
```

## Updating the Dependency

For compatible changes:

1. Merge the PHI package changes to `main`.
2. Bump `pyproject.toml` from `0.1.0` to `0.1.1`.
3. Create and push a new tag.
4. Update consuming projects to the new tag.

Example:

```bash
git tag v0.1.1
git push origin v0.1.1
```

Then update the consuming project:

```text
phi-context-boundary-report @ git+ssh://git@github.com/tigerless-labs/phi-context-boundary-report.git@v0.1.1
```

Use patch versions for compatible fixes and additions. Use a minor version, such as `0.2.0`, for API-breaking changes while the package is still pre-1.0.

## Release Checklist for v0.1.0

Install the build frontend if needed:

```bash
python3 -m pip install build
```

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
python3 -m build
```

After the checks pass:

```bash
git tag v0.1.0
git push origin v0.1.0
```

## Future Artifact Registry Route

When infrastructure permissions are ready, publish this package to a private Python registry such as Google Artifact Registry.

Expected consuming-project dependency after that migration:

```text
phi-context-boundary-report==0.1.0
```

The versioning workflow should stay the same. Only the package source changes from Git URL to a private package index.

## Notes

- Calling projects still need GitHub SSH access when installing from a Git URL.
- This package reports PHI candidates and redacts according to policy. It does not decide BAA provider eligibility.
- Do not commit real PHI, real traces, real logs, or real reports to this repository or consuming projects.
