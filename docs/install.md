# Install and Consume as a Package

This project is a Python package. Other projects should import it through normal package installation, not by copying source files.

## Local Editable Install

Use this when developing this package beside another local project.

```bash
python3 -m pip install -e /home/frank/code/phi-context-boundary-report
```

Then import the package:

```python
from phi_boundary_report import guard_text, load_policy
```

Editable install is best for local integration because changes in this repository are visible immediately to the calling project's Python environment.

The consuming project still needs its own policy files. The `samples/` directory
is part of this repository's examples, not installed package data.

## Git Tag Install

Use this when another project needs a reproducible dependency without a private package registry.

```bash
python3 -m pip install \
  "phi-context-boundary-report @ git+ssh://git@github.com/tigerless-labs/phi-context-boundary-report.git@v0.3.2"
```

For short-term testing, a commit SHA is also valid:

```bash
python3 -m pip install \
  "phi-context-boundary-report @ git+ssh://git@github.com/tigerless-labs/phi-context-boundary-report.git@<commit-sha>"
```

Do not use `@main` for production or serious integration. It is not reproducible.

## requirements.txt

```text
phi-context-boundary-report @ git+ssh://git@github.com/tigerless-labs/phi-context-boundary-report.git@v0.3.2
```

Install from the consuming project:

```bash
python3 -m pip install -r requirements.txt
```

## pyproject.toml

```toml
[project]
dependencies = [
  "phi-context-boundary-report @ git+ssh://git@github.com/tigerless-labs/phi-context-boundary-report.git@v0.3.2",
]
```

## Optional Local NER Install

The default install uses only bundled deterministic regex rules. To enable local
Presidio-assisted NER detection, install the optional `ner` extra and a spaCy
English model in the consuming environment:

```bash
python3 -m pip install \
  "phi-context-boundary-report[ner] @ git+ssh://git@github.com/tigerless-labs/phi-context-boundary-report.git@v0.3.2"
python3 -m spacy download en_core_web_lg
```

Then pass `--enable-presidio` on the CLI, or `enable_presidio=True` to
`scan_text`, `guard_text`, `build_report`, or `guard_compliance`.

## Updating the Dependency

For compatible changes:

1. Merge the PHI package changes to `main`.
2. Bump `pyproject.toml` and `src/phi_boundary_report/__init__.py`.
3. Create and push a new tag.
4. Update consuming projects to the new tag.

Example for a new release:

```bash
git tag v<new-version>
git push origin v<new-version>
```

Then update the consuming project:

```text
phi-context-boundary-report @ git+ssh://git@github.com/tigerless-labs/phi-context-boundary-report.git@v<new-version>
```

Use patch versions for compatible fixes. Use a minor version for new public API additions or behavior changes while the package is still pre-1.0.

## Release Checklist for v0.3.2

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
PYTHONPATH=src python3 -m phi_boundary_report.cli \
  --trace samples/traces/expanded_phi_variants.jsonl \
  --policy samples/policies/default.yml \
  --out /tmp/expanded-report.md \
  --json /tmp/expanded-report.json
PYTHONPATH=src python3 tools/trace_corpus_report.py \
  --traces samples/traces \
  --expectations samples/trace_expectations \
  --policy samples/policies/default.yml \
  --out /tmp/trace-corpus-coverage.json
diff -u reports/trace-corpus-coverage.json /tmp/trace-corpus-coverage.json
python3 -m pip install --no-build-isolation --no-deps --target /tmp/phi-package-smoke-v032 .
PYTHONPATH=/tmp/phi-package-smoke-v032 python3 -c "from phi_boundary_report import __version__, guard_text, guard_compliance; print(__version__, guard_text.__name__, guard_compliance.__name__)"
PYTHONPATH=/tmp/phi-package-smoke-v032 python3 -m phi_boundary_report.cli --help
```

After the checks pass:

```bash
git tag v0.3.2
git push origin v0.3.2
```

## Future Artifact Registry Route

When infrastructure permissions are ready, publish this package to a private Python registry such as Google Artifact Registry.

Expected consuming-project dependency after that migration:

```text
phi-context-boundary-report==0.3.2
```

The versioning workflow should stay the same. Only the package source changes from Git URL to a private package index.

## Notes

- Calling projects still need GitHub SSH access when installing from a Git URL.
- Calling projects must provide their own PHI policy YAML, and their own compliance policy YAML if they use `guard_compliance`.
- This package reports PHI candidates, redacts according to policy, and can enforce organization-supplied BAA/provider eligibility policy. It does not discover contract status automatically.
- Do not commit real PHI, real traces, real logs, or real reports to this repository or consuming projects.
- License: MIT. See [LICENSE](../LICENSE).
