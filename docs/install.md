# Install and Consume as a Package

This project is a Python package. Other projects should import it through normal
package installation, not by copying source files.

## PyPI Install

Use PyPI for normal consumption:

```bash
python3 -m pip install "phi-boundary-gate>=0.5,<0.6"
```

For `requirements.txt`:

```text
phi-boundary-gate>=0.5,<0.6
```

For `pyproject.toml`:

```toml
[project]
dependencies = [
  "phi-boundary-gate>=0.5,<0.6",
]
```

Use a compatible range instead of an exact pin in application manifests. Lock the
resolved version in the consuming project's lockfile or deployment artifact, then
let Dependabot, Renovate, or an equivalent dependency-update workflow propose
upgrades through CI.

## Optional Local NER Install

The default install uses only bundled deterministic regex rules. To enable local
Presidio-assisted NER detection, install the optional `ner` extra and a spaCy
English model in the consuming environment:

```bash
python3 -m pip install "phi-boundary-gate[ner]>=0.5,<0.6"
python3 -m spacy download en_core_web_lg
```

Then pass `--enable-presidio` on the CLI, or `enable_presidio=True` to
`scan_text`, `guard_text`, `build_report`, or `guard_compliance`.

## Project Bootstrap

Create starter policy files in a consuming project:

```bash
phi-boundary-gate init
phi-boundary-gate check-config
```

This writes:

```text
.phi-boundary-gate/config.json
config/phi-policy.yml
config/phi-compliance-policy.yml
```

The starter files are schema examples. Review and replace service, BAA, logging,
storage, and model facts with organization-approved values before using them with
real PHI.

Then use the SDK facade:

```python
from phi_boundary_gate import PhiBoundaryGate

gate = PhiBoundaryGate.from_project()
decision = gate.guard_model_input("member_id=MBR-SYN-8842")
safe_log_text = gate.redact_for_log("debug member_id=MBR-SYN-8842")
audit_payload = decision.to_safe_dict()
```

## External Trace Normalization

Projects with their own agent event logs can normalize generic JSONL before
scanning:

```bash
phi-boundary-gate convert-trace \
  --input raw-agent-events.jsonl \
  --mapping config/phi-trace-map.yml \
  --out normalized-trace.jsonl

phi-boundary-gate validate-mapping --mapping config/phi-trace-map.yml
phi-boundary-gate validate-trace --trace normalized-trace.jsonl
```

See [Trace Adapters](adapters.md) for mapping v1.

## Local Editable Install

Use this when developing this package beside another local project:

```bash
python3 -m pip install -e /home/frank/code/phi-boundary-gate
```

For package development, include developer tooling:

```bash
python3 -m pip install -e ".[dev]"
```

Editable install is best for local integration because changes in this repository
are visible immediately to the calling project's Python environment.

## Git Tag Fallback

Use a Git tag only when another project cannot access PyPI or the chosen private
package index:

```bash
python3 -m pip install \
  "phi-boundary-gate @ git+ssh://git@github.com/tigerless-labs/phi-boundary-gate.git@v0.5.5"
```

The NER extra works with the same fallback:

```bash
python3 -m pip install \
  "phi-boundary-gate[ner] @ git+ssh://git@github.com/tigerless-labs/phi-boundary-gate.git@v0.5.5"
```

For short-term testing, a commit SHA is also valid:

```bash
python3 -m pip install \
  "phi-boundary-gate @ git+ssh://git@github.com/tigerless-labs/phi-boundary-gate.git@<commit-sha>"
```

Do not use `@main` for production or serious integration. It is not reproducible.

## Publishing

Release publishing uses GitHub Actions and PyPI Trusted Publishing:

1. Configure a pending trusted publisher on TestPyPI for project
   `phi-boundary-gate`, repository `tigerless-labs/phi-boundary-gate`, workflow
   `.github/workflows/publish.yml`, environment `testpypi`.
2. Configure a pending trusted publisher on PyPI with the same repository and
   workflow, environment `pypi`.
3. Require manual approval for the `pypi` GitHub Environment.
4. Merge the release PR to `main`; the publish workflow builds distributions and
   publishes to TestPyPI.
5. Create and push the release tag:

```bash
git tag v0.5.5
git push origin v0.5.5
```

The tag workflow publishes the same built package shape to PyPI.

## Notes

- Calling projects must provide their own PHI policy YAML, and their own
  compliance policy YAML if they use `guard_compliance`.
- This package reports PHI candidates, redacts according to policy, and can
  enforce organization-supplied BAA/provider eligibility policy. It does not
  discover contract status automatically.
- Do not commit real PHI, real traces, real logs, or real reports to this
  repository or consuming projects.
- License: MIT. See [LICENSE](../LICENSE).
