# Exposure Diff

Exposure Diff compares two existing JSON audit reports and describes how observed PHI
candidate routes changed between runs. It is advisory analysis: differences never change
the command's successful exit status, block CI, rewrite a trace, or modify a policy.

## Run the synthetic example

From the repository root, generate both reports with the existing scanner and then compare
them:

```bash
mkdir -p /tmp/phi-exposure-diff

PYTHONPATH=src python3 -m phi_boundary_gate.cli scan-trace \
  --trace samples/traces/exposure_diff_baseline.jsonl \
  --policy samples/policies/default.yml \
  --report-values redacted \
  --out /tmp/phi-exposure-diff/before.md \
  --json /tmp/phi-exposure-diff/before.json

PYTHONPATH=src python3 -m phi_boundary_gate.cli scan-trace \
  --trace samples/traces/exposure_diff_candidate.jsonl \
  --policy samples/policies/exposure_diff_candidate.yml \
  --report-values redacted \
  --out /tmp/phi-exposure-diff/after.md \
  --json /tmp/phi-exposure-diff/after.json

PYTHONPATH=src python3 -m phi_boundary_gate.cli compare-reports \
  --before /tmp/phi-exposure-diff/before.json \
  --after /tmp/phi-exposure-diff/after.json \
  --out /tmp/phi-exposure-diff/diff.md \
  --json /tmp/phi-exposure-diff/diff.json \
  --review-summary /tmp/phi-exposure-diff/review-summary.md

sed -n '1,220p' /tmp/phi-exposure-diff/diff.md
cat /tmp/phi-exposure-diff/review-summary.md
python3 -m json.tool /tmp/phi-exposure-diff/diff.json
```

The example produces one newly observed `name` route, one no-longer-observed `claim_id`
route, and a frequency and policy-disposition change for the existing `member_id` route.
The normalized policy fingerprints differ, so the result is explicitly `limited`: the
disposition change may be configuration-driven and must not be attributed solely to Agent
behavior.

To compare observed audit scope alongside this unchanged Exposure Diff, generate
Coverage JSON for both scans and use the optional v0.8.4 sidecars described in
[Coverage-Aware Exposure Diff](coverage-aware-exposure-diff.md). The existing
Diff JSON schema, Markdown, and default command behavior are not modified.

## Advisory regression review summary

`--review-summary` is optional. When provided, it writes a separate, concise
Markdown artifact suitable for a GitHub Actions Job Summary or a human PR
review. Omitting the option preserves the existing CLI behavior and creates no
additional file.

The summary reuses the existing Diff result. It includes aggregate counts from
`summary`, comparability status, and at most six prioritized guidance entries.
Guidance uses fixed machine-readable codes and fixed text; it never includes
exposure keys, path references, raw paths, trace content, matched values, or
free-form detector, policy, or resolver reasons. The stable priorities are:

- review worsened dispositions and newly observed routes;
- validate policy, detector, or semantic comparability when evidence differs,
  is missing, or is unknown;
- verify no-longer-observed routes independently;
- review improved, mixed, or frequency changes without inferring causality.

Frequency changes are not automatically classified as risk worsening.
No-longer-observed routes are not classified as eliminated risks. Configuration
uncertainty is retained, and guidance cannot override Guard, policy, compliance,
or CI decisions.

To append the file manually in a GitHub Actions step:

```bash
cat /tmp/phi-exposure-diff/review-summary.md >> "$GITHUB_STEP_SUMMARY"
```

The CLI does not inspect a repository, call the GitHub API, create checks or
comments, read secrets, or modify workflows. A valid Diff returns `0` even when
the summary reports new routes, worsened dispositions, or configuration drift.
The summary is advisory and is not a HIPAA compliance certification.

## Canonical exposure key

Diff schema v1 expands every finding once per unique destination. A finding without a
destination receives one explicit no-destination route. Each route key contains only:

- candidate category;
- source layer;
- SHA-256 references for source type and source path;
- destination layer and a SHA-256 reference for destination path;
- SHA-256 references for `content_path` and `external_content_path`.

Schema v3 `boundary_exposures` group findings by category and matched value. Exposure Diff
instead reconstructs route groups from validated `findings`, because matched-value identity is
both sensitive and the wrong key for comparing structural flow. The existing exposure summaries
remain unchanged and are never rewritten.

The key deliberately excludes event ID, timestamp, matched value, value hash, span, finding
ID, report-local exposure ID, policy rule text, detector reason, and semantic output. Event
ordering and timestamp changes therefore do not change route identity. Repeated routes are
counted, while exact duplicate destinations on one finding are counted once.

JSON array indexes are retained in the path input before hashing. This conservative exact
matching avoids combining distinct array positions, but an array reorder can appear as a new
and no-longer-observed pair. Diff schema v1 does not guess that the two positions are the same.

`occurrences` counts finding-to-destination observations. `events` counts distinct report-local
event IDs within one route. Event IDs contribute only to that per-report count; they are never
copied to the Diff or used for cross-report identity. Exposure group counts are the number of
distinct canonical route keys, not event counts.

## Validation and safe output

Both inputs must be current path-aware audit reports (`schema_version: 3`,
`finding_schema: path-aware`). The reader validates the schema-defined fields used by the
comparison. Invalid JSON, missing required fields, unsupported categories/layers/dispositions,
or an incompatible schema return the CLI's normal validation error status (`2`). Differences
between two valid reports return `0`, including newly observed or more severe routes.

The Diff has its own versioned JSON contract (`schema_version: 1`). It never copies matched
values, raw trace text, event IDs, free-form detector or policy reasons, semantic rationale,
unknown input fields, source types, or input paths. Potentially sensitive structural strings are
represented only by SHA-256 references. Before and after report identifiers are content
references rather than filenames.

The comparison is deterministic and does not modify either input report.

## Configuration provenance and comparability

v0.8.1 audit reports retain schema version 3 and add optional `audit_context` evidence. Policy
fingerprints come from normalized effective policy objects, not paths or YAML field order.
Detector fingerprints cover the enabled built-in rules and Presidio enablement. An enabled
Presidio Analyzer's external model/configuration cannot be verified and is explicitly `unknown`.
SDK callers can identify a Semantic Resolver configuration with `semantic_resolver_id`; only a
SHA-256 fingerprint of that identifier is retained. An enabled resolver without an ID is unknown.

Diff schema v1 preserves `comparability.status` and adds:

- `structural`: whether the schema-defined route key shapes can be compared, plus whether detector
  evidence limits interpretation of the observed route population;
- `disposition`: whether observed risk-level changes have a comparable configuration basis;
- `reason_codes` and `diagnostics`: deterministic machine-readable explanations of matches,
  drift, missing evidence, and unknown external configuration.

The content fingerprint, rather than the policy path, determines effective policy equality. A
single path whose contents change is flagged with `POLICY_CONTENT_CHANGED_AT_SAME_REFERENCE`.
Different paths with the same normalized policy are not treated as policy drift. v0.8.0 reports
without `audit_context` remain valid inputs and receive `AUDIT_PROVENANCE_INCOMPLETE` with limited
comparability.

A changed disposition is an observed report difference, not proof that the Agent changed. Each
changed group has a direction based on its worst disposition rank: `worsened`, `improved`, or
`mixed_or_other`. A changed set whose worst disposition is unchanged is never forced into an
improvement or worsening category. Summary direction counts always equal the number of changed
disposition groups.

Semantic Context Gate metadata is optional and remains disabled by default. Exposure Diff does
not invoke an LLM, external provider, or resolver, compare semantic decisions, lower a policy
disposition, or alter Guard decisions. Mismatched, unknown, or partial semantic evidence limits
comparability; semantic fields remain excluded from the canonical key and output.

`New Exposure` means that a candidate route appears only in the after report. It is not automatic
proof of a new real-world PHI leak. `No Longer Observed` means only that a route is absent from the
after report; it is not proof that the underlying risk was eliminated. This tool performs neither
cross-event identity resolution nor HIPAA compliance determination.
