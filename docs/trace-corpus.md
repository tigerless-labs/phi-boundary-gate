# Trace Corpus

The trace corpus is a synthetic regression set for PHI candidate detection and
context-boundary reporting. It is not production PHI and does not claim real-world
coverage. Each valid trace has a matching expectation file under
`samples/trace_expectations/`; CI checks those expectations and the committed
coverage report.

## Coverage Matrix

| Trace | Purpose | Kind | Expected categories |
| --- | --- | --- | --- |
| `claim_agent_minimal.jsonl` | End-to-end boundary flow across user, RAG, tool, model input, debug log, memory, and provider destination. | Positive | `name`, `dob`, `date`, `phone`, `address`, `member_id`, `claim_id` |
| `expanded_phi_variants.jsonl` | Broader US healthcare and insurance identifier variants. | Positive | `name`, `phone`, `email`, `address`, `zip_code`, `member_id`, `policy_number`, `group_number`, `account_number`, `mrn`, `ssn`, `vehicle_id`, `device_id`, `url`, `ip_address` |
| `false_positive_near_misses.jsonl` | Non-PHI language that looks close to IDs, claims, public addresses, or support text. | Negative | none |
| `free_text_phi_variants.jsonl` | Less rigid free-text names, phone numbers, addresses, dates, and emails. | Positive | `name`, `phone`, `email`, `address`, `date` |
| `no_phi.jsonl` | General claim appeal support without identifiers. | Negative | none |
| `provider_boundary_phi.jsonl` | Lara-style provider boundary with user input, tool output, memory, prompt assembly, and debug logging. | Positive | `name`, `member_id`, `claim_id`, `phone`, `address` |
| `structured_payload_phi.jsonl` | JSON-shaped tool, prompt, debug, and memory content stored as trace strings. | Positive | `name`, `dob`, `phone`, `email`, `member_id`, `claim_id`, `account_number`, `policy_number`, `ip_address` |

## Expectations

Expectation files define the executable contract for each trace:

- `min_findings` and `max_findings`
- `min_boundary_exposures`
- required categories
- required layers
- known gaps that are not treated as regressions yet

Use ranges instead of exact finding counts for positive traces so legitimate
detector improvements do not make the corpus brittle. Negative near-miss traces
can stay strict with `max_findings: 0`.

## Coverage Report

Generate the committed baseline:

```bash
PYTHONPATH=src python3 tools/trace_corpus_report.py \
  --traces samples/traces \
  --expectations samples/trace_expectations \
  --policy samples/policies/default.yml \
  --out reports/trace-corpus-coverage.json
```

The report contains aggregate counts and expectation status only. It intentionally
does not list matched PHI candidate values.

## Current Known Gaps

- International phone, address, and identifier formats are not covered.
- Multilingual names and addresses are not covered.
- Relative dates such as "last Friday" are documented but not required to match.
- JSON-shaped content is scanned as text; detection is not path-aware yet.
- OCR, PDFs, HTML snippets, and CSV files are not represented.
- Presidio-backed free-text detection is tested with an adapter-level fake, not
  with a live NLP model in CI.

## Adding A Trace

1. Add a synthetic JSONL file under `samples/traces/`.
2. Add an expectation YAML file under `samples/trace_expectations/`.
3. Regenerate `reports/trace-corpus-coverage.json`.
4. Update the coverage matrix when the scenario is materially new.
5. Run the unit tests, release guard, and CLI smoke checks.
