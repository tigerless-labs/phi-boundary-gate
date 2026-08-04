# Validation Notes

The CLI validates synthetic trace and policy inputs before report generation. Validation is intentionally strict for structural contracts and intentionally conservative for PHI detection.

## Trace Validation

Each JSONL event must be a JSON object with:

- `event_id`: string
- `timestamp`: string
- `layer`: supported context layer
- `content`: string

Optional object fields must have the expected shape:

- `source`: object
- `source.type`: string, when present
- `source.path`: string, when present
- `destinations`: array of objects
- `destinations[].layer`: supported context layer or `model_provider` sink, when present
- `destinations[].path`: string, when present
- `metadata`: object

Empty lines in JSONL traces are ignored. Invalid JSON, missing required fields, unsupported layers, and malformed destination objects fail before report generation.

Validate a trace without scanning:

```bash
phi-boundary-gate validate-trace --trace normalized-trace.jsonl
```

Normalize a generic external JSONL trace before validation:

```bash
phi-boundary-gate convert-trace \
  --input raw-agent-events.jsonl \
  --mapping config/phi-trace-map.yml \
  --out normalized-trace.jsonl
```

## Policy Validation

The YAML policy must be an object with:

- `version: 1`
- non-empty `categories`

Each category must define:

- `redaction`: non-empty string

Optional category fields are validated when present:

- `description`: string
- `high_risk`: boolean
- `deny_layers`: string array of supported context layers
- `redact_layers`: string array of supported context layers
- `allow_layers`: string array of supported context layers

If the same layer appears in multiple policy lists, precedence is:

1. `deny_layers`
2. `redact_layers`
3. `allow_layers`

## CLI Errors

Input validation errors are written to stderr and return exit code `2`. Successful report generation returns `0`.
