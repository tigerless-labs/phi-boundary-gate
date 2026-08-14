# Trace Adapters

External agent frameworks often log different event shapes. PHI Boundary Gate
does not require those projects to adopt its trace schema internally. Instead,
use `convert-trace` to normalize generic JSONL into the package trace schema,
then run `validate-trace` and `scan-trace`.

Mapping v1 is the supported generic JSONL mapping contract for the `0.5.x`
release line. The adapter is intentionally small: it supports common JSONL event
logs, but it is not a full JSONPath engine and does not try to model every agent
framework.

## CLI Flow

```bash
phi-boundary-gate convert-trace \
  --input samples/external_traces/generic_agent_run.jsonl \
  --mapping samples/trace_mappings/generic_agent.yml \
  --out /tmp/phi-normalized-trace.jsonl \
  --diagnostics /tmp/phi-adapter-diagnostics.json

phi-boundary-gate validate-trace --trace /tmp/phi-normalized-trace.jsonl

phi-boundary-gate scan-trace \
  --trace /tmp/phi-normalized-trace.jsonl \
  --policy samples/policies/default.yml \
  --out /tmp/phi-report.md \
  --json /tmp/phi-report.json \
  --redacted-trace /tmp/phi-redacted-trace.jsonl
```

Validate the mapping itself before converting external traces:

```bash
phi-boundary-gate validate-mapping \
  --mapping samples/trace_mappings/generic_agent.yml
```

Use `--stdout` when a pipeline should avoid writing the normalized trace to disk:

```bash
phi-boundary-gate convert-trace \
  --input raw-agent-events.jsonl \
  --mapping config/phi-trace-map.yml \
  --stdout > /tmp/phi-normalized-trace.jsonl
```

Use `--diagnostics` while tuning a mapping. The diagnostics file summarizes the
converted event count, output layers, destination layers, content paths that
produced text, optional content paths that never matched, generated event IDs,
and value-spec fallback fields selected during conversion:

```bash
phi-boundary-gate convert-trace \
  --input samples/external_traces/callback_agent_run.jsonl \
  --mapping samples/trace_mappings/callback_agent.yml \
  --out /tmp/callback-agent-normalized.jsonl \
  --diagnostics /tmp/callback-agent-diagnostics.json
```

Normalized traces may contain raw PHI when the external input contains raw PHI.
Do not commit them. Prefer short-lived paths, restricted artifact retention, or
an immediate `scan-trace --redacted-trace` step.

## Python API

```python
from phi_boundary_gate import TraceAdapter, TraceMappingError

try:
    adapter = TraceAdapter.from_mapping("config/phi-trace-map.yml")
    events = adapter.load("raw-agent-events.jsonl")
    adapter.write("raw-agent-events.jsonl", "/tmp/phi-normalized-trace.jsonl")
except TraceMappingError as exc:
    raise RuntimeError(f"external trace normalization failed: {exc}") from exc
```

Function-style helpers are also public:

```python
from pathlib import Path

from phi_boundary_gate import build_conversion_diagnostics, load_external_trace, load_trace_mapping, write_converted_trace

events = load_external_trace(Path("raw-agent-events.jsonl"), Path("config/phi-trace-map.yml"))
write_converted_trace(Path("raw-agent-events.jsonl"), Path("config/phi-trace-map.yml"), Path("/tmp/phi-normalized-trace.jsonl"))
mapping = load_trace_mapping(Path("config/phi-trace-map.yml"))
diagnostics = build_conversion_diagnostics(Path("raw-agent-events.jsonl"), mapping)
```

The returned objects are regular `TraceEvent` instances and can be passed to
`build_report` or serialized with the CLI.

## Mapping v1

The mapping file is YAML. A valid mapping v1 file must define:

- `version: 1`
- `timestamp`
- `layer`
- `content`

`event_id` is optional. If it is omitted or its optional field is missing, the
adapter generates `external_evt_0001`, `external_evt_0002`, and so on. Use
`fallback_prefix` to customize that prefix.

The sample mapping covers user input, RAG chunks, tool output, prompt assembly,
memory writes, debug logs, provider destinations, array field paths, multiple
content fields, and metadata includes:

```yaml
version: 1
event_id:
  field: id
  required: false
  fallback_prefix: external_evt
timestamp:
  field: created_at
layer:
  field: event_type
  map:
    human_message: user_message
    retrieval_chunk: rag_context
    tool_result: tool_output
    prompt_assembled: model_input
    memory_write: memory
    debug_log: debug_log
content:
  fields:
    - field: messages.0.content
      label: user_message
      required: false
    - field: tool.response.summary
      label: tool_summary
      required: false
    - field: prompt.user
      label: user_prompt
      required: false
source:
  type:
    field: agent.name
    default: generic_agent
    required: false
  path:
    field: agent.node
    default: unknown_node
    required: false
destinations:
  - layer:
      field: routing.next_layer
      required: false
      map:
        prompt: model_input
    path:
      field: routing.next_path
      required: false
  - layer:
      field: provider.sink
      required: false
    path:
      field: provider.request_path
      required: false
metadata:
  include:
    - run_id
    - conversation_id
    - field: agent.node
      name: agent_node
      required: false
  constants:
    adapter: generic_agent_mapping_v1
```

Value specs such as `event_id`, `timestamp`, `layer`, `source.type`,
`source.path`, destination `layer`, and destination `path` may use `fields` when
agent runtimes use different names for the same concept. The adapter checks the
paths in order and uses the first path that exists and resolves to a non-empty
string or scalar:

```yaml
timestamp:
  fields:
    - timestamp
    - created_at
layer:
  fields:
    - kind
    - event_type
  map:
    message.user: user_message
    tool.done: tool_output
event_id:
  fields:
    - event.id
    - id
  required: false
  fallback_prefix: callback_evt
```

Do not define both `field` and `fields` in the same value spec. Use `default`
for an optional constant fallback and `fallback_prefix` for generated event IDs.

The repository includes a second callback-style mapping fixture that exercises
multi-field fallbacks across event IDs, timestamps, layers, source nodes, and
provider destinations:

```bash
phi-boundary-gate convert-trace \
  --input samples/external_traces/callback_agent_run.jsonl \
  --mapping samples/trace_mappings/callback_agent.yml \
  --out /tmp/callback-agent-normalized.jsonl
```

Supported output layers are:

- `user_message`
- `rag_context`
- `tool_output`
- `model_input`
- `memory`
- `debug_log`

Destination layers may also use `model_provider`.

## Field Paths

Mapping v1 supports dot paths over objects and numeric indexes over arrays:

```text
payload.text
messages.0.content
tool.response.summary
agent.node
```

It does not support filters, wildcards, negative indexes, quoted keys, or full
JSONPath. `fields` is an ordered fallback list of simple field paths, not a query
language. If an external framework needs JSONPath features, add a
project-specific preprocessor or adapter before writing normalized trace events.

## Validation Contract

`validate-mapping` checks mapping structure without reading any external trace
events. It validates:

- mapping version
- required top-level fields
- value spec shapes
- multi-field fallback shapes
- content field shapes
- layer alias outputs
- destination layer outputs
- metadata include shapes
- unsupported mapping keys

`validate-trace` checks normalized JSONL events after conversion. A mapping can be
valid while still failing conversion if a required external event field is
missing in a particular input line.

Diagnostics are conversion-time summaries, not schema validation. Use them to see
whether fallback fields and optional content fields are actually exercised by a
sample trace before relying on the mapping in CI.

## Content Fields

`content.field` copies one external field into the normalized event content.
`content.fields` combines multiple fields with labels:

```yaml
content:
  fields:
    - field: tool.response.summary
      label: tool_summary
      required: false
    - field: tool.response.member_id
      label: member_id
      required: false
```

The normalized content will look like:

```text
tool_summary: Lookup result member_id=MBR-SYN-8842
member_id: MBR-SYN-8842
```

The adapter stores selected content source paths in
`metadata.external_content_paths` so reviewers can see which external fields fed
the scan.

The repository includes a golden normalized fixture:

```text
samples/normalized_traces/generic_agent_expected.jsonl
```

Tests compare the adapter output against that fixture to keep the mapping output
stable across releases.

## Required And Optional Fields

By default, mapped fields are required. Add `required: false` and a `default`
when the external event type may omit a field:

```yaml
source:
  path:
    field: agent.node
    default: unknown_node
    required: false
```

`event_id` can generate deterministic IDs when the external log lacks one:

```yaml
event_id:
  field: id
  required: false
  fallback_prefix: external_evt
```

## Limits

- Only JSONL input is supported.
- Mapping v1 is experimental and intentionally small.
- Streaming deltas, retry deduplication, tool-call pairing, and framework-native
  callback objects should be handled by a project-specific adapter before this
  conversion step.
- The detector still scans normalized event content as text. Field paths are
  preserved in metadata, but findings are not path-aware yet.
