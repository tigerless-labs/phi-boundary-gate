# Trace Adapters

External agent frameworks often log different event shapes. PHI Boundary Gate
does not require those projects to adopt its trace schema internally. Instead,
use `convert-trace` to normalize generic JSONL into the package trace schema,
then run `validate-trace` and `scan-trace`.

The mapping v1 adapter is intentionally small and experimental. It supports
common JSONL event logs, but it is not a full JSONPath engine and does not try to
model every agent framework.

## CLI Flow

```bash
phi-boundary-gate convert-trace \
  --input samples/external_traces/generic_agent_run.jsonl \
  --mapping samples/trace_mappings/generic_agent.yml \
  --out /tmp/phi-normalized-trace.jsonl

phi-boundary-gate validate-trace --trace /tmp/phi-normalized-trace.jsonl

phi-boundary-gate scan-trace \
  --trace /tmp/phi-normalized-trace.jsonl \
  --policy samples/policies/default.yml \
  --out /tmp/phi-report.md \
  --json /tmp/phi-report.json \
  --redacted-trace /tmp/phi-redacted-trace.jsonl
```

Use `--stdout` when a pipeline should avoid writing the normalized trace to disk:

```bash
phi-boundary-gate convert-trace \
  --input raw-agent-events.jsonl \
  --mapping config/phi-trace-map.yml \
  --stdout > /tmp/phi-normalized-trace.jsonl
```

Normalized traces may contain raw PHI when the external input contains raw PHI.
Do not commit them. Prefer short-lived paths, restricted artifact retention, or
an immediate `scan-trace --redacted-trace` step.

## Python API

```python
from pathlib import Path

from phi_boundary_gate import load_external_trace, write_converted_trace

events = load_external_trace(
    Path("raw-agent-events.jsonl"),
    Path("config/phi-trace-map.yml"),
)

write_converted_trace(
    Path("raw-agent-events.jsonl"),
    Path("config/phi-trace-map.yml"),
    Path("/tmp/phi-normalized-trace.jsonl"),
)
```

The returned objects are regular `TraceEvent` instances and can be passed to
`build_report` or serialized with the CLI.

## Mapping v1

The mapping file is YAML:

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
JSONPath. If an external framework needs those features, add a project-specific
preprocessor or adapter before writing normalized trace events.

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
