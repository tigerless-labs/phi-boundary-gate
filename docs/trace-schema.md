# Trace Schema

The CLI reads newline-delimited JSON. Each line is one synthetic context event.

## Event Object

Required fields:

- `event_id`: Stable string identifier for the event.
- `timestamp`: ISO-8601 timestamp string.
- `layer`: Context layer name.
- `content`: Text content to scan for PHI candidates.

Optional fields:

- `source`: Object describing where the content came from.
- `destinations`: Array of destination objects that describe where the content flowed.
- `metadata`: Object for synthetic debugging notes.

## Supported Layers

- `user_message`
- `rag_context`
- `tool_output`
- `model_input`
- `memory`
- `debug_log`

## Source Object

Recommended fields:

- `type`: Synthetic source type, such as `synthetic_claim_note`.
- `path`: Source path within the synthetic workflow.

## Destination Object

Recommended fields:

- `layer`: Destination context layer.
- `path`: Destination path inside that layer.

When present, `layer` must be one of the supported layers and `path` must be a string.
`model_provider` is also allowed as a destination sink because it represents flow out of the local context boundary.

## Example

```json
{"event_id":"evt_001","timestamp":"2026-01-15T09:00:00Z","layer":"user_message","source":{"type":"synthetic_user","path":"chat.messages[0]"},"destinations":[{"layer":"model_input","path":"prompt.messages[0].content"}],"content":"Patient: Casey Example. DOB: 1978-04-18."}
```

## Validation Notes

The CLI validates only the fields required to produce a report. Additional fields are preserved as trace metadata but are not interpreted.
