# PHI Boundary Gate Report

- Trace: `samples/traces/claim_agent_minimal.jsonl`
- Policy: `samples/policies/default.yml`
- Total PHI candidates: 14
- Boundary exposures: 7
- Violations: 2
- Redaction required: 8
- High-risk candidates: 14

All findings are PHI candidates from a rule-based detector and require human review.

## Boundary Exposures

| ID | Category | Value | Layers Seen | Worst Disposition | Worst Layer | Recommended Action |
| --- | --- | --- | --- | --- | --- | --- |
| exposure-001 | claim_id | `CLM-SYN-44501` | user_message -> tool_output -> model_input -> debug_log -> memory | violation | debug_log | Remove or redact before debug_log. |
| exposure-002 | member_id | `MBR-SYN-8842` | user_message -> tool_output -> model_input -> debug_log | violation | debug_log | Remove or redact before debug_log. |
| exposure-003 | phone | `555-013-4421` | rag_context | redact | rag_context | Redact before rag_context. |
| exposure-004 | address | `101 Example Harbor Rd` | tool_output | redact | tool_output | Redact before tool_output. |
| exposure-005 | mrn | `MRN-SYN-22091` | tool_output | redact | tool_output | Redact before tool_output. |
| exposure-006 | dob | `1978-04-18` | user_message | allowed | user_message | Review only; no policy boundary action required. |
| exposure-007 | name | `Casey Example` | user_message | allowed | user_message | Review only; no policy boundary action required. |

## Findings

| ID | Event | Layer | Category | Value | Disposition | Risk | Redaction |
| --- | --- | --- | --- | --- | --- | --- | --- |
| finding-001 | evt_001 | user_message | name | `Casey Example` | allowed | high | `[REDACTED_NAME]` |
| finding-002 | evt_001 | user_message | dob | `1978-04-18` | allowed | high | `[REDACTED_DOB]` |
| finding-003 | evt_001 | user_message | member_id | `MBR-SYN-8842` | allowed | high | `[REDACTED_MEMBER_ID]` |
| finding-004 | evt_001 | user_message | claim_id | `CLM-SYN-44501` | allowed | high | `[REDACTED_CLAIM_ID]` |
| finding-005 | evt_002 | rag_context | phone | `555-013-4421` | redact | high | `[REDACTED_PHONE]` |
| finding-006 | evt_003 | tool_output | claim_id | `CLM-SYN-44501` | redact | high | `[REDACTED_CLAIM_ID]` |
| finding-007 | evt_003 | tool_output | member_id | `MBR-SYN-8842` | redact | high | `[REDACTED_MEMBER_ID]` |
| finding-008 | evt_003 | tool_output | mrn | `MRN-SYN-22091` | redact | high | `[REDACTED_MRN]` |
| finding-009 | evt_003 | tool_output | address | `101 Example Harbor Rd` | redact | high | `[REDACTED_ADDRESS]` |
| finding-010 | evt_004 | model_input | claim_id | `CLM-SYN-44501` | redact | high | `[REDACTED_CLAIM_ID]` |
| finding-011 | evt_004 | model_input | member_id | `MBR-SYN-8842` | redact | high | `[REDACTED_MEMBER_ID]` |
| finding-012 | evt_005 | debug_log | member_id | `MBR-SYN-8842` | violation | high | `[REDACTED_MEMBER_ID]` |
| finding-013 | evt_005 | debug_log | claim_id | `CLM-SYN-44501` | violation | high | `[REDACTED_CLAIM_ID]` |
| finding-014 | evt_006 | memory | claim_id | `CLM-SYN-44501` | redact | high | `[REDACTED_CLAIM_ID]` |

## Paths

### finding-001

- Detector: Matched a labeled synthetic person name. Confidence: 0.86.
- Policy: name has no layer-specific restriction for user_message.
- Source: `{"path": "chat.messages[0]", "type": "synthetic_member_chat"}`
- Destinations: `[{"layer": "model_input", "path": "prompt.messages[0].content"}]`

### finding-002

- Detector: Matched a labeled date of birth. Confidence: 0.95.
- Policy: dob has no layer-specific restriction for user_message.
- Source: `{"path": "chat.messages[0]", "type": "synthetic_member_chat"}`
- Destinations: `[{"layer": "model_input", "path": "prompt.messages[0].content"}]`

### finding-003

- Detector: Matched a labeled synthetic member identifier. Confidence: 0.97.
- Policy: member_id has no layer-specific restriction for user_message.
- Source: `{"path": "chat.messages[0]", "type": "synthetic_member_chat"}`
- Destinations: `[{"layer": "model_input", "path": "prompt.messages[0].content"}]`

### finding-004

- Detector: Matched a synthetic claim identifier. Confidence: 0.94.
- Policy: claim_id has no layer-specific restriction for user_message.
- Source: `{"path": "chat.messages[0]", "type": "synthetic_member_chat"}`
- Destinations: `[{"layer": "model_input", "path": "prompt.messages[0].content"}]`

### finding-005

- Detector: Matched a synthetic 555 phone number. Confidence: 0.92.
- Policy: phone requires redaction in rag_context.
- Source: `{"path": "claims.synthetic_note[12]", "type": "synthetic_claim_note"}`
- Destinations: `[{"layer": "model_input", "path": "prompt.context[0]"}]`

### finding-006

- Detector: Matched a synthetic claim identifier. Confidence: 0.94.
- Policy: claim_id requires redaction in tool_output.
- Source: `{"path": "tools.claim_lookup.response", "type": "synthetic_claim_lookup"}`
- Destinations: `[{"layer": "model_input", "path": "prompt.context[1]"}, {"layer": "debug_log", "path": "logs.debug.claim_lookup"}]`

### finding-007

- Detector: Matched a labeled synthetic member identifier. Confidence: 0.97.
- Policy: member_id requires redaction in tool_output.
- Source: `{"path": "tools.claim_lookup.response", "type": "synthetic_claim_lookup"}`
- Destinations: `[{"layer": "model_input", "path": "prompt.context[1]"}, {"layer": "debug_log", "path": "logs.debug.claim_lookup"}]`

### finding-008

- Detector: Matched a labeled synthetic medical record number. Confidence: 0.97.
- Policy: mrn requires redaction in tool_output.
- Source: `{"path": "tools.claim_lookup.response", "type": "synthetic_claim_lookup"}`
- Destinations: `[{"layer": "model_input", "path": "prompt.context[1]"}, {"layer": "debug_log", "path": "logs.debug.claim_lookup"}]`

### finding-009

- Detector: Matched a labeled street address. Confidence: 0.90.
- Policy: address requires redaction in tool_output.
- Source: `{"path": "tools.claim_lookup.response", "type": "synthetic_claim_lookup"}`
- Destinations: `[{"layer": "model_input", "path": "prompt.context[1]"}, {"layer": "debug_log", "path": "logs.debug.claim_lookup"}]`

### finding-010

- Detector: Matched a synthetic claim identifier. Confidence: 0.94.
- Policy: claim_id requires redaction in model_input.
- Source: `{"path": "prompt", "type": "assembled_prompt"}`
- Destinations: `[{"layer": "model_provider", "path": "request.messages"}]`

### finding-011

- Detector: Matched a labeled synthetic member identifier. Confidence: 0.97.
- Policy: member_id requires redaction in model_input.
- Source: `{"path": "prompt", "type": "assembled_prompt"}`
- Destinations: `[{"layer": "model_provider", "path": "request.messages"}]`

### finding-012

- Detector: Matched a labeled synthetic member identifier. Confidence: 0.97.
- Policy: member_id is denied in debug_log.
- Source: `{"path": "logs.debug.claim_lookup", "type": "synthetic_logger"}`
- Destinations: `[]`

### finding-013

- Detector: Matched a synthetic claim identifier. Confidence: 0.94.
- Policy: claim_id is denied in debug_log.
- Source: `{"path": "logs.debug.claim_lookup", "type": "synthetic_logger"}`
- Destinations: `[]`

### finding-014

- Detector: Matched a synthetic claim identifier. Confidence: 0.94.
- Policy: claim_id requires redaction in memory.
- Source: `{"path": "memory.session.summary", "type": "synthetic_agent_memory"}`
- Destinations: `[{"layer": "model_input", "path": "prompt.memory"}]`
