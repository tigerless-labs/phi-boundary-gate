# Policy Schema

The policy is YAML. It maps PHI candidate categories to layer-specific rules and redaction placeholders.

## Top-Level Fields

- `version`: Policy version number. The CLI expects `1`.
- `categories`: Mapping of category name to category policy.

## Category Policy

Supported fields:

- `description`: Human-readable category description.
- `high_risk`: Boolean. High-risk findings are highlighted in reports.
- `deny_layers`: Layers where the category should not appear.
- `redact_layers`: Layers where the category may appear only with redaction.
- `allow_layers`: Layers where the category may appear without a policy finding.
- `redaction`: Suggested replacement value.

## Disposition

The policy engine returns one disposition per candidate:

- `violation`: The category appeared in a denied layer.
- `redact`: The category appeared in a layer that requires redaction.
- `allowed`: The category appeared in an allowed or unspecified layer.

`deny_layers` has precedence over `redact_layers`; `redact_layers` has precedence over `allow_layers`.

Layer names in policy lists must be supported context layers.

## Example

```yaml
version: 1
categories:
  member_id:
    description: Synthetic member identifier.
    high_risk: true
    deny_layers:
      - debug_log
    redact_layers:
      - model_input
    redaction: "[REDACTED_MEMBER_ID]"
```

## Boundary

Policy expresses development-time audit behavior only. It is not a legal or compliance determination.
