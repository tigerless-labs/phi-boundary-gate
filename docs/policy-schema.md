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

The bundled sample policy includes categories for common synthetic PHI variants
such as `name`, `dob`, `date`, `phone`, `fax`, `email`, `ssn`, `address`,
`zip_code`, `member_id`, `claim_id`, `mrn`, `policy_number`, `group_number`,
`account_number`, `license_number`, `vehicle_id`, `device_id`, `url`, and
`ip_address`. Consuming projects should copy and adapt the sample policy rather
than relying on unconfigured categories. If a detector returns a category that is
not present in the policy, the policy engine marks it `allowed` with
`risk="unknown"` so the caller can decide whether to fail closed.

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
