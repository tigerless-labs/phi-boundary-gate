# Compliance Policy Schema

The compliance policy is YAML. It describes the organization-approved service profiles that may receive PHI after `guard_text` detects PHI candidates.

## Top-Level Fields

- `version`: Compliance policy version. The loader expects `1`.
- `default_action`: `block` or `allow`. Use `block` for fail-closed behavior.
- `phi_statuses`: Mapping of PHI status to whether BAA coverage is required.
- `environments`: Mapping of environment name to runtime requirements.
- `services`: Mapping of service profile id to approved service metadata.

## PHI Statuses

Supported status names:

- `non_phi`
- `synthetic`
- `deidentified`
- `real_phi`

Example:

```yaml
phi_statuses:
  real_phi:
    requires_baa: true
  synthetic:
    requires_baa: false
```

## Environment Policy

Supported fields:

- `require_redacted_logging`: Boolean. When true, raw logging blocks PHI traffic.
- `require_audit`: Boolean. Stored in the decision audit metadata for callers to enforce.

## Service Profile

Supported fields:

- `vendor`: Provider id used by the calling project.
- `service`: Service id used by the calling project.
- `covered_service`: Whether this service profile is confirmed to be covered for the workflow.
- `baa_executed`: Whether the organization has confirmed an executed BAA for this service profile.
- `allowed_phi_status`: PHI statuses this profile may handle.
- `model_patterns`: Shell-style model name patterns that match this profile.
- `denied_model_patterns`: Shell-style model name patterns that block PHI.
- `allowed_features`: Features allowed for PHI. Empty means no allowlist is enforced.
- `denied_features`: Features that block PHI.
- `allowed_logging`: Logging modes allowed for PHI.
- `allowed_storage`: Storage modes allowed for PHI.
- `allow_preview`: Whether preview, beta, or experimental models may handle PHI.
- `deny_reason`: Human-readable reason for profiles kept only to produce clear block output.
- `notes`: Internal notes for maintainers.

## Example

```yaml
version: 1
default_action: block
phi_statuses:
  real_phi:
    requires_baa: true
environments:
  production:
    require_redacted_logging: true
    require_audit: true
services:
  approved_llm:
    vendor: acme
    service: llm_api
    covered_service: true
    baa_executed: true
    allowed_phi_status: [real_phi]
    model_patterns: [acme-ga-model]
    denied_model_patterns: ["*preview*", "*beta*", "*experimental*"]
    allowed_features: [online_prediction]
    denied_features: [web_search, external_tools]
    allowed_logging: [metadata_only, redacted_only]
    allowed_storage: [none, encrypted_controlled]
    allow_preview: false
```

## Boundary

The sample policy is synthetic. Do not treat it as a vendor compliance source of truth. Replace it with organization-approved facts before using the guard for real PHI workflows.
