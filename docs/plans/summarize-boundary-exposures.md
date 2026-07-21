# Summarize Boundary Exposures Plan

## Goal

Make the report useful for engineering triage by summarizing where each PHI candidate crosses sensitive context boundaries.

## Scope

- Group findings by `category` and `value`.
- Add top-level `boundary_exposures` to JSON reports.
- Add a Markdown `Boundary Exposures` section.
- Rank exposures by worst policy disposition: `violation`, then `redact`, then `allowed`.
- Recommend a lightweight boundary action from the worst disposition and layer.
- Add tests for grouping, ordering, no-PHI behavior, and Markdown output.

## Acceptance

- The claim-agent sample report lists repeated member and claim identifiers as boundary exposures.
- Each boundary exposure includes ordered layers seen, related event IDs, worst disposition, worst layer, and recommended action.
- No-PHI traces produce an empty `boundary_exposures` array.
- Existing finding-level report details remain available.

## Non-Goals

- No external PHI detector integration.
- No detector category expansion.
- No automatic redaction execution.
- No graph database or causal lineage engine.
- No real-time guardrail behavior.
