from __future__ import annotations


DISPOSITION_RANK = {"allowed": 0, "redact": 1, "violation": 2}


def redaction_action(disposition: str) -> str:
    if disposition == "violation":
        return "remove_or_redact_before_this_layer"
    if disposition == "redact":
        return "redact_before_this_layer"
    return "review"


def recommended_boundary_action(disposition: str, layer: str) -> str:
    if disposition == "violation":
        return f"Remove or redact before {layer}."
    if disposition == "redact":
        return f"Redact before {layer}."
    return "Review only; no policy boundary action required."


def worst_disposition(dispositions: list[str]) -> str:
    if not dispositions:
        return "allowed"
    return max(dispositions, key=lambda item: DISPOSITION_RANK[item])
