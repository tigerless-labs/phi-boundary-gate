from __future__ import annotations

from typing import Any

from .detectors import Candidate


DEFAULT_PRESIDIO_ENTITIES = (
    "PERSON",
    "PHONE_NUMBER",
    "EMAIL_ADDRESS",
    "LOCATION",
    "DATE_TIME",
    "US_SSN",
    "IP_ADDRESS",
    "URL",
    "US_DRIVER_LICENSE",
    "CREDIT_CARD",
)

PRESIDIO_CATEGORY_MAP = {
    "PERSON": "name",
    "PHONE_NUMBER": "phone",
    "EMAIL_ADDRESS": "email",
    "LOCATION": "address",
    "DATE_TIME": "date",
    "US_SSN": "ssn",
    "IP_ADDRESS": "ip_address",
    "URL": "url",
    "US_DRIVER_LICENSE": "license_number",
    "CREDIT_CARD": "account_number",
}


def detect_presidio_candidates(
    content: str,
    *,
    analyzer: object | None = None,
    language: str = "en",
    entities: tuple[str, ...] = DEFAULT_PRESIDIO_ENTITIES,
) -> list[Candidate]:
    engine = analyzer if analyzer is not None else _load_analyzer()
    results = engine.analyze(text=content, language=language, entities=list(entities))
    candidates: list[Candidate] = []

    for result in results:
        entity_type = str(_get_attr(result, "entity_type"))
        category = PRESIDIO_CATEGORY_MAP.get(entity_type)
        if category is None:
            continue
        start = int(_get_attr(result, "start"))
        end = int(_get_attr(result, "end"))
        if start < 0 or end <= start or end > len(content):
            continue
        while start < end and content[start].isspace():
            start += 1
        while end > start and content[end - 1].isspace():
            end -= 1
        if end <= start:
            continue
        score = float(_get_attr(result, "score", 0.5))
        value = content[start:end]
        candidates.append(
            Candidate(
                category=category,
                value=value,
                start=start,
                end=end,
                confidence=score,
                reason=f"Detected by Presidio {entity_type} recognizer.",
                detector="presidio",
            )
        )

    return candidates


def _load_analyzer() -> Any:
    try:
        from presidio_analyzer import AnalyzerEngine
    except ImportError as exc:
        raise ValueError(
            "Presidio detection was requested but 'presidio-analyzer' is not installed. "
            "Install optional dependencies with: pip install -e '.[ner]'"
        ) from exc
    return AnalyzerEngine()


def _get_attr(value: object, name: str, default: object | None = None) -> object:
    if isinstance(value, dict):
        return value.get(name, default)
    return getattr(value, name, default)
