from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class Candidate:
    category: str
    value: str
    start: int
    end: int
    confidence: float
    reason: str


@dataclass(frozen=True)
class PatternRule:
    category: str
    pattern: re.Pattern[str]
    reason: str
    confidence: float = 0.9
    group: str = "value"


RULES: tuple[PatternRule, ...] = (
    PatternRule(
        "name",
        re.compile(r"\b(?:Patient|Member|Name)\s*:\s*(?P<value>[A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2})\b"),
        "Matched a labeled synthetic person name.",
        0.86,
    ),
    PatternRule(
        "dob",
        re.compile(r"\b(?:DOB|Date of birth)\s*:\s*(?P<value>\d{4}-\d{2}-\d{2}|\d{1,2}/\d{1,2}/\d{4})\b", re.I),
        "Matched a labeled date of birth.",
        0.95,
    ),
    PatternRule(
        "phone",
        re.compile(r"\b(?P<value>555-\d{3}-\d{4})\b"),
        "Matched a synthetic 555 phone number.",
        0.92,
    ),
    PatternRule(
        "address",
        re.compile(
            r"\baddress\s*=\s*(?P<value>\d+\s+[A-Z][A-Za-z]+\s+[A-Z][A-Za-z]+\s+(?:Rd|St|Ave|Blvd|Lane|Ln|Drive|Dr)\.?)\b",
            re.I,
        ),
        "Matched a labeled street address.",
        0.9,
    ),
    PatternRule(
        "member_id",
        re.compile(r"\b(?:Member ID|member_id)\s*[:=]\s*(?P<value>MBR-SYN-\d{4,})\b", re.I),
        "Matched a labeled synthetic member identifier.",
        0.97,
    ),
    PatternRule(
        "claim_id",
        re.compile(r"\b(?:Claim ID|claim_id|claim)\s*[:=]?\s*(?P<value>CLM-SYN-\d{4,})\b", re.I),
        "Matched a synthetic claim identifier.",
        0.94,
    ),
    PatternRule(
        "mrn",
        re.compile(r"\b(?:MRN|mrn)\s*[:=]\s*(?P<value>MRN-SYN-\d{4,})\b"),
        "Matched a labeled synthetic medical record number.",
        0.97,
    ),
)


def detect_candidates(content: str) -> list[Candidate]:
    candidates: list[Candidate] = []
    seen: set[tuple[str, int, int]] = set()

    for rule in RULES:
        for match in rule.pattern.finditer(content):
            value = match.group(rule.group)
            start, end = match.span(rule.group)
            key = (rule.category, start, end)
            if key in seen:
                continue
            seen.add(key)
            candidates.append(
                Candidate(
                    category=rule.category,
                    value=value,
                    start=start,
                    end=end,
                    confidence=rule.confidence,
                    reason=rule.reason,
                )
            )

    return sorted(candidates, key=lambda item: (item.start, item.end, item.category))


def iter_candidates(contents: Iterable[str]) -> Iterable[Candidate]:
    for content in contents:
        yield from detect_candidates(content)
