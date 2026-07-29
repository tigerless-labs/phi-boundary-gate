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
    detector: str = "regex"


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
        re.compile(
            r"\b(?:Patient|Patient Name|Member|Member Name|Subscriber|Subscriber Name|Name|Full Name|"
            r"Emergency Contact|Spouse)\s*:\s*"
            r"(?P<value>[A-Z][A-Za-z'’-]+(?:\s+[A-Z]\.)?(?:\s+[A-Z][A-Za-z'’-]+){1,3})\b"
        ),
        "Matched a labeled synthetic person name.",
        0.86,
    ),
    PatternRule(
        "name",
        re.compile(
            r"\b(?:Patient|Member|Subscriber|Name)\s*:\s*"
            r"(?P<value>[A-Z][A-Za-z'’-]+,\s*[A-Z][A-Za-z'’-]+(?:\s+[A-Z]\.)?)\b"
        ),
        "Matched a labeled comma-form person name.",
        0.84,
    ),
    PatternRule(
        "dob",
        re.compile(r"\b(?:DOB|Date of birth|Birth date|Birthdate)\s*[:=]\s*(?P<value>\d{4}-\d{2}-\d{2}|\d{1,2}/\d{1,2}/\d{4})\b", re.I),
        "Matched a labeled date of birth.",
        0.95,
    ),
    PatternRule(
        "date",
        re.compile(
            r"\b(?:admission date|admitted|discharge date|discharged|date of service|service date|"
            r"appointment date|death date|visit date)\s*[:=]?\s*"
            r"(?P<value>\d{4}-\d{2}-\d{2}|\d{1,2}/\d{1,2}/\d{2,4}|[A-Z][a-z]+ \d{1,2}, \d{4})\b",
            re.I,
        ),
        "Matched an individual-related healthcare date.",
        0.82,
    ),
    PatternRule(
        "phone",
        re.compile(
            r"(?<!\d)(?P<value>(?:\+?1[-.\s]?)?(?:\(\d{3}\)|\d{3})[-.\s]?\d{3}[-.\s]?\d{4}"
            r"(?:\s*(?:x|ext\.?|extension)\s*\d{1,6})?)(?!\d)",
            re.I,
        ),
        "Matched a phone number.",
        0.92,
    ),
    PatternRule(
        "fax",
        re.compile(
            r"\b(?:fax|facsimile)\s*[:=]\s*"
            r"(?P<value>(?:\+?1[-.\s]?)?(?:\(\d{3}\)|\d{3})[-.\s]?\d{3}[-.\s]?\d{4})(?!\d)",
            re.I,
        ),
        "Matched a labeled fax number.",
        0.9,
    ),
    PatternRule(
        "email",
        re.compile(r"\b(?P<value>[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,})\b", re.I),
        "Matched an email address.",
        0.94,
    ),
    PatternRule(
        "ssn",
        re.compile(r"\b(?:SSN|Social Security(?: Number)?)\s*[:=]?\s*(?P<value>\d{3}-\d{2}-\d{4}|XXX-XX-\d{4})\b", re.I),
        "Matched a labeled Social Security number.",
        0.96,
    ),
    PatternRule(
        "address",
        re.compile(
            r"\baddress\s*[:=]\s*(?P<value>\d+\s+(?:[A-Z][A-Za-z.'’-]+\s+){1,6}"
            r"(?:Rd|Road|St|Street|Ave|Avenue|Blvd|Boulevard|Lane|Ln|Drive|Dr|Court|Ct|"
            r"Circle|Cir|Way|Place|Pl)\.?"
            r"(?:,\s*(?:Apt|Apartment|Suite|Ste|Unit|#)\s*[\w-]+)?"
            r"(?:,\s*[A-Z][A-Za-z .'-]+,\s*[A-Z]{2}\s+\d{5}(?:-\d{4})?)?)\b",
            re.I,
        ),
        "Matched a labeled street address.",
        0.9,
    ),
    PatternRule(
        "address",
        re.compile(
            r"\b(?P<value>\d+\s+(?:[A-Z][A-Za-z.'’-]+\s+){1,6}"
            r"(?:Rd|Road|St|Street|Ave|Avenue|Blvd|Boulevard|Lane|Ln|Drive|Dr|Court|Ct|"
            r"Circle|Cir|Way|Place|Pl)\.?"
            r"(?:,\s*(?:Apt|Apartment|Suite|Ste|Unit|#)\s*[\w-]+)?"
            r"(?:,\s*[A-Z][A-Za-z .'-]+,\s*[A-Z]{2}\s+\d{5}(?:-\d{4})?)?)\b"
        ),
        "Matched a street address pattern.",
        0.78,
    ),
    PatternRule(
        "address",
        re.compile(r"\b(?P<value>P\.?O\.?\s+Box\s+\d{2,10})\b", re.I),
        "Matched a post office box address.",
        0.88,
    ),
    PatternRule(
        "zip_code",
        re.compile(r"\b(?:ZIP|ZIP code|postal code)\s*[:=]?\s*(?P<value>\d{5}(?:-\d{4})?)\b", re.I),
        "Matched a labeled ZIP or postal code.",
        0.86,
    ),
    PatternRule(
        "member_id",
        re.compile(
            r"\b(?:Member ID|member_id|subscriber(?: id)?|subscriber_id|beneficiary(?: number| id)?|"
            r"health plan(?: beneficiary)?(?: number| id)?)\s*[:=#]?\s*"
            r"(?P<value>(?=[A-Z0-9-]*\d)[A-Z0-9]{2,}(?:-[A-Z0-9]{2,})*)\b",
            re.I,
        ),
        "Matched a labeled member, subscriber, or health plan identifier.",
        0.95,
    ),
    PatternRule(
        "member_id",
        re.compile(r"\b(?P<value>MBR-SYN-\d{4,})\b", re.I),
        "Matched a synthetic member identifier.",
        0.94,
    ),
    PatternRule(
        "claim_id",
        re.compile(
            r"\b(?:Claim ID|claim_id|claim number|claim|authorization(?: number| id)?|auth(?: number| id)?)"
            r"\s*[:=#]?\s*(?P<value>(?=[A-Z0-9-]*\d)[A-Z]{2,}-?[A-Z0-9]{2,}(?:-[A-Z0-9]{2,})*)\b",
            re.I,
        ),
        "Matched a labeled claim or authorization identifier.",
        0.93,
    ),
    PatternRule(
        "claim_id",
        re.compile(r"\b(?P<value>CLM-SYN-\d{4,})\b", re.I),
        "Matched a synthetic claim identifier.",
        0.92,
    ),
    PatternRule(
        "mrn",
        re.compile(r"\b(?:MRN|mrn|Medical Record(?: Number)?|Record No\.?)\s*[:=#]?\s*(?P<value>[A-Z]*-?\d[\dA-Z-]{3,})\b", re.I),
        "Matched a labeled medical record number.",
        0.97,
    ),
    PatternRule(
        "policy_number",
        re.compile(r"\b(?:Policy No\.?|Policy Number|policy_number)\s*[:=#]?\s*(?P<value>[A-Z0-9]{2,}(?:-[A-Z0-9]{2,})+)\b", re.I),
        "Matched a labeled policy number.",
        0.9,
    ),
    PatternRule(
        "group_number",
        re.compile(r"\b(?:Group No\.?|Group Number|group_number)\s*[:=#]?\s*(?P<value>[A-Z0-9]{2,}(?:-[A-Z0-9]{2,})*)\b", re.I),
        "Matched a labeled group number.",
        0.88,
    ),
    PatternRule(
        "account_number",
        re.compile(r"\b(?:Account No\.?|Account Number|account_number|Acct #?)\s*[:=#]?\s*(?P<value>[A-Z0-9-]{5,})\b", re.I),
        "Matched a labeled account number.",
        0.88,
    ),
    PatternRule(
        "license_number",
        re.compile(r"\b(?:License No\.?|License Number|Certificate No\.?|Certificate Number)\s*[:=#]?\s*(?P<value>[A-Z0-9-]{5,})\b", re.I),
        "Matched a labeled license or certificate number.",
        0.86,
    ),
    PatternRule(
        "vehicle_id",
        re.compile(r"\b(?:VIN|Vehicle ID|License Plate|Plate)\s*[:=#]?\s*(?P<value>[A-HJ-NPR-Z0-9-]{5,17})\b", re.I),
        "Matched a labeled vehicle identifier.",
        0.86,
    ),
    PatternRule(
        "device_id",
        re.compile(r"\b(?:Device ID|Device Serial|Serial Number|serial)\s*[:=#]?\s*(?P<value>[A-Z0-9-]{5,})\b", re.I),
        "Matched a labeled device identifier.",
        0.84,
    ),
    PatternRule(
        "url",
        re.compile(r"\b(?P<value>https?://[^\s<>\]\)\"']+)", re.I),
        "Matched a URL.",
        0.9,
    ),
    PatternRule(
        "ip_address",
        re.compile(
            r"\b(?P<value>(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d))\b"
        ),
        "Matched an IPv4 address.",
        0.9,
    ),
)


def detect_candidates(
    content: str,
    *,
    enable_presidio: bool = False,
    presidio_analyzer: object | None = None,
) -> list[Candidate]:
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
                    detector="regex",
                )
            )

    if enable_presidio:
        from .presidio_detector import detect_presidio_candidates

        candidates.extend(detect_presidio_candidates(content, analyzer=presidio_analyzer))

    return _merge_candidates(candidates)


def iter_candidates(contents: Iterable[str]) -> Iterable[Candidate]:
    for content in contents:
        yield from detect_candidates(content)


def _merge_candidates(candidates: list[Candidate]) -> list[Candidate]:
    best_by_exact_span: dict[tuple[str, int, int], Candidate] = {}
    for candidate in candidates:
        key = (candidate.category, candidate.start, candidate.end)
        existing = best_by_exact_span.get(key)
        if existing is None or _candidate_rank(candidate) > _candidate_rank(existing):
            best_by_exact_span[key] = candidate

    merged: list[Candidate] = []
    for candidate in sorted(best_by_exact_span.values(), key=_candidate_sort_key):
        if any(_overlaps(candidate, kept) for kept in merged):
            continue
        merged.append(candidate)

    return sorted(merged, key=lambda item: (item.start, item.end, item.category))


def _candidate_sort_key(candidate: Candidate) -> tuple[int, int, float, int, str]:
    return (
        candidate.start,
        -_detector_priority(candidate.detector),
        -candidate.confidence,
        -(candidate.end - candidate.start),
        candidate.category,
    )


def _candidate_rank(candidate: Candidate) -> tuple[int, float, int]:
    return (_detector_priority(candidate.detector), candidate.confidence, candidate.end - candidate.start)


def _detector_priority(detector: str) -> int:
    if detector == "regex":
        return 2
    return 1


def _overlaps(left: Candidate, right: Candidate) -> bool:
    return left.start < right.end and right.start < left.end
