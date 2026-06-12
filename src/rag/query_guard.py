"""Pre-retrieval guards for out-of-scope or vague analyst queries."""

from __future__ import annotations

import re

from src.rag.retriever import (
    CVE_PATTERN,
    GROUP_PATTERN,
    SOFTWARE_PATTERN,
    TECHNIQUE_PATTERN,
)

GREETING_PATTERN = re.compile(
    r"^\s*(hi|hello|hey|thanks|thank you|yo|sup|good\s+(morning|afternoon|evening))[\s!.?]*$",
    re.IGNORECASE,
)

SOCIAL_PATTERN = re.compile(
    r"^\s*(how are you|how're you|how r you|what'?s up|how is it going|"
    r"how do you do|nice to meet you)[\s!.?]*$",
    re.IGNORECASE,
)

HELP_PATTERN = re.compile(
    r"^\s*(help|what can you do|who are you)[\s!.?]*$",
    re.IGNORECASE,
)

OFF_TOPIC_PATTERN = re.compile(
    r"\b(weather|forecast|temperature|recipe|cook|cooking|sports|football|"
    r"basketball|movie|music|joke|poem|stock price|bitcoin price)\b",
    re.IGNORECASE,
)


def is_out_of_scope_query(question: str) -> bool:
    """Return True for greetings, social chat, or non-intel queries."""
    return not is_threat_intel_query(question)


def is_threat_intel_query(question: str) -> bool:
    """
    Return False for greetings and queries too vague to ground in MITRE/KEV.

    Requires a technique ID, CVE ID, or at least two substantive words
    related to threat intelligence.
    """
    text = question.strip()
    if not text:
        return False

    if (
        GREETING_PATTERN.match(text)
        or SOCIAL_PATTERN.match(text)
        or HELP_PATTERN.match(text)
        or OFF_TOPIC_PATTERN.search(text)
    ):
        return False

    if (
        TECHNIQUE_PATTERN.search(text)
        or GROUP_PATTERN.search(text)
        or SOFTWARE_PATTERN.search(text)
        or CVE_PATTERN.search(text)
    ):
        return True

    lower = text.lower()
    intel_keywords = (
        "mitre",
        "attack",
        "technique",
        "tactic",
        "cve",
        "vulnerability",
        "exploit",
        "kev",
        "ransomware",
        "malware",
        "threat",
        "powershell",
        "windows",
        "linux",
        "adversary",
        "campaign",
    )
    if any(re.search(rf"\b{re.escape(kw)}\b", lower) for kw in intel_keywords):
        return True

    # Longer general-knowledge questions without intel signals are not answerable.
    word_count = len(re.findall(r"\w+", text))
    return word_count >= 6


def out_of_scope_message(question: str) -> str:
    """User-facing guidance when a query is not threat-intelligence scoped."""
    return (
        "I can only answer **threat intelligence questions** grounded in MITRE ATT&CK "
        "and CISA KEV data.\n\n"
        "Try asking about a technique (e.g. *How is T1059 used?*), a group or "
        "software ID (e.g. *G0007* or *S0002*), a CVE, or exploited vulnerabilities "
        "for a platform (e.g. *Recent exploited CVEs affecting Windows?*)."
    )
