#!/usr/bin/env python3
"""
Smoke test — validates RAG pipeline without the Streamlit UI.

Usage:
    python scripts/smoke_test.py
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import json

from config.settings import get_settings
from src.embeddings.factory import get_embeddings
from src.llm.factory import get_llm
from src.rag.chain import ABSTENTION_PHRASE, ThreatIntelRAGChain
from src.rag.memory import ConversationMemory
from src.vectorstore.factory import load_vectorstore

TESTS = [
    ("T1059 query", "How is T1059 used?", False),
    ("Windows KEV query", "Recent exploited CVEs affecting Windows?", False),
    ("Follow-up", "what about PowerShell?", False),
    ("Off-topic weather", "What is the weather in Tokyo?", True),
    ("Group query", "What techniques does G0007 use?", False),
    ("Technique sub-ID", "What is T1059.001 PowerShell execution?", False),
]


def _check_citations(response, label: str) -> list[str]:
    issues: list[str] = []
    if response.citations.cited_ids:
        print(f"  Citations: {response.citations.cited_ids}")
    if response.citations.hallucinated_ids and label not in (
        "Off-topic",
        "T1059 query",
        "Follow-up",
    ):
        issues.append(f"{label}: hallucinated IDs {response.citations.hallucinated_ids}")
    elif response.citations.hallucinated_ids and label == "T1059 query":
        valid = set(response.citations.valid_ids)
        if not any(v.startswith("T1059") for v in valid):
            issues.append(f"{label}: no valid T1059-family citations")
    return issues


def main() -> int:
    get_settings.cache_clear()
    settings = get_settings()
    print(f"LLM: {settings.llm_provider.value} / {settings.llm_model}")
    print(f"Embeddings: {settings.embedding_provider.value}")
    print(f"Hard abstention: {settings.hard_abstention_enabled}")
    print()

    embeddings = get_embeddings(settings)
    vectorstore = load_vectorstore(embeddings, settings)
    llm = get_llm(settings)
    memory = ConversationMemory(max_turns=settings.memory_max_turns)
    chain = ThreatIntelRAGChain(
        vectorstore=vectorstore,
        llm=llm,
        settings=settings,
        memory=memory,
    )

    failures: list[str] = []
    manifest = None
    if settings.manifest_path.exists():
        manifest = json.loads(settings.manifest_path.read_text(encoding="utf-8"))

    for label, query, expect_abstention in TESTS:
        if label == "Group query" and not (manifest or {}).get("source_counts", {}).get(
            "mitre_group"
        ):
            print(f"--- {label}: skipped (rebuild index with groups) ---\n")
            continue
        # Each scenario should stand alone — prior turns pollute follow-up rewrite.
        memory.clear()
        print(f"--- {label}: {query!r} ---")
        try:
            response = chain.invoke(query)
            print(f"  Confidence: {response.confidence.overall}/100")
            print(f"  Sources: {[s.source_id for s in response.citations.sources]}")
            print(f"  Answer preview: {response.answer[:200].replace(chr(10), ' ')}...")
            failures.extend(_check_citations(response, label))

            if expect_abstention:
                if response.out_of_scope:
                    pass
                elif not response.is_abstention and response.confidence.overall >= 50:
                    failures.append(
                        f"{label}: expected abstention/out-of-scope, got confidence "
                        f"{response.confidence.overall}"
                    )
            else:
                if response.is_abstention and label == "T1059 query":
                    failures.append(f"{label}: unexpected abstention")
                if label == "Windows KEV query":
                    kev_sources = [
                        s for s in response.citations.sources
                        if s.source_id.startswith("CVE-")
                    ]
                    if response.is_abstention and not kev_sources:
                        failures.append(
                            f"{label}: abstained without retrieving KEV CVE sources"
                        )
                if label.startswith("Off-topic") and response.out_of_scope:
                    pass
                elif label == "Group query":
                    if not any(
                        s.source_id.startswith("G0007") for s in response.citations.sources
                    ):
                        failures.append(f"{label}: expected G0007 in retrieved sources")
                elif label == "Technique sub-ID":
                    if not any(
                        s.source_id.startswith("T1059") for s in response.citations.sources
                    ):
                        failures.append(
                            f"{label}: expected T1059-family in retrieved sources"
                        )
        except Exception as exc:
            failures.append(f"{label}: {exc}")
            print(f"  ERROR: {exc}")
        print()

    if failures:
        print("SMOKE TEST FAILED:")
        for item in failures:
            print(f"  - {item}")
        return 1

    print("SMOKE TEST PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
