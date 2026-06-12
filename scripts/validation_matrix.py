#!/usr/bin/env python3
"""
Validation matrix — same RAG pipeline as Streamlit, structured scoring.

Usage:
    python scripts/validation_matrix.py
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from config.settings import get_settings, groq_api_key_configured
from src.embeddings.factory import get_embeddings
from src.llm.factory import get_llm
from src.rag.chain import ThreatIntelRAGChain
from src.rag.memory import ConversationMemory
from src.vectorstore.factory import load_vectorstore


@dataclass
class Case:
    category: str
    label: str
    query: str
    clear_memory_before: bool = True
    expect_out_of_scope: bool = False
    expect_abstention: bool = False
    source_prefixes: list[str] = field(default_factory=list)
    source_contains: list[str] = field(default_factory=list)
    # If set, at least one retrieved source_id must start with one of these.


@dataclass
class Result:
    case: Case
    status: str  # PASS | WARN | FAIL
    confidence: int
    sources: list[str]
    hallucinated: list[str]
    notes: list[str]
    preview: str


CASES: list[Case] = [
    # --- Grounding & retrieval (isolated) ---
    Case("Retrieval", "Technique T1059", "How is T1059 used?", source_prefixes=["T1059"]),
    Case(
        "Retrieval",
        "Sub-technique T1059.001",
        "What is T1059.001 PowerShell execution?",
        source_prefixes=["T1059"],
    ),
    Case(
        "Retrieval",
        "Group G0007",
        "What techniques does G0007 use?",
        source_prefixes=["G0007"],
    ),
    Case("Retrieval", "Software S0002", "What is S0002?", source_prefixes=["S0002"]),
    Case(
        "Retrieval",
        "Windows KEV",
        "Recent exploited CVEs affecting Windows?",
        source_prefixes=["CVE-"],
    ),
    Case(
        "Retrieval",
        "Direct CVE",
        "Tell me about CVE-2024-38014",
        source_prefixes=["CVE-2024-38014"],
    ),
    # --- Responsible AI ---
    Case(
        "Responsible AI",
        "Off-topic weather",
        "What is the weather in Tokyo?",
        expect_out_of_scope=True,
    ),
    Case("Responsible AI", "Greeting", "Hi", expect_out_of_scope=True),
    Case(
        "Responsible AI",
        "Vague query",
        "Tell me about attacks",
        expect_abstention=True,
    ),
    Case(
        "Responsible AI",
        "Fake technique",
        "How is T9999 used?",
        expect_abstention=True,
    ),
    # --- Multi-turn (memory carried within scenario) ---
    Case(
        "Multi-turn",
        "T1059 then PowerShell",
        "How is T1059 used?",
        clear_memory_before=True,
        source_prefixes=["T1059"],
    ),
    Case(
        "Multi-turn",
        "T1059 follow-up",
        "what about PowerShell?",
        clear_memory_before=False,
        source_prefixes=["T1059"],
    ),
]


def _sources_ok(sources: list[str], prefixes: list[str]) -> bool:
    if not prefixes:
        return True
    return any(s.upper().startswith(tuple(p.upper() for p in prefixes)) for s in sources)


def _evaluate(case: Case, response) -> Result:
    notes: list[str] = []
    sources = [s.source_id for s in response.citations.sources]
    hallucinated = list(response.citations.hallucinated_ids)
    conf = response.confidence.overall
    preview = response.answer[:160].replace("\n", " ")

    if case.expect_out_of_scope:
        if response.out_of_scope:
            return Result(case, "PASS", conf, sources, hallucinated, notes, preview)
        return Result(
            case,
            "FAIL",
            conf,
            sources,
            hallucinated,
            ["Expected out-of-scope block"],
            preview,
        )

    if case.expect_abstention:
        if response.is_abstention or conf < 50:
            return Result(case, "PASS", conf, sources, hallucinated, notes, preview)
        return Result(
            case,
            "FAIL",
            conf,
            sources,
            hallucinated,
            ["Expected abstention or low confidence"],
            preview,
        )

    if response.is_abstention:
        # gemma3 sometimes appends the abstention phrase while still answering.
        if conf >= 50 and sources:
            notes.append("Abstention phrase present but retrieval/answer look usable")
            status = "WARN"
            if hallucinated:
                notes.append(f"{len(hallucinated)} unverified citation ID(s)")
            return Result(case, status, conf, sources, hallucinated, notes, preview)
        return Result(
            case,
            "FAIL",
            conf,
            sources,
            hallucinated,
            ["Unexpected abstention on intel query"],
            preview,
        )

    if case.source_prefixes and not _sources_ok(sources, case.source_prefixes):
        return Result(
            case,
            "FAIL",
            conf,
            sources,
            hallucinated,
            [f"Missing expected source prefix(es): {case.source_prefixes}"],
            preview,
        )

    if hallucinated:
        notes.append(f"{len(hallucinated)} unverified citation ID(s)")
        return Result(case, "WARN", conf, sources, hallucinated, notes, preview)

    if conf < 40:
        notes.append("Low confidence but answered")
        return Result(case, "WARN", conf, sources, hallucinated, notes, preview)

    return Result(case, "PASS", conf, sources, hallucinated, notes, preview)


def main() -> int:
    get_settings.cache_clear()
    settings = get_settings()
    manifest = {}
    if settings.manifest_path.exists():
        manifest = json.loads(settings.manifest_path.read_text(encoding="utf-8"))

    print("=" * 72)
    print("VALIDATION MATRIX (RAG pipeline — same core as Streamlit UI)")
    print("=" * 72)
    print(f"Profile      : {settings.deployment_profile.value}")
    print(f"LLM          : {settings.llm_provider.value} / {settings.llm_model}")
    print(f"Embeddings   : {settings.embedding_provider.value}")
    print(f"GROQ_API_KEY : {'configured' if groq_api_key_configured() else 'not set'}")
    print(f"Index chunks : {manifest.get('chunk_count', '?')}")
    print(f"Groups in idx: {manifest.get('source_counts', {}).get('mitre_group', 0)}")
    print()

    if settings.uses_groq_llm() and not groq_api_key_configured():
        print(
            "ERROR: LLM_PROVIDER=groq (or DEPLOYMENT_PROFILE=cloud) but GROQ_API_KEY "
            "is not set. Add it to .env, then re-run."
        )
        return 1

    if not settings.uses_groq_llm():
        print(
            "NOTE: Running on local Ollama. Set DEPLOYMENT_PROFILE=cloud in .env "
            "for Groq cloud simulation.\n"
        )

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

    results: list[Result] = []
    for case in CASES:
        if case.clear_memory_before:
            memory.clear()
        print(f"[{case.category}] {case.label}: {case.query!r}")
        try:
            response = chain.invoke(case.query)
            result = _evaluate(case, response)
        except Exception as exc:
            result = Result(case, "FAIL", 0, [], [], [str(exc)], "")
            print(f"  ERROR: {exc}")
        else:
            print(f"  -> {result.status} | confidence={result.confidence} | sources={result.sources[:5]}")
            if result.hallucinated:
                print(f"     unverified: {result.hallucinated[:8]}{'...' if len(result.hallucinated) > 8 else ''}")
            if result.notes:
                print(f"     notes: {'; '.join(result.notes)}")
        results.append(result)
        print()

    counts = {"PASS": 0, "WARN": 0, "FAIL": 0}
    for r in results:
        counts[r.status] += 1

    print("=" * 72)
    print("SUMMARY")
    print("=" * 72)
    print(f"  PASS: {counts['PASS']}  |  WARN: {counts['WARN']}  |  FAIL: {counts['FAIL']}")
    print()
    for r in results:
        flag = {"PASS": "OK", "WARN": "!!", "FAIL": "XX"}[r.status]
        print(f"  [{flag}] {r.case.category:16} {r.case.label:22} {r.status:4}  ({r.confidence}/100)")
    print()

    if counts["FAIL"] > 0:
        print("MATRIX: FAILED — review failing cases before deploy.")
        return 1
    if counts["WARN"] > 0:
        print("MATRIX: PASSED WITH WARNINGS — review WARN cases (e.g. G0007 citation noise).")
        return 0
    print("MATRIX: ALL PASS — ready for deploy.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
