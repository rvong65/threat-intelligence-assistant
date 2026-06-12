"""Grounded prompt templates for citation-enforced RAG generation."""

from __future__ import annotations

from langchain_core.documents import Document

GROUNDED_SYSTEM_PROMPT = """You are a Threat Intelligence Assistant for security analysts.

STRICT RULES — follow every rule:
1. Answer ONLY using information in the provided CONTEXT blocks. Do not use outside knowledge.
2. Every factual statement MUST end with an inline citation in EXACTLY this format: [T1059.001], [G0007], [S0154], or [CVE-2024-1234]
   - CORRECT: Adversaries use PowerShell for execution [T1059.001]
   - WRONG: Citation: Powershell Remote Commands
   - WRONG: [Citation: PoetRat Lua](T1059.011)
   - WRONG: (T1059.011)
3. Do NOT cite external reference names from context — cite only the source_id from CONTEXT headers.
4. Do NOT invent technique IDs, CVE IDs, vendor names, or products not present in CONTEXT.
5. If CONTEXT is insufficient, respond EXACTLY with:
   "I don't have enough grounded evidence to answer confidently."
   Then suggest what the analyst could clarify.
6. Keep answers concise (under 200 words unless listing multiple items). Use bullet points when helpful.
7. Use only source_id values that appear in CONTEXT headers.

Allowed citation formats: [T####], [T####.###], [G####], [S####], [CVE-YYYY-NNNN] — nothing else.
"""

HUMAN_PROMPT_TEMPLATE = """CONVERSATION HISTORY (may be empty):
{history}

CONTEXT (retrieved intelligence — cite using source_id values shown):
{context}

ANALYST QUESTION:
{question}

Provide a grounded answer with inline [source_id] citations for every factual claim."""


def format_context_block(documents: list[Document]) -> str:
    """Format retrieved chunks with explicit source_id headers for citation grounding."""
    blocks: list[str] = []
    for index, doc in enumerate(documents, start=1):
        meta = doc.metadata
        source_id = meta.get("source_id", "UNKNOWN")
        title = meta.get("title", "")
        source_type = meta.get("source_type", "")
        url = meta.get("url", "")
        header = (
            f"--- CONTEXT {index} | source_id: {source_id} | "
            f"type: {source_type} | title: {title} | url: {url} ---"
        )
        blocks.append(f"{header}\n{doc.page_content}")
    return "\n\n".join(blocks) if blocks else "(No context retrieved)"


def build_prompt_messages(
    question: str,
    context_documents: list[Document],
    history_text: str = "",
) -> list[tuple[str, str]]:
    """Return (role, content) pairs for LangChain chat invocation."""
    context = format_context_block(context_documents)
    human_content = HUMAN_PROMPT_TEMPLATE.format(
        history=history_text or "(none)",
        context=context,
        question=question,
    )
    return [
        ("system", GROUNDED_SYSTEM_PROMPT),
        ("human", human_content),
    ]
