"""
Threat Intelligence Assistant — Streamlit presentation layer.

Thin UI over the RAG stack in ``src/rag/``:
  query → guard → retrieve → generate → cite → confidence / abstention

Deployment profiles (``config/settings.py``):
  - cloud: Groq LLM + HuggingFace embeddings (Streamlit Community Cloud default)
  - local: Ollama LLM + embeddings; admin ingest panel enabled

Run locally:
    streamlit run app.py
"""

from __future__ import annotations

import base64
import html
import importlib
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

import streamlit as st

# ---------------------------------------------------------------------------
# Bootstrap — ensure project root is importable when launched via Streamlit.
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import config.settings as settings_module
from config.settings import EmbeddingProvider
from src.embeddings.factory import get_embeddings
from src.ingestion.normalize import load_documents_jsonl
from src.llm.errors import LLMUserError
from src.llm.factory import get_llm
from src.rag.chain import RAGResponse, ThreatIntelRAGChain
from src.rag.memory import ConversationMemory
from src.vectorstore.factory import load_vectorstore

st.set_page_config(
    page_title="Threat Intelligence Assistant",
    page_icon=str(PROJECT_ROOT / "docs" / "assets" / "favicon.svg"),
    layout="wide",
    initial_sidebar_state="expanded",
)

EXAMPLE_QUERIES = [
    "How is T1059 used?",
    "Recent exploited CVEs affecting Windows?",
    "What is T1059.001 PowerShell execution?",
    "Which KEV entries mention ransomware?",
]

ICON_PATH = PROJECT_ROOT / "docs" / "assets" / "icon.svg"


# ---------------------------------------------------------------------------
# Custom HTML helpers (branding + sidebar runtime card)
# ---------------------------------------------------------------------------
def _render_html(container: st.delta_generator.DeltaGenerator, markup: str) -> None:
    """
    Render raw HTML without Markdown parsing.

    Prefer ``st.html`` over ``markdown(unsafe_allow_html=True)`` — indented HTML
    inside markdown strings is interpreted as a code block and shown as text.
    """
    if hasattr(container, "html"):
        container.html(markup)
    else:
        container.markdown(markup, unsafe_allow_html=True)


def _svg_data_uri(path: Path) -> str:
    """Inline SVG as a data URI for use in custom HTML headings."""
    encoded = base64.b64encode(path.read_bytes()).decode("ascii")
    return f"data:image/svg+xml;base64,{encoded}"


def _render_branded_heading(
    title: str,
    *,
    container: st.delta_generator.DeltaGenerator,
    icon_px: int = 44,
    heading_tag: str = "h1",
    heading_size: str = "2.25rem",
    gap: str = "0.35rem",
) -> None:
    """Left-aligned product icon immediately before the title text."""
    icon_uri = _svg_data_uri(ICON_PATH)
    _render_html(
        container,
        f'<div style="display:flex;align-items:center;gap:{gap};margin:0 0 0.25rem 0;">'
        f'<img src="{icon_uri}" width="{icon_px}" height="{icon_px}" alt="" '
        f'style="flex-shrink:0;display:block;"/>'
        f'<{heading_tag} style="margin:0;padding:0;font-size:{heading_size};font-weight:600;'
        f'line-height:1.2;color:inherit;">{html.escape(title)}</{heading_tag}></div>',
    )


# ---------------------------------------------------------------------------
# Settings and RAG chain lifecycle
# ---------------------------------------------------------------------------
def _get_settings():
    """
    Reload settings on each access.

    Streamlit hot-reload does not invalidate ``@lru_cache`` on ``get_settings``;
    clearing the cache here keeps sidebar profile/LLM labels in sync with ``.env``.
    """
    importlib.reload(settings_module)
    settings_module.get_settings.cache_clear()
    return settings_module.get_settings()


@st.cache_resource(show_spinner="Loading intelligence index and models...")
def _load_rag_chain() -> ThreatIntelRAGChain:
    """
    Build the full RAG stack once per process (expensive: FAISS + embed + LLM).

    Call ``_load_rag_chain.clear()`` after index rebuild or "Clear conversation"
    so the next request picks up a fresh chain and empty memory.
    """
    settings = _get_settings()
    embeddings = get_embeddings(settings)
    vectorstore = load_vectorstore(embeddings, settings)
    llm = get_llm(settings)
    return ThreatIntelRAGChain(
        vectorstore=vectorstore,
        llm=llm,
        settings=settings,
        memory=ConversationMemory(max_turns=settings.memory_max_turns),
    )


# ---------------------------------------------------------------------------
# Corpus / ingest helpers (local admin panel)
# ---------------------------------------------------------------------------
def _count_jsonl_sources() -> Counter[str]:
    """Count documents per ``source_type`` in processed JSONL (local dev only)."""
    settings = _get_settings()
    path = settings.documents_jsonl_path
    if not path.exists():
        return Counter()
    docs = load_documents_jsonl(path)
    return Counter(doc.source_type for doc in docs)


def _load_manifest() -> dict | None:
    """Load committed FAISS index manifest (chunk counts, corpus version)."""
    settings = _get_settings()
    if not settings.manifest_path.exists():
        return None
    return json.loads(settings.manifest_path.read_text(encoding="utf-8"))


def _run_ingest_command(args: list[str]) -> tuple[int, str]:
    """Run ``scripts/ingest.py`` in a subprocess; return exit code and combined output."""
    cmd = [sys.executable, str(PROJECT_ROOT / "scripts" / "ingest.py"), *args]
    result = subprocess.run(cmd, cwd=str(PROJECT_ROOT), capture_output=True, text=True)
    return result.returncode, (result.stdout or "") + (result.stderr or "")


# ---------------------------------------------------------------------------
# Session state
# ---------------------------------------------------------------------------
def _response_flag(response: RAGResponse | None, name: str, default: bool = False) -> bool:
    """
    Safely read boolean flags from ``RAGResponse``.

    Guards against stale session objects after code deploys (older instances may
    lack newer dataclass fields such as ``out_of_scope``).
    """
    if response is None:
        return default
    return bool(getattr(response, name, default))


def _init_session_state() -> None:
    """Initialize chat history and drop incompatible cached responses after deploy."""
    if "messages" not in st.session_state:
        st.session_state.messages = []
    if "last_response" not in st.session_state:
        st.session_state.last_response = None
    if "llm_error" not in st.session_state:
        st.session_state.llm_error = None
    last = st.session_state.get("last_response")
    if last is not None and not hasattr(last, "out_of_scope"):
        st.session_state.last_response = None


# ---------------------------------------------------------------------------
# Sidebar renderers
# ---------------------------------------------------------------------------
def _render_sidebar_how_it_works(settings, manifest: dict | None) -> None:
    """End-user documentation: pipeline, confidence formula, cloud privacy."""
    with st.sidebar.expander("How it works", expanded=False):
        st.markdown(
            "**Threat Intelligence Assistant** answers analyst questions using "
            "retrieved MITRE ATT&CK and CISA KEV data only — not open-web knowledge."
        )
        st.markdown(
            "1. **Query guard** — blocks greetings and off-topic prompts  \n"
            "2. **Retrieval** — FAISS similarity search (+ ID boost for T/G/S/CVE)  \n"
            "3. **Generation** — grounded LLM answer with mandatory citations  \n"
            "4. **Validation** — confidence score + unverified citation warnings"
        )
        st.caption(
            "Confidence = 0.60×retrieval + 0.25×coverage + 0.15×citation_match "
            "(see sidebar breakdown after each answer)."
        )
        st.markdown(
            "**Citations:** use `[T1059]`, `[G0007]`, `[S0002]`, `[CVE-2024-…]` "
            "from retrieved sources. **Abstention:** weak evidence → no speculative answer."
        )
        if settings.is_cloud():
            st.caption(
                "Cloud profile: see **Privacy & data** below for where your questions are sent."
            )
            st.caption("If the service is rate-limited, wait a moment and try again.")
        if manifest:
            counts = manifest.get("source_counts", {})
            st.markdown(
                f"**Index:** {manifest.get('chunk_count', '?')} chunks — "
                f"{counts.get('mitre_attack', 0)} techniques, "
                f"{counts.get('mitre_group', 0)} groups, "
                f"{counts.get('mitre_software', 0)} software, "
                f"{counts.get('cisa_kev', 0)} KEV entries."
            )


def _render_sidebar_privacy(settings) -> None:
    """Data-flow disclosure for cloud demo and local/Ollama deployments."""
    with st.sidebar.expander("Privacy & data", expanded=False):
        st.markdown(
            "This app is **decision support**, not a certified data-processing platform. "
            "Understand where your input may go:"
        )
        if settings.is_cloud():
            st.markdown(
                "- **Questions & follow-ups** → **Groq** (answer generation)  \n"
                "- **Query text** → **HuggingFace** (`nomic-embed-text-v1` embeddings)  \n"
                "- **Retrieved MITRE/KEV chunks** → included in the Groq prompt  \n"
                "- **Session chat** → Streamlit memory only; not stored in a project database"
            )
            st.markdown(
                "**Public demo:** Do not submit classified data, credentials, PII, or live "
                "incident details you cannot share with Groq or HuggingFace. Prefer "
                "example queries or synthetic analyst-style questions."
            )
            st.caption("No API key is required from you — the hosted app is configured by the maintainer.")
        else:
            st.markdown(
                "- **LLM answers** → **Ollama** on your network (when configured)  \n"
                "- **Query embeddings** → Ollama or HuggingFace per your `.env`  \n"
                "- **Retrieved chunks** → sent to your local LLM only  \n"
                "- **Session chat** → Streamlit memory only; not stored in a project database"
            )
        st.caption(
            "Streamlit Cloud and cloud API providers may retain operational logs under "
            "their own policies. Full table: README Privacy & data section on GitHub."
        )


def _render_sidebar_llm_error() -> None:
    """Surface mapped Groq / LLM errors from the most recent failed request."""
    err = st.session_state.get("llm_error")
    if err:
        st.sidebar.warning(err)


def _render_sidebar_config(settings) -> None:
    """
    Active deployment profile card (sidebar).

    Values mirror ``config/settings.py``; runtime warnings come from
    ``settings.validate_runtime()`` (e.g. missing GROQ_API_KEY, HF cold start).
    """
    profile = settings.deployment_profile.value
    llm = f"{settings.llm_provider.value} / {settings.llm_model}"
    hard_abstention = getattr(settings, "hard_abstention_enabled", True)
    embeddings = (
        f"{settings.embedding_provider.value} / "
        f"{settings.effective_embedding_model_name()}"
    )

    profile_color = "#5eb8e8" if profile == "cloud" else "#a78bfa"
    abstention_bg = "rgba(94,234,212,0.15)" if hard_abstention else "rgba(148,163,184,0.12)"
    abstention_fg = "#5eead4" if hard_abstention else "#94a3b8"
    abstention_label = "Enabled" if hard_abstention else "Disabled"

    def _row(label: str, value: str, accent: str, value_html: str | None = None) -> str:
        # Single-line HTML — multi-line indented markup breaks in st.markdown.
        cell = value_html if value_html is not None else (
            f'<span style="color:#f1f5f9;font-family:ui-monospace,monospace;'
            f'font-size:0.76rem;word-break:break-word;">{html.escape(value)}</span>'
        )
        return (
            f'<div style="display:flex;align-items:flex-start;gap:10px;padding:11px 12px;'
            f'background:rgba(255,255,255,0.04);border-radius:9px;border-left:3px solid {accent};'
            f'margin-bottom:8px;">'
            f'<span style="min-width:88px;font-size:0.72rem;font-weight:600;letter-spacing:0.04em;'
            f'text-transform:uppercase;color:#94a3b8;padding-top:2px;">{html.escape(label)}</span>'
            f'<div style="flex:1;">{cell}</div></div>'
        )

    profile_badge = (
        f'<span style="display:inline-block;padding:3px 10px;border-radius:999px;'
        f'font-size:0.76rem;font-weight:600;font-family:ui-monospace,monospace;'
        f'background:rgba(94,184,232,0.18);color:{profile_color};'
        f'border:1px solid rgba(94,184,232,0.35);">{html.escape(profile)}</span>'
    )
    abstention_badge = (
        f'<span style="display:inline-block;padding:3px 10px;border-radius:999px;'
        f'font-size:0.76rem;font-weight:600;background:{abstention_bg};color:{abstention_fg};'
        f'border:1px solid {abstention_fg}33;">{abstention_label}</span>'
    )

    rows = (
        _row("Profile", profile, profile_color, profile_badge)
        + _row("LLM", llm, "#f59e0b")
        + _row("Abstention", abstention_label, "#5eead4", abstention_badge)
        + _row("Embeddings", embeddings, "#38bdf8")
    )

    _render_html(
        st.sidebar,
        f'<div style="background:linear-gradient(160deg,#1c2333 0%,#262730 55%,#1e2430 100%);'
        f'border:1px solid rgba(31,119,180,0.45);border-radius:14px;padding:14px 14px 10px;'
        f'margin:0 0 12px 0;box-shadow:0 8px 28px rgba(0,0,0,0.35);">'
        f'<div style="display:flex;align-items:center;gap:8px;margin-bottom:12px;">'
        f'<span style="width:8px;height:8px;border-radius:50%;'
        f'background:linear-gradient(135deg,#5eead4,#1f77b4);'
        f'box-shadow:0 0 10px rgba(94,234,212,0.55);"></span>'
        f'<span style="font-size:0.7rem;font-weight:700;letter-spacing:0.1em;text-transform:uppercase;'
        f'background:linear-gradient(90deg,#8ec8f0,#5eead4);-webkit-background-clip:text;'
        f'-webkit-text-fill-color:transparent;background-clip:text;">Runtime</span></div>'
        f"{rows}</div>",
    )
    for note in settings.validate_runtime():
        st.sidebar.caption(f"Note: {note}")


def _render_sidebar_response(response: RAGResponse | None) -> None:
    """Confidence, citation sources, and validation warnings for the latest answer."""
    st.sidebar.subheader("Latest answer")
    if response is None:
        st.sidebar.caption("Ask a question to see confidence and sources.")
        return

    st.sidebar.caption(f"Query: {response.question}")

    if _response_flag(response, "out_of_scope"):
        st.sidebar.info("Out-of-scope query — no retrieval or confidence scoring.")
        return

    if _response_flag(response, "degraded_retrieval_only"):
        st.sidebar.warning(
            "Retrieval-only mode — LLM unavailable; showing sources without synthesis."
        )

    confidence = response.confidence
    st.sidebar.progress(confidence.overall / 100, text=f"Confidence: {confidence.overall}/100")
    if confidence.is_low_confidence:
        st.sidebar.warning("Low confidence — verify against primary sources.")

    with st.sidebar.expander("Confidence breakdown", expanded=False):
        for line in confidence.explanation_lines():
            st.caption(line)
        st.caption(confidence.formula)

    st.sidebar.subheader("Retrieved sources")
    for source in response.citations.sources:
        boost_tag = " (boosted)" if source.boosted else ""
        st.sidebar.markdown(
            f"**{source.rank}. [{source.source_id}]({source.url})**{boost_tag}\n\n"
            f"{source.title}\n\n"
            f"*distance: {source.score:.3f} (lower = better)*"
        )

    if _response_flag(response, "hard_abstained"):
        st.sidebar.info("Hard abstention — answer blocked due to low confidence.")

    if response.citations.hallucinated_ids:
        st.sidebar.error(
            "Unverified citations: " + ", ".join(response.citations.hallucinated_ids)
        )

    if response.retrieval_query != response.question:
        st.sidebar.caption(f"Retrieval query: `{response.retrieval_query}`")


# ---------------------------------------------------------------------------
# Chat interaction
# ---------------------------------------------------------------------------
def _process_prompt(chain: ThreatIntelRAGChain, prompt: str) -> None:
    """
    Run one user turn through the RAG chain and update session state.

    ``LLMUserError`` carries end-user-safe messages (rate limits, auth).
    Generic exceptions are collapsed to a single friendly chat bubble.
    """
    st.session_state.messages.append({"role": "user", "content": prompt})
    st.session_state.llm_error = None

    try:
        response = chain.invoke(prompt)
        st.session_state.last_response = response
        assistant_text = response.answer
        if _response_flag(response, "degraded_retrieval_only"):
            st.toast(
                "Showing retrieved sources only — LLM temporarily unavailable.",
                icon="ℹ️",
            )
        if (
            response.confidence
            and not response.is_abstention
            and not _response_flag(response, "out_of_scope")
        ):
            assistant_text = (
                f"{response.answer}\n\n---\n*Confidence: {response.confidence.overall}/100*"
            )
        st.session_state.messages.append(
            {"role": "assistant", "content": assistant_text}
        )
    except LLMUserError as exc:
        st.session_state.llm_error = exc.user_message
        st.session_state.last_response = None
        if exc.is_rate_limit:
            st.toast("Groq rate limit reached — please wait and try again.", icon="⚠️")
        st.session_state.messages.append(
            {"role": "assistant", "content": exc.user_message}
        )
    except Exception:
        st.session_state.llm_error = (
            "**Could not generate an answer.** Please try again in a moment."
        )
        st.session_state.last_response = None
        st.session_state.messages.append(
            {
                "role": "assistant",
                "content": st.session_state.llm_error,
            }
        )


# ---------------------------------------------------------------------------
# Application entry
# ---------------------------------------------------------------------------
def main() -> None:
    _init_session_state()
    settings = _get_settings()

    # Committed index is required — cloud deploys ship indices/faiss_index/ in git.
    index_ready = settings.manifest_path.exists()
    if not index_ready:
        st.error(
            "FAISS index not found. Run `python scripts/ingest.py --build-index` locally."
        )
        return

    try:
        chain = _load_rag_chain()
    except Exception as exc:
        st.error(f"Failed to load RAG chain: {exc}")
        if settings.llm_provider.value == "ollama":
            st.info("Ensure Ollama is running with your configured LLM and `nomic-embed-text`.")
        elif settings.llm_provider.value == "groq":
            st.info("The hosted service could not reach Groq. Try again in a moment.")
        return

    manifest = _load_manifest()

    # Collect prompt from example buttons (pending_query) or chat input, then rerun.
    prompt: str | None = None
    if "pending_query" in st.session_state:
        prompt = st.session_state.pop("pending_query")

    chat_prompt = st.chat_input("Ask about techniques, CVEs, or threat intelligence...")
    if chat_prompt:
        prompt = chat_prompt

    if prompt:
        _process_prompt(chain, prompt)
        st.rerun()

    # --- Sidebar: branding, runtime config, latest answer metadata ---
    _render_branded_heading(
        "Threat Intel Assistant",
        container=st.sidebar,
        icon_px=32,
        heading_tag="h2",
        heading_size="1.25rem",
        gap="0.25rem",
    )
    _render_sidebar_config(settings)
    _render_sidebar_how_it_works(settings, manifest)
    _render_sidebar_privacy(settings)
    _render_sidebar_llm_error()
    st.sidebar.divider()
    _render_sidebar_response(st.session_state.last_response)
    st.sidebar.divider()
    if st.sidebar.button("Clear conversation"):
        st.session_state.messages = []
        st.session_state.last_response = None
        st.session_state.llm_error = None
        _load_rag_chain.clear()
        st.rerun()

    # --- Main panel: chat history and example queries ---
    _render_branded_heading(
        "Threat Intelligence Assistant",
        container=st,
        gap="0.3rem",
    )
    st.caption(
        "Grounded answers from MITRE ATT&CK and CISA KEV with mandatory citations."
    )
    if settings.embedding_provider == EmbeddingProvider.HUGGINGFACE:
        if not st.session_state.get("hf_cold_start_noted"):
            st.info(
                "First query may take 30–60 seconds while HuggingFace embedding "
                "models load (cloud cold start)."
            )
            st.session_state.hf_cold_start_noted = True

    st.markdown("**Try an example:**")
    example_cols = st.columns(2)
    for index, query in enumerate(EXAMPLE_QUERIES):
        col = example_cols[index % 2]
        if col.button(query, key=f"example_{index}", use_container_width=True):
            st.session_state.pending_query = query
            st.rerun()

    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])

    # Local-only maintainer tools — hidden on cloud (no raw data / ingest on Streamlit).
    if not settings.is_cloud():
        with st.expander("Corpus status and ingestion (admin)"):
            st.markdown(
                "Maintainer tools for **local development only**. Use this to verify datasets, "
                "inspect the indexed corpus, and rebuild the FAISS index after data updates."
            )
            col1, col2, col3, col4 = st.columns(4)
            col1.metric("MITRE raw", "OK" if settings.mitre_path.exists() else "Missing")
            col2.metric("KEV raw", "OK" if settings.kev_path.exists() else "Missing")
            col3.metric(
                "JSONL",
                "OK" if settings.documents_jsonl_path.exists() else "Missing",
            )
            col4.metric("FAISS", "OK" if index_ready else "Missing")

            counts = _count_jsonl_sources()
            if counts:
                st.write(dict(counts))

            if manifest:
                st.json(manifest)

            st.caption("Cloud deploys: build index locally, commit indices/, redeploy.")

            btn_col1, btn_col2 = st.columns(2)
            with btn_col1:
                if st.button("Validate datasets", key="validate_btn"):
                    with st.spinner("Validating..."):
                        code, output = _run_ingest_command(["--validate-only"])
                    st.code(output)
                    if code != 0:
                        st.error("Validation failed.")
            with btn_col2:
                if st.button("Build FAISS index", key="build_btn"):
                    with st.spinner("Building index..."):
                        code, output = _run_ingest_command(["--build-index"])
                    st.code(output)
                    if code == 0:
                        _load_rag_chain.clear()
                        st.success("Index rebuilt. Refresh the page.")
                    else:
                        st.error("Index build failed.")


if __name__ == "__main__":
    main()
