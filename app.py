"""
Threat Intelligence Assistant — RAG chat with citations and confidence.

Run locally:
    streamlit run app.py
"""

from __future__ import annotations

import importlib
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

import streamlit as st

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
    page_icon="🤖",
    layout="wide",
    initial_sidebar_state="expanded",
)

EXAMPLE_QUERIES = [
    "How is T1059 used?",
    "Recent exploited CVEs affecting Windows?",
    "What is T1059.001 PowerShell execution?",
    "Which KEV entries mention ransomware?",
]


def _get_settings():
    """Reload settings so Streamlit hot-reload picks up configuration changes."""
    importlib.reload(settings_module)
    settings_module.get_settings.cache_clear()
    return settings_module.get_settings()


@st.cache_resource(show_spinner="Loading intelligence index and models...")
def _load_rag_chain() -> ThreatIntelRAGChain:
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


def _count_jsonl_sources() -> Counter[str]:
    settings = _get_settings()
    path = settings.documents_jsonl_path
    if not path.exists():
        return Counter()
    docs = load_documents_jsonl(path)
    return Counter(doc.source_type for doc in docs)


def _load_manifest() -> dict | None:
    settings = _get_settings()
    if not settings.manifest_path.exists():
        return None
    return json.loads(settings.manifest_path.read_text(encoding="utf-8"))


def _run_ingest_command(args: list[str]) -> tuple[int, str]:
    cmd = [sys.executable, str(PROJECT_ROOT / "scripts" / "ingest.py"), *args]
    result = subprocess.run(cmd, cwd=str(PROJECT_ROOT), capture_output=True, text=True)
    return result.returncode, (result.stdout or "") + (result.stderr or "")


def _response_flag(response: RAGResponse | None, name: str, default: bool = False) -> bool:
    """Safely read flags from RAGResponse (handles stale session objects)."""
    if response is None:
        return default
    return bool(getattr(response, name, default))


def _init_session_state() -> None:
    if "messages" not in st.session_state:
        st.session_state.messages = []
    if "last_response" not in st.session_state:
        st.session_state.last_response = None
    if "llm_error" not in st.session_state:
        st.session_state.llm_error = None
    last = st.session_state.get("last_response")
    if last is not None and not hasattr(last, "out_of_scope"):
        st.session_state.last_response = None


def _render_sidebar_how_it_works(settings, manifest: dict | None) -> None:
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
            st.markdown(
                "**Cloud privacy:** your question and retrieved context are sent to "
                "**Groq** for inference. No API key is required from you — the hosted "
                "app is configured by the maintainer."
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


def _render_sidebar_llm_error() -> None:
    err = st.session_state.get("llm_error")
    if err:
        st.sidebar.warning(err)


def _render_sidebar_config(settings) -> None:
    st.sidebar.title("Threat Intel Assistant")
    st.sidebar.markdown(f"**Profile:** `{settings.deployment_profile.value}`")
    st.sidebar.markdown(f"**LLM:** `{settings.llm_provider.value}` / `{settings.llm_model}`")
    hard_abstention = getattr(settings, "hard_abstention_enabled", True)
    st.sidebar.markdown(f"**Hard abstention:** `{hard_abstention}`")
    st.sidebar.markdown(
        f"**Embeddings:** `{settings.embedding_provider.value}` / "
        f"`{settings.effective_embedding_model_name()}`"
    )
    for note in settings.validate_runtime():
        st.sidebar.caption(f"Note: {note}")


def _render_sidebar_response(response: RAGResponse | None) -> None:
    st.sidebar.subheader("Latest answer")
    if response is None:
        st.sidebar.caption("Ask a question to see confidence and sources.")
        return

    st.sidebar.caption(f"Query: {response.question}")

    if _response_flag(response, "out_of_scope"):
        st.sidebar.info("Out-of-scope query — no retrieval or confidence scoring.")
        return

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


def _process_prompt(chain: ThreatIntelRAGChain, prompt: str) -> None:
    """Handle one user prompt and update session state."""
    st.session_state.messages.append({"role": "user", "content": prompt})
    st.session_state.llm_error = None

    try:
        response = chain.invoke(prompt)
        st.session_state.last_response = response
        assistant_text = response.answer
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


def main() -> None:
    _init_session_state()
    settings = _get_settings()

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

    prompt: str | None = None
    if "pending_query" in st.session_state:
        prompt = st.session_state.pop("pending_query")

    chat_prompt = st.chat_input("Ask about techniques, CVEs, or threat intelligence...")
    if chat_prompt:
        prompt = chat_prompt

    if prompt:
        _process_prompt(chain, prompt)
        st.rerun()

    _render_sidebar_config(settings)
    _render_sidebar_how_it_works(settings, manifest)
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

    st.title("Threat Intelligence Assistant")
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
