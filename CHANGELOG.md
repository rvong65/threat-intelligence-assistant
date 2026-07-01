# Changelog

All notable changes to this project are documented in this file.  

Release dates reflect when a version was tagged on GitHub (Release), not necessarily when the repo first went public or when each feature was first committed.

## [1.1.2] - 2026-07-01

### Added

- **Retrieval-only fallback** — when LLM generation fails after successful retrieval, return formatted MITRE/KEV sources without synthesis (`RETRIEVAL_ONLY_FALLBACK`, default `true`)
- **RAG integration tests** — full `chain.invoke` coverage for answer, sources, and confidence (CI: mocked LLM; optional live Groq when `GROQ_API_KEY` set)
- Streamlit sidebar warning and toast for degraded retrieval-only mode

### Changed

- **Groq cloud default** migrated from deprecated `llama-3.1-8b-instant` to `openai/gpt-oss-20b` (auto-migrates legacy 8b and 70b model IDs in settings)
- Clearer Groq 404 / model-unavailable error mapping in `src/llm/errors.py`

## [1.1.1] - 2026-06-23

### Added

- **Privacy & data** disclosures in README (Safety section) and Streamlit sidebar expander
- Live Demo privacy note for public Groq-based Streamlit Cloud demo

## [1.1.0] - 2026-06-23

### Added

- **Docker** — `Dockerfile`, `docker-compose.yml`, and `.dockerignore` for reproducible cloud-profile runs (`docker compose up --build` on port 8501)
- **Docker CI** — GitHub Actions job builds the image and checks Streamlit `/_stcore/health`
- **Architecture documentation** — [`docs/architecture.md`](docs/architecture.md) (goals, diagrams, module map, deployment topologies, safety)
- **SVG assets** — `docs/assets/` (`logo-light.svg`, `logo-dark.svg`, `icon.svg`, `favicon.svg`) with theme-aware README logo
- **CHANGELOG** — this file and GitHub Release discipline
- **README** — collapsible Table of Contents, Version history section, slim Architecture summary linking to full doc, V2 roadmap table

### Changed

- README restructured (Get started → Overview → Technical → Legal)
- Quick Start includes Docker instructions and `.venv` workflow
- `app.py` — custom `page_icon` from `docs/assets/favicon.svg` (replaces emoji)
- Project Status — v1.1 maturity milestone documented

## [1.0.0] - 2026-06-18

First **tagged** release. The repository and Streamlit app were **public since 2026-06-12**; CI, tests, and README polish landed on **2026-06-18** before this tag. 

### Added (2026-06-18 — pre-tag polish)
- GitHub Actions CI — `pytest` on push/PR to `main`
- `requirements.txt` / `requirements-dev.txt` split
- README table of contents and repository layout refresh

### Included (2026-06-12 — initial public MVP)
- RAG chat over **MITRE ATT&CK Enterprise** + **CISA KEV** (3,312 indexed chunks)
- Grounded answers with **mandatory citations**, confidence scoring, and hard abstention
- Query guard, entity-ID-aware retrieval, citation validation, multi-turn memory
- Streamlit UI ([live demo](https://threat-intelligence-rag-assistant.streamlit.app/))
- Dual deployment profile — Ollama (local) / Groq + HuggingFace (cloud)
- Committed FAISS index for clone-and-run deploys
- pytest suite (49 tests) and `validation_matrix.py` (11 PASS / 1 WARN / 0 FAIL on cloud)


[1.1.2]: https://github.com/rvong65/threat-intelligence-assistant/releases/tag/v1.1.2
[1.1.1]: https://github.com/rvong65/threat-intelligence-assistant/releases/tag/v1.1.1
[1.1.0]: https://github.com/rvong65/threat-intelligence-assistant/releases/tag/v1.1.0
[1.0.0]: https://github.com/rvong65/threat-intelligence-assistant/releases/tag/v1.0.0
