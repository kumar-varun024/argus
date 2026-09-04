# Sprint 31 Implementation Plan: Vector RAG & Semantic Search

## Milestone Breakdown

### Milestone 1: Vector Store & Embedding Engine (R1 & Dependencies)
- **Goal**: Build file-based SQLite-vec vector database with dual-engine fallback (native sqlite-vec + numpy), deterministic offline embedding provider (384-d), disk persistence, and metadata filtering.
- **Files**:
  - `pyproject.toml` (add `sqlite-vec>=0.1.6`)
  - `argus/vector/__init__.py`
  - `argus/vector/models.py`
  - `argus/vector/embeddings.py`
  - `argus/vector/store.py`
  - `argus/vector/exceptions.py`
  - `tests/test_vector_store.py`
- **Verification**: `python -m pytest tests/test_vector_store.py -v` (assert 5+ tests pass, CRUD, persistence, restart survival, filtering).

### Milestone 2: Scan Semantic Search & CVE Knowledge Base (R2 & R3)
- **Goal**: Implement scan evidence & finding indexing post-scan, multi-concept semantic search, CVE feed ingestion, and finding-to-CVE hybrid correlation.
- **Files**:
  - `argus/knowledge/cve_models.py`
  - `argus/knowledge/cve_kb.py`
  - `argus/knowledge/cve_correlator.py`
  - `argus/reporting/vector_indexer.py`
  - `argus/knowledge/__init__.py`
  - `argus/scanning/engine.py` (hook indexing on scan completion)
  - `tests/test_semantic_search.py`
  - `tests/test_cve_kb.py`
- **Verification**: `python -m pytest tests/test_semantic_search.py tests/test_cve_kb.py -v`

### Milestone 3: Workspace Copilot Blended Context Engine (R4)
- **Goal**: Upgrade `ResearchContextEngine` to query vector store for evidence, findings, CVEs, and memories. Upgrade `ContextRanker` with hybrid formula ($S = w_{\text{vec}}S_{\text{vec}} + w_{\text{lex}}S_{\text{lex}} + S_{\text{scope}} + S_{\text{type}}$) and backward-compatible fallback. Upgrade `ContextAssembler` to render CVE and Memory sections.
- **Files**:
  - `argus/workspace/context/models.py`
  - `argus/workspace/context/ranker.py`
  - `argus/workspace/context/engine.py`
  - `argus/workspace/context/assembler.py`
  - `tests/workspace/test_blended_context.py`
- **Verification**: `python -m pytest tests/workspace/ -q`

### Milestone 4: Conversational Learning & Memory System (R5)
- **Goal**: Build persistent multi-session memory system in `argus/memory/` storing attack patterns, user corrections, and key decisions with vector similarity recall.
- **Files**:
  - `argus/memory/__init__.py`
  - `argus/memory/models.py`
  - `argus/memory/store.py`
  - `argus/memory/manager.py`
  - `tests/test_memory.py`
- **Verification**: `python -m pytest tests/test_memory.py -v`

### Milestone 5: Full Validation, Forensics & Victory Handoff (R6)
- **Goal**: Execute full test suite (`python -m pytest tests/ --ignore=tests/workspace -x -q` and `python -m pytest tests/workspace -q`), verify 2,089+ passing tests with 0 regressions + 20+ new tests. Run Reviewers, Challengers, and Forensic Auditor. Publish handoff to `.agents/sprint31_vector_rag/handoff.md`.
