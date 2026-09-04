# Dispatch Log

## 2026-09-03T09:35:41Z
You are the SWE Orchestrator for Sprint 31a: Conversational Memory System for the ARGUS security scanner.

Working directory: /home/varun/argus/.agents/swe_sprint31a
Workspace root: /home/varun/argus
Original request: /home/varun/argus/.agents/ORIGINAL_REQUEST.md
Handoff destination: /home/varun/argus/.agents/swe_sprint31a/handoff.md

Your mission is to implement the conversational memory system (`argus/memory/`) with vector-backed persistence, integrate it into `ResearchContextEngine`, write comprehensive unit, adversarial, and integration tests, verify zero regressions across the codebase, update sprint_handoff.md, and deliver a clean handoff.

## Detailed Requirements

### R1. Memory Data Models & Store (`argus/memory/`)
Implement the memory system module with these components:
1. `argus/memory/models.py`:
   - Data models for memory entries covering: attack patterns learned from previous scans, user corrections/overrides, strategic decisions (e.g. "skip host X", "prioritize SQLi over XSS"), session context (current scan state, active hypotheses), and free-form notes.
   - Each entry must have: `id`, `content` text, `memory_type` enum/str (`attack_pattern`, `user_correction`, `strategic_decision`, `session_context`, `note`), `mission_id` (optional, for mission-scoped memories), `created_at`/`updated_at` timestamps, `metadata` dict, `tags` list, `confidence` float, and `status` (`active`, `archived`, `superseded`).
   - Follow ARGUS dataclass patterns (slots, type hints, factory defaults).
2. `argus/memory/store.py`:
   - Vector-backed memory store persisting entries into the existing `VectorStore` (`argus/vector/store.py`) under `source_type='memory'`.
   - Must support: `add(entry)`, `get(id)`, `search(query, top_k, filters)` for semantic recall, `list(memory_type, mission_id)`, `update(id, ...)`, `archive(id)`, `clear(mission_id)`, and `count(filters)`.
   - Score values from memory search must always be bounded in [0.0, 1.0].
   - Entries must persist across `MemoryStore` re-instantiation (disk persistence via VectorStore).
3. `argus/memory/manager.py`:
   - High-level `MemoryManager` facade wrapping the store.
   - Provides semantic recall (`recall(query, top_k)` returning ranked memory entries), memory lifecycle management, and cross-mission knowledge transfer.
   - Expose `get_memory_manager()` singleton factory.
4. `argus/memory/__init__.py`:
   - Clean public exports.

### R2. ResearchContextEngine Integration
- Wire `MemoryManager` into the existing `ResearchContextEngine` at `argus/workspace/context/engine.py`.
- The `_get_memory_manager()` method (around line 78) currently has a placeholder — make it resolve to the real `MemoryManager`.
- Semantic retrieval in `resolve()` should include memory results alongside findings, evidence, CVE, and graph results when `enable_semantic_retrieval=True`.
- Touch only `_get_memory_manager()` and semantic retrieval integration in `argus/workspace/context/engine.py`. Do NOT break existing tests or behavior.

### R3. Tests
- `tests/memory/test_memory.py`: Unit tests for models, store CRUD, vector search integration, filtering by memory_type and mission_id, lifecycle operations (archive, supersede). Minimum 30 test cases.
- `tests/memory/test_memory_adversarial.py`: Adversarial tests including: empty/null inputs, extremely long content, special characters, concurrent access patterns, score bound invariants ([0.0, 1.0]), state isolation between missions. Minimum 15 test cases.
- `tests/memory/test_memory_integration.py`: Integration test verifying memory recall flows through `ResearchContextEngine.resolve()`.
- Total new test cases across the 3 files must be at least 45.

### Existing Architecture Reference
Do NOT modify existing vector store, embedding engine, or CVE KB internal logic:
- `argus/vector/store.py` (`VectorStore` dual-engine sqlite-vec / NumPy)
- `argus/vector/embeddings.py` (`EmbeddingEngine`)
- `argus/vector/models.py` (`VectorDocument`, `SearchResult`, `VectorFilter`, `VectorStoreConfig`)
- `argus/evidence/model.py`, `argus/evidence/store.py`
- `argus/knowledge/cve_kb.py`
- `argus/workspace/context/engine.py` (touch only `_get_memory_manager()` and semantic retrieval integration)
- `argus/workspace/context/models.py`
All vector documents for memory must use `source_type='memory'`.

### Post-Sprint Handoff
Update `/home/varun/argus/.agents/sprint_handoff.md`:
- Add Sprint 31a row to completed sprints table
- Update test baseline count
- Update "Remaining Roadmap" section (Sprint 31b: CLI search + integration tests, Sprint 31c: Adversarial RAG pipeline tests)
- Add Sprint 31a section with results summary

### Verification & Acceptance
- `python -m pytest tests/memory/ -x -q` must pass completely.
- `python -m pytest tests/ --ignore=tests/workspace -x -q` must pass with >= 2,089 tests.
- Minimum 45 new test cases.
- In your working directory `/home/varun/argus/.agents/swe_sprint31a`, maintain `progress.md` and write `handoff.md` upon completion.
- When 100% complete with all tests passing and handoff written, send your completion report with a victory claim.
