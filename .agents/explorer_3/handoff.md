# Handoff Report: Explorer 3 — Copilot Context & Memory Systems Specialist

## 1. Observation

### 1.1 Workspace Copilot Context Engine (`argus/workspace/context/`)
- **Location & Components**:
  - `argus/workspace/context/engine.py`: Defines `ResearchContextEngine`. Its `__init__` instantiates `ContextRanker`, `ContextPolicy`, `ContextAssembler`, `EvidenceManager`, `MissionContextResolver`, and `KnowledgeGraphRetriever`.
  - `ResearchContextEngine._retrieve_sources(query: ContextQuery)` currently queries:
    1. `self.evidence_manager.get_by_investigation(query.investigation_id)` (lines 28–43) — maps evidence records to `ContextSource` with status `EVIDENCE` (if `USER_REVIEWED`, `CONFIRMED`, `CORROBORATED`) or `OBSERVATION`.
    2. `self.mission_resolver.resolve(query)` (lines 45–46) — resolves `MISSION_STATE`, `SCOPE`, `INVESTIGATION_STATE`, `FINDING`, `HYPOTHESIS`.
    3. `self.graph_retriever.resolve(query)` (lines 49–50) — extracts 1-hop subgraph of entities matching query terms or recent conversation references (`KNOWLEDGE_GRAPH`).
  - `ResearchContextEngine.resolve_context(query: ContextQuery)` (lines 56–104):
    1. Checks authorization via `authorization_gate.can_access_mission(user_id, mission_id)`.
    2. Enforces mission and project isolation.
    3. Filters sources via `ContextPolicy.apply(query, isolated_sources)`.
    4. Ranks sources via `ContextRanker.rank(query, allowed_sources)`.
    5. Formats context prompt via `ContextAssembler.assemble(result)`.
  - `argus/workspace/context/ranker.py`: Defines `ContextRanker.rank(query, sources)`.
    - Scoring logic:
      - Active mission match: $+5$
      - Active investigation match: $+10$
      - Query term overlap in title + content ($>3$ char tokens): $+2$ per matching term
      - Semantic status priority (`EVIDENCE` or `FINDING`): $+3$
    - Relevance classification: $\ge 15 \to \text{"Critical"}$, $\ge 10 \to \text{"High"}$, $\ge 5 \to \text{"Medium"}$, $< 5 \to \text{"Low"}$.
    - Filters out `"Low"` items and caps the result set at top 15 sources (`return filtered[:15]`).
  - `argus/workspace/context/models.py`: Defines `ContextQuery`, `ContextSource` (fields: `source_id`, `source_type`, `title`, `content`, `semantic_status`, `relevance_score`, `relevance_reason`, `mission_id`, `investigation_id`, `project_id`, `timestamp`, `confidence`, `authorization_scope`, `metadata`), and `ContextResult`.
  - `argus/workspace/context/assembler.py`: Assembles structured Markdown prompt grouping sections by semantic state (`ACTIVE MISSION STATE`, `AUTHORIZED SCOPE`, `ACTIVE INVESTIGATION`, `RELEVANT OBSERVATIONS`, `RELEVANT EVIDENCE`, `ACTIVE HYPOTHESES`, `CONFIRMED FINDINGS`, `KNOWLEDGE GRAPH CONTEXT`).

### 1.2 Conversational Learning & Memory System (`argus/memory/`)
- **Current State**:
  - `argus/memory/` does NOT exist in the codebase.
  - `argus/learning/` exists (`models.py`, `patterns.py`, `feedback.py`, `history.py`, `metrics.py`, `registry.py`, `recommendations.py`, `engine.py`), but it is scoped exclusively to mission metrics, heuristic stats, and discovered research patterns requiring planner approval. It has no conversational learning, vector embeddings, cross-session conversational recall, or user correction capture.
  - `argus/workspace/repository.py`: `ConversationRepository` manages conversations stored as JSON files under `~/.argus/workspace/conversations/` with in-memory set indexes for `user_id`, `mission_id`, `project_id`, `task_id`.
  - `argus/workspace/engine.py`: `ConversationEngine` handles `add_user_message` and `generate_response` / `generate_response_stream`. It evaluates answer planning via `EvidenceAwareAnswerPlanner` and calls `self.context_engine.resolve_context(query)`. It currently lacks automated extraction/learning of user corrections, strategic decisions, or attack pattern memory.

### 1.3 Test Suite Baseline & Execution
- **Test Suite Structure**:
  - 197 test files in `tests/` across 23 subdirectories (excluding `tests/workspace/` which contains 23 test files).
  - Baseline execution command: `python3 -m pytest tests/ --ignore=tests/workspace -x -q` (or `python3 -m pytest tests/workspace -q` for workspace).
  - Test suite status:
    - `tests/workspace/`: 80 passed, 0 failures.
    - `tests/collectors/`: 1,078 passed, 0 failures.
    - Total baseline test count: 2,089+ tests passing with zero regressions.
  - Existing Mock Patterns:
    - Global fixture in `tests/workspace/conftest.py`: Sets `os.environ["ARGUS_LLM_PROVIDER"] = "mock"` and cleans API keys (`OPENAI_API_KEY`, `DEEPSEEK_API_KEY`, `NVIDIA_API_KEY`, `GEMINI_API_KEY`).
    - Uses `tmp_path` fixture for filesystem isolation via `ARGUS_WORKSPACE_DIR = str(tmp_path)`.
    - Uses `unittest.mock.MagicMock`, `AsyncMock`, and `patch` for mocking LLM calls, collectors, and network services.

---

## 2. Logic Chain

### 2.1 Context Engine Upgrade Path (Requirement R4)
1. **Limitation of Current Ranker**: `ContextRanker` uses primitive exact word token splitting (`term in s_text`). Queries like *"parameter tampering on authentication endpoint"* fail to match an evidence titled *"BOLA in /api/v1/users?id=12"* because no keywords overlap directly, even though they are semantically related.
2. **Integration Architecture for Vector RAG**:
   - `ResearchContextEngine` should incorporate a `VectorContextRetriever` (or connect to the new Vector Store / Semantic Search Engine from R1/R2/R3).
   - In `_retrieve_sources`, query the vector store for semantic matches across evidence, findings, CVE knowledge base entries, and recalled historical memories.
   - Attach cosine similarity / vector score to `source.metadata["vector_score"]`.
3. **Blended Context Ranking Algorithm**:
   - Hybrid Score Calculation:
     $$S_{\text{hybrid}} = w_{\text{vec}} \cdot S_{\text{vec}} + w_{\text{lex}} \cdot S_{\text{lex}} + S_{\text{scope}} + S_{\text{type}}$$
     where:
     - $S_{\text{vec}} \in [0, 10]$ (normalized cosine similarity $\times 10$)
     - $S_{\text{lex}} = \min(10, \text{overlap\_count} \times 2)$
     - $S_{\text{scope}} = (+10 \text{ if investigation match}) + (+5 \text{ if mission match})$
     - $S_{\text{type}} = (+3 \text{ if confirmed EVIDENCE / FINDING})$
     - $w_{\text{vec}} = 0.6$, $w_{\text{lex}} = 0.4$ (configurable default).
   - Graceful Fallback: If vector scores are absent ($S_{\text{vec}} = 0$), $w_{\text{lex}}$ automatically defaults to $1.0$, preserving exact backward-compatible scoring for all existing tests.
   - Relevance category thresholds remain compatible: $\ge 15 \to \text{"Critical"}$, $\ge 10 \to \text{"High"}$, $\ge 5 \to \text{"Medium"}$, $< 5 \to \text{"Low"}$.
4. **Assembler Extension**:
   - `ContextAssembler` should format new semantic statuses:
     - `### RELEVANT CVE & VULNERABILITY KNOWLEDGE` (for `CVE_KNOWLEDGE` sources)
     - `### RECALLED MEMORIES & HISTORICAL PATTERNS` (for `HISTORICAL_MEMORY` sources)

### 2.2 Memory System Design (Requirement R5)
1. **Module Layout (`argus/memory/`)**:
   - `argus/memory/__init__.py`: Public API exports (`MemoryManager`, `MemoryEntry`, `MemoryType`, `MemoryQuery`, `MemoryStore`).
   - `argus/memory/models.py`:
     - `MemoryType(str, Enum)`: `ATTACK_PATTERN`, `USER_CORRECTION`, `KEY_DECISION`, `SESSION_EXPERIENCE`, `TECH_STACK_INSIGHT`.
     - `MemoryEntry(BaseModel)`: `id: str`, `memory_type: MemoryType`, `title: str`, `content: str`, `tags: List[str]`, `metadata: Dict[str, Any]`, `embedding: Optional[List[float]]`, `created_at: str`, `updated_at: str`, `usage_count: int`.
     - `MemoryQuery(BaseModel)`: `query: str`, `memory_types: Optional[List[MemoryType]]`, `tags: Optional[List[str]]`, `project_id: Optional[str]`, `mission_id: Optional[str]`, `top_k: int = 5`, `min_score: float = 0.4`.
     - `MemorySearchResult(BaseModel)`: `entry: MemoryEntry`, `score: float`, `relevance_reason: str`.
   - `argus/memory/store.py`:
     - `MemoryStore`: Persistent SQLite-backed store with optional `sqlite-vec` vector indexing.
     - Supports CRUD and filtering by `project_id`, `mission_id`, `tags`, and `memory_type`.
     - Implements vector similarity search with cosine distance metric.
   - `argus/memory/manager.py`:
     - `MemoryManager`:
       - `store_memory(entry: MemoryEntry) -> str`
       - `recall(query: MemoryQuery) -> List[MemorySearchResult]`
       - `learn_from_conversation(conversation: Conversation) -> List[MemoryEntry]`: Extracts user corrections (e.g., negative feedback, explicit constraints), key decisions (chosen attack vectors), and summarizes session insights.
       - `learn_from_scan(mission: Mission) -> List[MemoryEntry]`: Ingests confirmed findings and successful exploitation chains.
       - `format_memories_for_prompt(memories: List[MemorySearchResult]) -> str`
2. **Integration with Workspace**:
   - `ResearchContextEngine._retrieve_sources()` invokes `memory_manager.recall(...)` to inject relevant cross-session learnings into Copilot prompts.
   - `ConversationEngine.generate_response()` can record user corrections and decisions post-response.

### 2.3 Test Suite & Quality Assurance (Requirement R6)
1. **Zero-Regression Strategy**:
   - Run existing test suites with zero breaking changes.
   - All new modules must support mock/offline embedding generation (e.g., deterministic hash embeddings or pure Python cosine similarity) during unit test runs so tests execute fast and reliably without external network dependencies.
2. **New Test Suite Composition (20+ New Tests)**:
   - **Vector Store & Embeddings (R1)**: 5 tests (`test_vector_store_crud`, `test_vector_store_persistence`, `test_similarity_search`, `test_metadata_filtering`, `test_store_restart`).
   - **Semantic Search Over Evidence/Findings (R2)**: 4 tests (`test_evidence_indexing`, `test_findings_semantic_search`, `test_historical_scan_indexing`, `test_cross_finding_similarity`).
   - **CVE Knowledge Base (R3)**: 4 tests (`test_cve_ingestion`, `test_cve_semantic_search`, `test_finding_to_cve_correlation`, `test_cve_metadata_filters`).
   - **Workspace Copilot & Blended Context Engine (R4)**: 5 tests (`test_blended_context_ranker_hybrid`, `test_blended_context_ranker_backward_compat`, `test_research_context_engine_vector_retrieval`, `test_context_assembler_new_sections`, `test_copilot_context_isolation`).
   - **Conversational Memory System (R5)**: 6 tests (`test_memory_models_and_types`, `test_memory_store_sqlite_crud`, `test_memory_recall_semantic`, `test_learn_from_conversation_corrections`, `test_learn_from_scan_attack_patterns`, `test_cross_session_memory_injection`).

---

## 3. Caveats
- `sqlite-vec` is a C extension for SQLite. On environments where the binary extension is not pre-compiled or pre-installed, the vector engine should provide a pure-Python / NumPy vector fallback (`numpy.dot` / cosine similarity over SQLite blobs) so tests pass in any environment without binary compile errors.
- `argus/memory/` must not conflict with `argus/learning/`. `argus/learning/` is for mission execution metrics & planner recommendations, while `argus/memory/` is for conversational experiences, user corrections, attack patterns, and cross-session memory.

---

## 4. Conclusion
1. **Workspace Context Engine**: The existing `ResearchContextEngine` and `ContextRanker` are clean and modular. Upgrading them to a **Blended Context Ranker** requires adding vector retrieval to `_retrieve_sources`, implementing a hybrid scoring formula ($w_{\text{vec}} \cdot S_{\text{vec}} + w_{\text{lex}} \cdot S_{\text{lex}} + S_{\text{scope}} + S_{\text{type}}$) in `ContextRanker`, and extending `ContextAssembler` to render CVE and memory sections.
2. **Memory System**: A new `argus/memory/` package must be built with `models.py`, `store.py`, and `manager.py`. It will persist attack patterns, user corrections, and decisions in SQLite with vector indexing, recallable across sessions.
3. **Test Suite & Baseline**: Baseline is confirmed at 2,089+ passing tests. 24 new dedicated tests across `tests/rag/`, `tests/memory/`, and `tests/workspace/` will ensure full coverage of R1–R5 with 0 regressions.

---

## 5. Verification Method
1. **Baseline Suite Verification**:
   ```bash
   python3 -m pytest tests/ --ignore=tests/workspace -q
   python3 -m pytest tests/workspace -q
   ```
2. **Context Engine & Workspace Suite**:
   ```bash
   python3 -m pytest tests/workspace/test_context.py tests/workspace/test_copilot.py tests/workspace/test_graph_retrieval.py -q
   ```
3. **Memory Suite (Once Implemented)**:
   ```bash
   python3 -m pytest tests/test_memory.py -q
   ```
4. **Invalidation Conditions**:
   - Any test failure in the 2,089+ baseline test suite.
   - `ContextRanker` failing to rank items when vector scores are omitted (breaks existing workspace tests).
   - Real network calls made during unit test execution.
