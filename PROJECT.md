# PROJECT: ARGUS Sprint 31 — Vector RAG & Semantic Search

## Architecture Overview
ARGUS is an autonomous offensive security and vulnerability research platform. Sprint 31 introduces a self-contained, air-gapped Vector RAG and Semantic Search subsystem with zero external service dependencies.
The architecture consists of:
1. **Vector & Embedding Engine (`argus/vector/`)**: Dual-engine vector store backed by SQLite-vec with resilient pure-Python/NumPy fallback, deterministic offline embedding generation (384-d), and disk persistence.
2. **Scan Semantic Indexer & Search (`argus/reporting/vector_indexer.py`)**: Post-scan indexing of evidence, findings, and historical reports with multi-field semantic similarity search.
3. **CVE Knowledge Base & Correlator (`argus/knowledge/cve_kb.py`, `cve_correlator.py`)**: Ingestion of CVE feeds, vector search across vulnerability descriptions, and blended correlation to scan findings.
4. **Blended Context Ranker (`argus/workspace/context/`)**: Upgraded `ResearchContextEngine`, `ContextRanker` (hybrid score $S = w_{\text{vec}}S_{\text{vec}} + w_{\text{lex}}S_{\text{lex}} + S_{\text{scope}} + S_{\text{type}}$), and `ContextAssembler`.
5. **Conversational Memory System (`argus/memory/`)**: Persistent multi-session memory capturing attack patterns, user corrections, key decisions, and cross-session recall.

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| 1 | R1.1 Embedding Generation | Local 384-d embedding engine with deterministic offline & optional neural providers | M1 | ORIGINAL_REQUEST §R1 |
| 2 | R1.2 SQLite-Vec Vector Store | File-based vector database with native sqlite-vec + numpy fallback, disk persistence | M1 | ORIGINAL_REQUEST §R1 |
| 3 | R1.3 Metadata Filtering | Filter vector queries by source_type, mission_id, severity, category, metadata | M1 | ORIGINAL_REQUEST §R1 |
| 4 | R2.1 Scan Evidence Indexer | Automatic post-scan indexing of all confirmed findings and evidence | M2 | ORIGINAL_REQUEST §R2 |
| 5 | R2.2 Finding Semantic Search | Multi-concept semantic search across vulnerability findings and historical reports | M2 | ORIGINAL_REQUEST §R2 |
| 6 | R3.1 CVE Feed Ingestion | Ingest CVE records from JSON feeds/files into vector knowledge base | M2 | ORIGINAL_REQUEST §R3 |
| 7 | R3.2 Finding-to-CVE Correlation | Hybrid correlation engine matching findings to CVEs via vector + CWE + tech | M2 | ORIGINAL_REQUEST §R3 |
| 8 | R4.1 Vector Context Retrieval | ResearchContextEngine vector retrieval for evidence, findings, CVEs, memory | M3 | ORIGINAL_REQUEST §R4 |
| 9 | R4.2 Blended Context Ranker | Hybrid ranker combining vector similarity with lexical and scope scoring | M3 | ORIGINAL_REQUEST §R4 |
| 10 | R4.3 Copilot Context Assembly | Extended ContextAssembler formatting CVE and recalled memory sections | M3 | ORIGINAL_REQUEST §R4 |
| 11 | R5.1 Conversational Memory Models | MemoryEntry models for attack patterns, user corrections, decisions | M4 | ORIGINAL_REQUEST §R5 |
| 12 | R5.2 Multi-Session Memory Store | SQLite-backed persistent memory store with vector search and recall | M4 | ORIGINAL_REQUEST §R5 |
| 13 | R5.3 Conversational Learning | Auto-extract corrections, decisions, and attack patterns from conversations and scans | M4 | ORIGINAL_REQUEST §R5 |
| 14 | R6.1 Test Suite & Zero Regression | 20+ new tests across modules, 2,089+ baseline tests passing | M5 | ORIGINAL_REQUEST §R6 |
| 15 | R6.2 Dependencies & Final Handoff | Update pyproject.toml and produce victory handoff at .agents/sprint31_vector_rag/handoff.md | M5 | ORIGINAL_REQUEST §R6 |

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M1 | Vector Store & Embedding Engine | `argus/vector/`, `pyproject.toml`, `tests/test_vector_store.py` | none | DONE |
| M2 | Scan Semantic Search & CVE Knowledge Base | `argus/reporting/vector_indexer.py`, `argus/knowledge/cve_*.py`, `tests/test_semantic_search.py`, `tests/test_cve_kb.py` | M1 | DONE |
| M3 | Workspace Copilot Blended Context Engine | `argus/workspace/context/`, `tests/workspace/test_blended_context.py` | M1, M2 | IN_PROGRESS |
| M4 | Conversational Memory System | `argus/memory/`, `tests/test_memory.py` | M1, M3 | PLANNED |
| M5 | Full Validation, Forensics & Victory Handoff | E2E integration verification, full regression run, audit, final handoff | M1, M2, M3, M4 | PLANNED |

## Interface Contracts
### `argus.vector` ↔ Downstream Modules
```python
class VectorDocument:
    id: str
    content: str
    embedding: Optional[List[float]] = None
    source_type: str = "general"
    mission_id: Optional[str] = None
    severity: Optional[str] = None
    category: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

class VectorStore:
    def add_document(self, doc: VectorDocument) -> str: ...
    def add_documents(self, docs: List[VectorDocument]) -> List[str]: ...
    def search(self, query: str | List[float], top_k: int = 10, filters: Optional[Dict[str, Any] | VectorFilter] = None, min_score: Optional[float] = None) -> List[SearchResult]: ...
    def get(self, doc_id: str) -> Optional[VectorDocument]: ...
    def delete(self, doc_id: str) -> bool: ...
    def count(self, filters: Optional[Dict[str, Any] | VectorFilter] = None) -> int: ...
```

### `argus.knowledge` & `argus.reporting` ↔ Context Engine
```python
class CVEKnowledgeBase:
    def ingest_cve_records(self, records: List[Dict[str, Any]] | List[CVEEntry]) -> int: ...
    def search_cves(self, query: str, top_k: int = 5, min_score: float = 0.0) -> List[SearchResult]: ...

class FindingSemanticSearchEngine:
    def index_mission_findings(self, mission_id: str, findings: List[Finding]) -> int: ...
    def search_findings(self, query: str, top_k: int = 10, filters: Optional[Dict[str, Any]] = None) -> List[SearchResult]: ...
```

### `argus.memory` ↔ Workspace Engine
```python
class MemoryManager:
    def store_memory(self, entry: MemoryEntry) -> str: ...
    def recall(self, query: MemoryQuery) -> List[MemorySearchResult]: ...
    def learn_from_conversation(self, conversation: Any) -> List[MemoryEntry]: ...
    def learn_from_scan(self, mission: Any) -> List[MemoryEntry]: ...
```

## Code Layout
- `argus/vector/`: `__init__.py`, `models.py`, `embeddings.py`, `store.py`, `exceptions.py`
- `argus/knowledge/`: `cve_models.py`, `cve_kb.py`, `cve_correlator.py`
- `argus/reporting/`: `vector_indexer.py`
- `argus/workspace/context/`: `engine.py`, `ranker.py`, `assembler.py`, `models.py`
- `argus/memory/`: `__init__.py`, `models.py`, `store.py`, `manager.py`
- `tests/`: `test_vector_store.py`, `test_semantic_search.py`, `test_cve_kb.py`, `test_memory.py`, `workspace/test_blended_context.py`
- `.agents/sprint31_vector_rag/handoff.md`: Final completion handoff
