# Handoff Report — Explorer 1: Vector Store & Embedding Engine Specialist (Sprint 31: Vector RAG & Semantic Search)

## 1. Observation

### 1.1 Python Environment & Dependency Audit
- **Python Version**: Python 3.13.14 (`/usr/bin/python3`, Linux x86_64, GCC 15.2.0)
- **Build Backend**: `setuptools>=68` configured via `pyproject.toml` (lines 1-3)
- **SQLite Engine**: Standard library `sqlite3` (SQLite 3.46.1). C-extension loading verified with `db.enable_load_extension(True)` returning `SUPPORTED`.
- **Installed Mathematical / ML Libraries**:
  - `numpy`: Version 2.4.6 is installed and fully functional.
  - `pydantic`: Version 2.13.4 is installed.
  - `fastapi`, `uvicorn`, `networkx`, `rich`, `typer`, `loguru`, `pyyaml`, `msgpack`, `jinja2`, `httpx`, `python-dotenv`, `openai`, `beautifulsoup4`, `python-dateutil` are declared in `pyproject.toml:11-28`.
- **Missing / Target Dependencies**:
  - `sqlite-vec`: Not currently installed. Latest stable release on PyPI is `sqlite-vec==0.1.9`.
  - `sentence-transformers`, `fastembed`, `onnxruntime`, `torch`, `transformers`: Not currently installed.
- **Baseline Test Suite Status**:
  - Command: `python3 -m pytest tests/ --ignore=tests/workspace --collect-only -q` collected 2,110 tests across 113 test files.
  - Test suites execute with zero external daemon requirements.

### 1.2 Existing Storage & Persistence Subsystems in ARGUS
Audit of the existing codebase revealed the following persistence paradigms:
1. **Workspace Project & Task Storage** (`argus/workspace/repository.py:8-100`):
   - `ProjectRepository` stores individual JSON files in `~/.argus/workspace/projects/<project_id>.json`.
   - `WorkspaceTaskRepository` stores JSON files in `~/.argus/workspace/tasks/<task_id>.json`.
   - In-memory dictionary cache backed by disk loads on startup (`_cache: Dict[str, Any]`).
2. **Binary & Attachment Storage** (`argus/workspace/storage.py:6-65`):
   - `AttachmentStorage` saves raw binary uploads to `~/.argus/workspace/attachments/` with MIME and size validation (10MB limit).
3. **Knowledge Base Storage** (`argus/knowledge/manager.py:11-172`):
   - `KnowledgeManager` manages structured `KnowledgeEntry` models (`argus/knowledge/models.py:22-46`) stored as `.json` files in `~/.argus/knowledge/`. Supports JSON, YAML, and Markdown file imports (`importers.py`).
4. **Mission Learning & History Registry** (`argus/learning/registry.py:28-60` and `argus/learning/history.py:21-93`):
   - `LearningRegistry` persists snapshots to `.argus/learning_history.json`.
5. **Evidence & Facts Management** (`argus/evidence/store.py:4-37`, `argus/evidence/model.py:26-56`, `argus/facts/store.py:1-26`):
   - In-memory stores (`EvidenceStore`, `FactStore`) managing dataclass models containing metadata: `evidence_id`, `mission_id`, `source_type`, `severity`, `category`, `confidence`, `status`.
6. **Workspace Context Engine** (`argus/workspace/context/engine.py:10-104` and `argus/workspace/context/ranker.py:4-53`):
   - `ResearchContextEngine` orchestrates context gathering from `EvidenceManager`, `MissionContextResolver`, and `KnowledgeGraphRetriever`.
   - `ContextRanker` currently uses naive keyword string overlap and categorical score assignment ("Critical", "High", "Medium", "Low").
7. **Storage Directory Conventions**:
   - Primary user data directory: `~/.argus/` (with fallback to `.argus/` or environment variable overrides such as `ARGUS_WORKSPACE_DIR` / `ARGUS_DATA_DIR`).
   - All directory paths use `Path(os.path.expanduser(...))` with `mkdir(parents=True, exist_ok=True)`.

---

## 2. Logic Chain

1. **Self-Contained & Air-Gapped Requirement (Zero External Services)**:
   - ARGUS is an autonomous offensive security platform designed to operate in air-gapped, isolated penetration testing environments or private CI pipelines.
   - Vector search and embedding generation must not rely on external cloud APIs (e.g. OpenAI, Cohere, Pinecone) or require external running daemons (e.g. Milvus, Qdrant, Chroma servers).
   - Local embedding generation and embedded SQLite persistence are strictly required.

2. **Dual-Engine SQLite-vec Architecture (High Performance + 100% Portability)**:
   - `sqlite-vec` provides C-accelerated vector indexing (`vec0` virtual table), supporting cosine similarity, L2 distance, and auxiliary metadata columns directly in SQLite.
   - However, to ensure zero build breakages on diverse OS/CI environments (where C extension loading or dynamic library linking might encounter platform limitations), the vector store should employ a **Dual-Engine Pattern**:
     - **Primary Engine**: Native `sqlite-vec` virtual table (`vec_documents USING vec0(id TEXT PRIMARY KEY, embedding float[384] distance_metric=cosine)`).
     - **Fallback Engine**: SQLite relational table with `embedding_blob` storage + vector distance computation via `numpy` (already installed in the environment).
     - Both engines share the exact same SQLite database file (`.argus/vector_store.db`), exact same relational schema (`documents` table for content, metadata, and timestamps), and identical Python API methods (`VectorStore`).

3. **Pluggable Local Embedding Engine (Fast, Lightweight, Deterministic)**:
   - A standard vector dimension of **384** (matching `all-MiniLM-L6-v2` and `bge-small-en-v1.5`) should be used across all ARGUS vector stores.
   - Heavy ML frameworks (`torch`, `transformers`) introduce massive overhead (hundreds of MBs/GBs, 5-10s cold-start import times).
   - The embedding engine must provide a clean abstract interface `BaseEmbeddingProvider` with three implementations:
     1. `DeterministicEmbeddingProvider` / `LocalFeatureEmbeddingProvider`: Pure Python + `numpy` implementation using token hashing, subword n-grams, IDF-weighted security vocabulary, and L2 normalization to produce high-quality 384-d semantic vectors in < 0.1ms with zero third-party dependencies. Guarantees 100% deterministic test results and instant test execution.
     2. `FastEmbedProvider` (optional fast ONNX-based provider when `fastembed` is available).
     3. `SentenceTransformerProvider` (optional provider when `sentence-transformers` is installed).
     4. `EmbeddingEngine` auto-factory that selects the best available provider.

4. **Relational + Vector Metadata Filtering**:
   - Security queries in ARGUS require strict scoping (e.g., searching findings only within `mission_id == 'm-123'`, or CVE records where `severity in ('HIGH', 'CRITICAL')`, or filtering by `source_type == 'evidence'`).
   - Combining a structured `documents` relational table (with indexed columns for `source_type`, `mission_id`, `severity`, `category`, and JSON `metadata`) with vector indexing ensures fast pre-filtering, exact joins, and deterministic retrieval.

5. **Downstream Integration Compatibility (R2, R3, R4, R5)**:
   - **R2 (Scan Evidence & Findings)**: Ingests `Evidence` and confirmed scan findings into the vector store with metadata (`source_type="finding"|"evidence"`, `mission_id`, `severity`, `category`).
   - **R3 (CVE Knowledge Base)**: Ingests CVE JSON records into the vector store with metadata (`source_type="cve"`, `cvss`, `cwe`, `severity`).
   - **R4 (Workspace Copilot & ContextRanker)**: `ResearchContextEngine` and `ContextRanker` query the vector store, blending cosine similarity scores with graph/lexical scores for context ranking.
   - **R5 (Conversational Memory)**: Memory records stored with metadata (`source_type="memory"`, `session_id`, `memory_type`) for cross-session semantic recall.

---

## 3. Caveats

1. **Native SQLite-vec Extension Loading**:
   - `sqlite3.enable_load_extension(True)` is supported on Linux Python 3.13. On some locked-down macOS or Windows Python distributions, extension loading may be restricted by the OS build flags. The built-in numpy fallback engine handles this transparently.
2. **Vector Dimension Uniformity**:
   - All documents in a single vector table must share identical dimensions (384 dimensions standard). Any attempt to query with mismatched dimensions must raise a clear validation error.
3. **Database File Locking**:
   - SQLite should be initialized with `PRAGMA journal_mode=WAL;` and `PRAGMA busy_timeout=5000;` to ensure safe concurrent read/write access across multiple scanner agents or asynchronous tasks.

---

## 4. Conclusion & Architectural Recommendation

### 4.1 Proposed Module File Structure
Place the vector and embedding engine in `argus/vector/` (with clean top-level exports):

```
argus/vector/
├── __init__.py           # Public exports: VectorStore, VectorDocument, SearchResult, EmbeddingEngine, VectorFilter
├── models.py             # VectorDocument, SearchResult, VectorFilter, DistanceMetric, VectorStoreConfig
├── embeddings.py         # BaseEmbeddingProvider, DeterministicEmbeddingProvider, FastEmbedProvider, SentenceTransformerProvider, EmbeddingEngine, get_embedding_engine
├── store.py              # VectorStore, SQLiteVecStore (with native sqlite-vec and resilient numpy fallback)
└── exceptions.py         # VectorStoreError, EmbeddingError, ExtensionLoadError
```

### 4.2 Detailed Component Designs

#### A. Data Models (`argus/vector/models.py`)
```python
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional
from datetime import datetime

class DistanceMetric(str, Enum):
    COSINE = "cosine"
    L2 = "l2"
    DOT = "dot"

@dataclass
class VectorDocument:
    id: str
    content: str
    embedding: Optional[List[float]] = None
    source_type: str = "general"       # "finding", "evidence", "cve", "memory", "observation"
    mission_id: Optional[str] = None
    severity: Optional[str] = None     # "critical", "high", "medium", "low", "info"
    category: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

@dataclass
class SearchResult:
    id: str
    content: str
    score: float                       # Similarity score (0.0 to 1.0, higher is more similar)
    distance: float                    # Raw distance metric
    source_type: str
    mission_id: Optional[str] = None
    severity: Optional[str] = None
    category: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = ""

@dataclass
class VectorFilter:
    source_type: Optional[str | List[str]] = None
    mission_id: Optional[str] = None
    severity: Optional[str | List[str]] = None
    category: Optional[str | List[str]] = None
    metadata_filters: Optional[Dict[str, Any]] = None
```

#### B. Embedding Engine (`argus/vector/embeddings.py`)
- Standard dimension: `384`
- `BaseEmbeddingProvider`: Abstract class defining `embed_text(text: str) -> List[float]` and `embed_batch(texts: List[str]) -> List[List[float]]`.
- `DeterministicEmbeddingProvider`: Zero-dependency, offline semantic hash + character n-gram + domain keyword feature projector with L2 normalization.
- `FastEmbedProvider` & `SentenceTransformerProvider`: Optional high-accuracy neural embedding models when packages are installed.
- `EmbeddingEngine(provider="auto", dimension=384)`: Default provider router.

#### C. Vector Store Engine (`argus/vector/store.py`)
- Default persistence path: `~/.argus/vector_store.db` (or `ARGUS_VECTOR_STORE_PATH` env var).
- Database Initialization:
  - Table `documents`: `id (PK), content, source_type, mission_id, severity, category, metadata_json, embedding_blob, created_at, updated_at`
  - Indices on: `source_type`, `mission_id`, `severity`, `category`
  - Virtual Table `vec_documents`: `vec0(id TEXT PRIMARY KEY, embedding float[384] distance_metric=cosine)` when `sqlite-vec` is loaded.
- Core Methods:
  - `add_document(doc: VectorDocument) -> str`
  - `add_documents(docs: List[VectorDocument]) -> List[str]`
  - `add_texts(texts: List[str], metadatas: Optional[List[Dict[str, Any]]] = None, ids: Optional[List[str]] = None, **kwargs) -> List[str]`
  - `search(query: str | List[float], top_k: int = 10, filters: Optional[Dict[str, Any] | VectorFilter] = None, metric: str = "cosine", min_score: Optional[float] = None) -> List[SearchResult]`
  - `get(id: str) -> Optional[VectorDocument]`
  - `delete(id: str) -> bool`
  - `delete_where(filters: Dict[str, Any] | VectorFilter) -> int`
  - `count(filters: Optional[Dict[str, Any] | VectorFilter] = None) -> int`
  - `clear() -> None`
  - `close() -> None`

### 4.3 Recommended Updates to `pyproject.toml`
Add the following dependency to `pyproject.toml` under `dependencies`:
```toml
dependencies = [
    # ... existing dependencies ...
    "sqlite-vec>=0.1.6"
]
```

---

## 5. Verification Method

1. **Unit Testing & Isolation Verification**:
   - Verify Vector Store CRUD, persistence to disk, and survival across process restarts using a temporary SQLite database file (`pytest tests/test_vector_store.py`).
2. **Metadata Filtering Verification**:
   - Insert multi-source documents (`source_type="finding"`, `source_type="cve"`, `source_type="memory"`) across different `mission_id` values and assert that filtering by `source_type`, `mission_id`, and `severity` returns strictly matching results.
3. **Similarity & Metric Verification**:
   - Verify that semantically similar strings (e.g., "SQL Injection via query parameter" vs "SQLi database injection vulnerability") achieve high similarity scores (`> 0.7`) and correct top-k ranking.
4. **Full Test Suite Verification**:
   - Run the full existing test suite:
     `python3 -m pytest tests/ --ignore=tests/workspace -x -q`
     Ensure all 2,089+ tests continue to pass without regressions.
