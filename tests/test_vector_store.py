"""Comprehensive test suite for Vector Store and Embedding Engine (Milestone 1)."""

import os
from pathlib import Path
import tempfile
import pytest

from argus.vector import (
    BaseEmbeddingProvider,
    DeterministicEmbeddingProvider,
    DimensionMismatchError,
    DistanceMetric,
    DocumentNotFoundError,
    EmbeddingEngine,
    EmbeddingError,
    SearchResult,
    VectorDocument,
    VectorFilter,
    VectorStore,
    VectorStoreConfig,
    get_embedding_engine,
    get_vector_store,
)


@pytest.fixture
def embedding_engine():
    """Fixture providing a deterministic 384-dimension embedding engine."""
    return EmbeddingEngine(provider="deterministic", dimension=384)


@pytest.fixture
def memory_store(embedding_engine):
    """Fixture providing an in-memory vector store with sqlite-vec."""
    store = VectorStore(
        db_path=":memory:",
        embedding_engine=embedding_engine,
        use_sqlite_vec=True,
    )
    yield store
    store.close()


@pytest.fixture
def fallback_memory_store(embedding_engine):
    """Fixture providing an in-memory vector store running in pure NumPy fallback mode."""
    store = VectorStore(
        db_path=":memory:",
        embedding_engine=embedding_engine,
        use_sqlite_vec=False,
    )
    yield store
    store.close()


# ============================================================================
# 1. Embedding Engine & Deterministic Provider Tests
# ============================================================================

def test_deterministic_embedding_dimension(embedding_engine):
    """Verify embedding generation yields strictly 384-dimension unit vectors."""
    text = "SQL Injection in auth parameter"
    emb = embedding_engine.embed_text(text)
    assert isinstance(emb, list)
    assert len(emb) == 384
    # All floats
    assert all(isinstance(x, float) for x in emb)


def test_deterministic_embedding_reproducibility(embedding_engine):
    """Verify that deterministic embedding produces 100% identical vectors across invocations."""
    text = "Remote Code Execution via Apache Commons FileUpload"
    emb1 = embedding_engine.embed_text(text)
    emb2 = embedding_engine.embed_text(text)
    assert emb1 == emb2


def test_deterministic_embedding_batch(embedding_engine):
    """Verify batch embedding produces identical output to single text embeddings."""
    texts = [
        "Cross-Site Scripting (XSS) in search field",
        "Server-Side Request Forgery in webhook URL",
        "Insecure Direct Object Reference in user profile API",
    ]
    batch_embs = embedding_engine.embed_batch(texts)
    assert len(batch_embs) == len(texts)
    for i, text in enumerate(texts):
        assert batch_embs[i] == embedding_engine.embed_text(text)


def test_deterministic_embedding_edge_cases(embedding_engine):
    """Verify embedding engine handles empty strings, whitespace, and special characters."""
    empty_emb = embedding_engine.embed_text("")
    assert len(empty_emb) == 384

    ws_emb = embedding_engine.embed_text("   \n\t  ")
    assert len(ws_emb) == 384

    special_emb = embedding_engine.embed_text("!@#$%^&*()_+{}[]|:;<>?,./~`")
    assert len(special_emb) == 384

    cve_emb = embedding_engine.embed_text("CVE-2023-38606 CWE-89 sqlInjection")
    assert len(cve_emb) == 384


def test_deterministic_semantic_similarity(embedding_engine):
    """Verify that semantically related security terms produce high cosine similarity."""
    sqli_1 = embedding_engine.embed_text("SQL injection vulnerability in login query")
    sqli_2 = embedding_engine.embed_text("SQLi database exploit via username parameter")
    xss_1 = embedding_engine.embed_text("Reflected Cross-Site Scripting via alert payload")
    rce_1 = embedding_engine.embed_text("Remote Code Execution shell via command injection")

    sim_sqli = embedding_engine.similarity(sqli_1, sqli_2, metric=DistanceMetric.COSINE)
    sim_sqli_xss = embedding_engine.similarity(sqli_1, xss_1, metric=DistanceMetric.COSINE)
    sim_sqli_rce = embedding_engine.similarity(sqli_1, rce_1, metric=DistanceMetric.COSINE)

    # SQLi 1 should be significantly closer to SQLi 2 than to XSS or RCE
    assert sim_sqli > 0.65
    assert sim_sqli > sim_sqli_xss
    assert sim_sqli > sim_sqli_rce


def test_embedding_dimension_mismatch_validation(embedding_engine):
    """Verify that dimension mismatch raises DimensionMismatchError."""
    with pytest.raises(DimensionMismatchError):
        embedding_engine.similarity([0.1] * 384, [0.1] * 128)


# ============================================================================
# 2. Vector Store CRUD Tests
# ============================================================================

def test_store_add_and_get_document(memory_store):
    """Verify adding and retrieving a document by ID."""
    doc = VectorDocument(
        id="doc-001",
        content="Authentication bypass via JWT none algorithm",
        source_type="finding",
        mission_id="mission-alpha",
        severity="critical",
        category="auth",
        metadata={"cve": "CVE-2022-1234", "cvss": 9.8},
    )
    doc_id = memory_store.add_document(doc)
    assert doc_id == "doc-001"

    retrieved = memory_store.get("doc-001")
    assert retrieved is not None
    assert retrieved.id == "doc-001"
    assert retrieved.content == "Authentication bypass via JWT none algorithm"
    assert retrieved.source_type == "finding"
    assert retrieved.mission_id == "mission-alpha"
    assert retrieved.severity == "critical"
    assert retrieved.category == "auth"
    assert retrieved.metadata["cve"] == "CVE-2022-1234"
    assert retrieved.metadata["cvss"] == 9.8
    assert len(retrieved.embedding) == 384


def test_store_get_nonexistent(memory_store):
    """Verify getting a non-existent document returns None."""
    assert memory_store.get("missing-id") is None


def test_store_add_documents_batch(memory_store):
    """Verify batch insertion of multiple documents."""
    docs = [
        VectorDocument(id=f"doc-{i}", content=f"Security event report #{i}", source_type="evidence")
        for i in range(10)
    ]
    ids = memory_store.add_documents(docs)
    assert len(ids) == 10
    assert memory_store.count() == 10
    for i in range(10):
        doc = memory_store.get(f"doc-{i}")
        assert doc is not None
        assert doc.content == f"Security event report #{i}"


def test_store_add_texts(memory_store):
    """Verify add_texts convenience helper."""
    texts = [
        "Open port 22 SSH detected",
        "Open port 80 HTTP server nginx 1.18",
        "Open port 443 HTTPS TLS 1.3",
    ]
    metas = [{"port": 22}, {"port": 80}, {"port": 443}]
    ids = memory_store.add_texts(
        texts=texts,
        metadatas=metas,
        source_type="recon",
        mission_id="m-recon",
    )
    assert len(ids) == 3
    assert memory_store.count() == 3
    doc = memory_store.get(ids[0])
    assert doc.content == "Open port 22 SSH detected"
    assert doc.metadata["port"] == 22
    assert doc.source_type == "recon"
    assert doc.mission_id == "m-recon"


def test_store_delete_document(memory_store):
    """Verify deleting a single document by ID."""
    doc = VectorDocument(id="doc-del", content="Temporary finding", source_type="finding")
    memory_store.add_document(doc)
    assert memory_store.count() == 1

    deleted = memory_store.delete("doc-del")
    assert deleted is True
    assert memory_store.count() == 0
    assert memory_store.get("doc-del") is None

    # Delete non-existent ID
    assert memory_store.delete("non-existent-id") is False


def test_store_delete_where(memory_store):
    """Verify conditional bulk deletion by filter."""
    docs = [
        VectorDocument(id="m1-f1", content="Finding 1", mission_id="m1", source_type="finding"),
        VectorDocument(id="m1-f2", content="Finding 2", mission_id="m1", source_type="finding"),
        VectorDocument(id="m2-f1", content="Finding 3", mission_id="m2", source_type="finding"),
        VectorDocument(id="m2-c1", content="CVE 1", mission_id="m2", source_type="cve"),
    ]
    memory_store.add_documents(docs)
    assert memory_store.count() == 4

    # Delete all documents for mission 'm1'
    deleted_count = memory_store.delete_where({"mission_id": "m1"})
    assert deleted_count == 2
    assert memory_store.count() == 2
    assert memory_store.get("m1-f1") is None
    assert memory_store.get("m1-f2") is None
    assert memory_store.get("m2-f1") is not None


def test_store_count_and_clear(memory_store):
    """Verify count with filters and clear operations."""
    docs = [
        VectorDocument(id="d1", content="High severity finding", severity="high", source_type="finding"),
        VectorDocument(id="d2", content="Medium severity finding", severity="medium", source_type="finding"),
        VectorDocument(id="d3", content="High severity CVE", severity="high", source_type="cve"),
    ]
    memory_store.add_documents(docs)

    assert memory_store.count() == 3
    assert memory_store.count({"severity": "high"}) == 2
    assert memory_store.count({"source_type": "cve"}) == 1
    assert memory_store.count({"severity": "low"}) == 0

    memory_store.clear()
    assert memory_store.count() == 0
    assert memory_store.get("d1") is None


# ============================================================================
# 3. Similarity Search & Ranking Tests
# ============================================================================

@pytest.mark.parametrize("use_vec", [True, False])
def test_similarity_search_ranking(embedding_engine, use_vec):
    """Verify similarity search returns ranked results in order of relevance (tested on both engines)."""
    store = VectorStore(
        db_path=":memory:",
        embedding_engine=embedding_engine,
        use_sqlite_vec=use_vec,
    )

    docs = [
        VectorDocument(id="sqli-target", content="SQL Injection in user login form", category="injection"),
        VectorDocument(id="xss-target", content="Stored Cross-Site Scripting in comment body", category="xss"),
        VectorDocument(id="rce-target", content="Remote Code Execution via file upload popen", category="rce"),
        VectorDocument(id="traversal-target", content="Directory path traversal ../../etc/passwd", category="traversal"),
    ]
    store.add_documents(docs)

    # Search for SQL injection
    results = store.search("database SQL query injection exploit", top_k=2)
    assert len(results) == 2
    assert results[0].id == "sqli-target"
    assert results[0].score > 0.6
    assert results[0].document is not None
    assert results[0].document.id == "sqli-target"

    # Search for XSS
    xss_results = store.search("reflected script tag alert XSS", top_k=2)
    assert len(xss_results) >= 1
    assert xss_results[0].id == "xss-target"

    store.close()


@pytest.mark.parametrize("use_vec", [True, False])
def test_search_min_score_threshold(embedding_engine, use_vec):
    """Verify min_score threshold filters out low-similarity documents."""
    store = VectorStore(
        db_path=":memory:",
        embedding_engine=embedding_engine,
        use_sqlite_vec=use_vec,
    )

    docs = [
        VectorDocument(id="sqli-doc", content="SQL injection flaw in database endpoint"),
        VectorDocument(id="unrelated-doc", content="Network printer discovery SNMP scan"),
    ]
    store.add_documents(docs)

    # With high min_score, only relevant document should return
    results = store.search("SQL injection attack", top_k=10, min_score=0.6)
    assert len(results) == 1
    assert results[0].id == "sqli-doc"

    # With impossible min_score 0.999
    strict_results = store.search("SQL injection attack", top_k=10, min_score=0.999)
    assert len(strict_results) == 0

    store.close()


def test_search_empty_store(memory_store):
    """Verify search on empty store returns empty list."""
    results = memory_store.search("SQL injection", top_k=5)
    assert results == []


# ============================================================================
# 4. Metadata Filtering Tests
# ============================================================================

@pytest.mark.parametrize("use_vec", [True, False])
def test_metadata_filtering_source_type_and_mission(embedding_engine, use_vec):
    """Verify filtering by source_type, mission_id, severity, and category."""
    store = VectorStore(
        db_path=":memory:",
        embedding_engine=embedding_engine,
        use_sqlite_vec=use_vec,
    )

    docs = [
        VectorDocument(
            id="f-1",
            content="SQL injection in API login",
            source_type="finding",
            mission_id="m-100",
            severity="critical",
            category="injection",
        ),
        VectorDocument(
            id="f-2",
            content="SQL injection in admin report",
            source_type="finding",
            mission_id="m-200",
            severity="high",
            category="injection",
        ),
        VectorDocument(
            id="cve-1",
            content="SQL injection in PostgreSQL driver",
            source_type="cve",
            mission_id="m-100",
            severity="critical",
            category="injection",
        ),
        VectorDocument(
            id="mem-1",
            content="Attacker bypassed login with SQL injection",
            source_type="memory",
            mission_id="m-100",
            severity="info",
            category="auth",
        ),
    ]
    store.add_documents(docs)

    # Filter by source_type = 'finding'
    res_findings = store.search(
        "SQL injection",
        top_k=10,
        filters={"source_type": "finding"},
    )
    assert len(res_findings) == 2
    assert all(r.source_type == "finding" for r in res_findings)

    # Filter by mission_id = 'm-100'
    res_m100 = store.search(
        "SQL injection",
        top_k=10,
        filters={"mission_id": "m-100"},
    )
    assert len(res_m100) == 3
    assert all(r.mission_id == "m-100" for r in res_m100)

    # Filter by combined source_type='finding' AND mission_id='m-100'
    res_combined = store.search(
        "SQL injection",
        top_k=10,
        filters={"source_type": "finding", "mission_id": "m-100"},
    )
    assert len(res_combined) == 1
    assert res_combined[0].id == "f-1"

    # Filter with list of source_types
    res_multi_type = store.search(
        "SQL injection",
        top_k=10,
        filters=VectorFilter(source_type=["finding", "cve"]),
    )
    assert len(res_multi_type) == 3
    assert set(r.id for r in res_multi_type) == {"f-1", "f-2", "cve-1"}

    store.close()


@pytest.mark.parametrize("use_vec", [True, False])
def test_custom_metadata_filtering(embedding_engine, use_vec):
    """Verify filtering by nested custom metadata JSON properties."""
    store = VectorStore(
        db_path=":memory:",
        embedding_engine=embedding_engine,
        use_sqlite_vec=use_vec,
    )

    docs = [
        VectorDocument(
            id="ep-1",
            content="GraphQL endpoint introspection enabled",
            source_type="evidence",
            metadata={"port": 443, "protocol": "https", "env": "prod"},
        ),
        VectorDocument(
            id="ep-2",
            content="GraphQL endpoint query depth flaw",
            source_type="evidence",
            metadata={"port": 8080, "protocol": "http", "env": "staging"},
        ),
        VectorDocument(
            id="ep-3",
            content="REST API endpoint leaking tokens",
            source_type="evidence",
            metadata={"port": 443, "protocol": "https", "env": "prod"},
        ),
    ]
    store.add_documents(docs)

    # Filter by custom metadata: env = 'prod'
    prod_results = store.search(
        "GraphQL introspection",
        top_k=5,
        filters={"metadata_filters": {"env": "prod"}},
    )
    assert len(prod_results) == 2
    assert set(r.id for r in prod_results) == {"ep-1", "ep-3"}

    # Filter by custom metadata: port = 8080
    staging_results = store.search(
        "GraphQL query depth",
        top_k=5,
        filters={"metadata_filters": {"port": 8080}},
    )
    assert len(staging_results) == 1
    assert staging_results[0].id == "ep-2"

    store.close()


# ============================================================================
# 5. Disk Persistence & Process Restart Survival
# ============================================================================

def test_disk_persistence_and_restart_survival(embedding_engine):
    """Verify that vector store persisted to disk survives closing and re-opening."""
    with tempfile.TemporaryDirectory() as temp_dir:
        db_file = os.path.join(temp_dir, "test_vector_store.db")

        # Session 1: Create store, insert documents, verify search
        with VectorStore(db_path=db_file, embedding_engine=embedding_engine) as store1:
            assert store1.is_sqlite_vec_available is True
            store1.add_documents([
                VectorDocument(
                    id="p-1",
                    content="Remote code execution in logging framework",
                    source_type="finding",
                    severity="critical",
                    metadata={"framework": "log4j"},
                ),
                VectorDocument(
                    id="p-2",
                    content="Server side template injection in Jinja2",
                    source_type="finding",
                    severity="high",
                    metadata={"framework": "jinja2"},
                ),
            ])
            assert store1.count() == 2

        # Session 2: Re-open the database file in a brand new VectorStore instance
        with VectorStore(db_path=db_file, embedding_engine=embedding_engine) as store2:
            assert store2.count() == 2

            doc1 = store2.get("p-1")
            assert doc1 is not None
            assert doc1.content == "Remote code execution in logging framework"
            assert doc1.metadata["framework"] == "log4j"
            assert len(doc1.embedding) == 384

            doc2 = store2.get("p-2")
            assert doc2 is not None
            assert doc2.content == "Server side template injection in Jinja2"

            # Search on re-opened instance
            search_res = store2.search("remote code execution shell exploit", top_k=1)
            assert len(search_res) == 1
            assert search_res[0].id == "p-1"


# ============================================================================
# 6. Dual-Engine Consistency Test
# ============================================================================

def test_dual_engine_consistency(embedding_engine):
    """Verify sqlite-vec and NumPy fallback engines produce consistent results and rankings."""
    vec_store = VectorStore(db_path=":memory:", embedding_engine=embedding_engine, use_sqlite_vec=True)
    npy_store = VectorStore(db_path=":memory:", embedding_engine=embedding_engine, use_sqlite_vec=False)

    docs = [
        VectorDocument(id="d-1", content="Authentication bypass in OAuth callback", category="auth"),
        VectorDocument(id="d-2", content="SQL injection in search form query", category="injection"),
        VectorDocument(id="d-3", content="Directory traversal arbitrary file disclosure", category="traversal"),
    ]
    vec_store.add_documents(docs)
    npy_store.add_documents(docs)

    query = "login authentication bypass token vulnerability"
    res_vec = vec_store.search(query, top_k=3)
    res_npy = npy_store.search(query, top_k=3)

    assert len(res_vec) == len(res_npy) == 3
    # Top ranked document must be identical
    assert res_vec[0].id == res_npy[0].id == "d-1"
    # Scores should be practically identical (within float32 precision)
    assert pytest.approx(res_vec[0].score, rel=1e-3) == res_npy[0].score

    vec_store.close()
    npy_store.close()


# ============================================================================
# 7. Helper & Singleton Functions Tests
# ============================================================================

def test_get_embedding_engine_and_vector_store_helpers():
    """Verify singleton/cached factory helpers get_embedding_engine and get_vector_store."""
    eng1 = get_embedding_engine()
    eng2 = get_embedding_engine()
    assert eng1 is eng2

    vstore1 = get_vector_store(db_path=":memory:")
    vstore2 = get_vector_store()
    assert vstore1 is vstore2
    vstore1.close()
