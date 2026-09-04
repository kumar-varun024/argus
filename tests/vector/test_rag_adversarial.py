"""
Adversarial evaluation of the full RAG pipeline under hostile inputs (Sprint 31c).

Covers:
- Poisoned Finding Injection
- Deceptive CVE Records
- Embedding Collision Attacks
- Cross-Source Contamination
- Ranking Manipulation
- Large-Scale Stress
"""

from __future__ import annotations

import concurrent.futures
from pathlib import Path
import pytest

from argus.evidence.model import Evidence
from argus.knowledge.cve_correlator import CVECorrelator
from argus.knowledge.cve_kb import CVEKnowledgeBase
from argus.knowledge.cve_models import CVEEntry
from argus.memory.manager import MemoryManager
from argus.reporting.models import Finding
from argus.reporting.vector_indexer import FindingSemanticSearchEngine, ScanEvidenceIndexer
from argus.vector.embeddings import EmbeddingEngine
from argus.vector.models import VectorFilter, VectorStoreConfig
from argus.vector.store import VectorStore


@pytest.fixture
def temp_db_path(tmp_path: Path) -> str:
    return str(tmp_path / "adversarial_rag.db")


@pytest.fixture
def embedding_engine() -> EmbeddingEngine:
    return EmbeddingEngine(provider="deterministic", dimension=384)


@pytest.fixture
def vector_store(temp_db_path: str, embedding_engine: EmbeddingEngine) -> VectorStore:
    config = VectorStoreConfig(
        db_path=temp_db_path,
        dimension=384,
        use_sqlite_vec=False,
    )
    store = VectorStore(config=config, embedding_engine=embedding_engine)
    yield store
    store.close()


# ==============================================================================
# Poisoned Finding Injection (3 tests)
# ==============================================================================


def test_poisoned_finding_verbatim(vector_store: VectorStore):
    """Verify adversarial payloads are stored and retrieved verbatim without corruption."""
    indexer = ScanEvidenceIndexer(vector_store=vector_store)
    engine = FindingSemanticSearchEngine(vector_store=vector_store)

    adv_title = "Admin Login \x00'; DROP TABLE documents; --"
    adv_desc = "<script>alert('XSS')</script> \u202e malicious \x00 payload"

    finding = Finding(
        id="adv-01",
        title=adv_title,
        category="sql_injection",
        severity="critical",
        description=adv_desc,
        impact="Full compromise",
        remediation="Parameterized queries",
    )
    doc_id = indexer.index_finding(finding, mission_id="m1")

    # Verify directly from VectorStore
    doc = vector_store.get(doc_id)
    assert doc is not None
    assert doc.metadata["title"] == adv_title
    assert doc.metadata["raw_finding"]["description"] == adv_desc
    assert adv_title in doc.content
    assert adv_desc in doc.content

    # Verify via FindingSemanticSearchEngine
    retrieved = engine.get_finding(finding.id, mission_id="m1")
    assert retrieved is not None
    assert retrieved.metadata["title"] == adv_title
    assert retrieved.metadata["raw_finding"]["description"] == adv_desc
    assert adv_title in retrieved.content
    assert adv_desc in retrieved.content


def test_poisoned_finding_no_corruption(vector_store: VectorStore):
    """Verify poisoned content does not corrupt the store (can add and search after)."""
    indexer = ScanEvidenceIndexer(vector_store=vector_store)
    engine = FindingSemanticSearchEngine(vector_store=vector_store)

    finding = Finding(
        id="adv-01",
        title="\x00'; DROP TABLE documents; --",
        category="sql_injection",
        severity="critical",
        description="<script>alert('XSS')</script>",
        impact="impact",
        remediation="remediation",
    )
    indexer.index_finding(finding, mission_id="m1")

    # Verify we can still add subsequent findings and search
    finding2 = Finding(
        id="benign-02",
        title="Normal SQLi in auth",
        category="sql_injection",
        severity="high",
        description="Standard union-based database injection",
        impact="impact",
        remediation="remediation",
    )
    indexer.index_finding(finding2, mission_id="m1")

    assert vector_store.count() == 2

    res = engine.search_findings("Normal SQLi", top_k=5)
    assert len(res) >= 1
    assert any(r.id.endswith("benign-02") for r in res)


def test_poisoned_finding_relevance(vector_store: VectorStore):
    """Verify search retrieval returns correct results by semantic relevance despite payloads."""
    indexer = ScanEvidenceIndexer(vector_store=vector_store)
    engine = FindingSemanticSearchEngine(vector_store=vector_store)

    f1 = Finding(
        id="f1",
        title="SQL Injection in auth",
        category="sql_injection",
        severity="critical",
        description="Valid union-based SQL injection payload in login parameter",
        impact="none",
        remediation="none",
    )
    f2 = Finding(
        id="f2",
        title="<script>alert('XSS')</script>",
        category="xss",
        severity="high",
        description="Cross-site scripting DOM script injection in user profile",
        impact="none",
        remediation="none",
    )

    indexer.index_finding(f1, mission_id="m1")
    indexer.index_finding(f2, mission_id="m1")

    # Query targeting SQL injection
    res_sqli = engine.search_findings("database sql injection parameter", top_k=5)
    assert len(res_sqli) >= 1
    assert res_sqli[0].category == "sql_injection"

    # Query targeting XSS
    res_xss = engine.search_findings("cross site scripting DOM script injection", top_k=5)
    assert len(res_xss) >= 1
    assert res_xss[0].category == "xss"


# ==============================================================================
# Deceptive CVE Records (3 tests)
# ==============================================================================


def test_deceptive_cve_mismatched_description(vector_store: VectorStore):
    """Verify correlator downranks CVE records with mismatched descriptions despite CWE tag."""
    kb = CVEKnowledgeBase(vector_store=vector_store)

    cve = CVEEntry(
        cve_id="CVE-9999-0001",
        title="Deceptive CVE Record",
        description="This vulnerability describes Cross-Site Scripting (XSS) client browser DOM execution.",
        severity="high",
        cvss_score=8.0,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cwes=["CWE-89"],  # Tagged with SQLi CWE misleadingly
        affected_products=["TestDB"],
        references=[],
    )
    kb.ingest_entries([cve])
    correlator = CVECorrelator(cve_kb=kb)

    finding = Finding(
        id="f1",
        title="SQL Injection Database Bypass",
        category="sql_injection",
        severity="high",
        description="Union-based SQL injection allows complete database exfiltration.",
        impact="Database compromise",
        remediation="Parameterized queries",
    )

    # Correlator should not produce a high-confidence match because the semantic text is about XSS
    suggestions = correlator.correlate_finding(finding, top_k=3, min_score=0.85)
    assert len(suggestions) == 0


def test_cve_empty_none_fields(vector_store: VectorStore):
    """Test CVE entries with empty descriptions, None fields, and missing attributes."""
    kb = CVEKnowledgeBase(vector_store=vector_store)

    cve = CVEEntry(
        cve_id="CVE-9999-0002",
        title="",
        description="",
        severity="low",
        cvss_score=0.0,
        cvss_vector=None,
        cwes=[],
        affected_products=[],
        references=[],
    )
    ingested = kb.ingest_entries([cve])
    assert ingested == 1

    res = kb.get_cve("CVE-9999-0002")
    assert res is not None
    assert res.cve_id == "CVE-9999-0002"
    assert res.description == ""
    assert res.title == ""


def test_cve_extremely_long_description(vector_store: VectorStore):
    """Test CVE entries with extremely long descriptions (10,000 characters)."""
    kb = CVEKnowledgeBase(vector_store=vector_store)

    long_desc = ("Cross-site scripting vulnerability in web application interface. " * 200)[:10000]
    cve = CVEEntry(
        cve_id="CVE-9999-0003",
        title="CVE with 10K Character Description",
        description=long_desc,
        severity="medium",
        cvss_score=5.0,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        cwes=["CWE-79"],
        affected_products=["WebApp"],
        references=[],
    )
    kb.ingest_entries([cve])

    res = kb.get_cve("CVE-9999-0003")
    assert res is not None
    assert len(res.description) == len(long_desc)

    # Correlator handles long CVE description without error
    correlator = CVECorrelator(cve_kb=kb)
    finding = Finding(id="fx", title="Stored XSS", category="xss", severity="medium", description="XSS issue")
    suggestions = correlator.correlate_finding(finding, top_k=1, min_score=0.1)
    assert len(suggestions) >= 1
    assert suggestions[0].cve_id == "CVE-9999-0003"


# ==============================================================================
# Embedding Collision Attacks (3 tests)
# ==============================================================================


def test_embedding_collision_lexical_overlap(vector_store: VectorStore):
    """Craft pairs of semantically different inputs sharing lexical tokens."""
    indexer = ScanEvidenceIndexer(vector_store=vector_store)
    engine = FindingSemanticSearchEngine(vector_store=vector_store)

    f1 = Finding(id="f1", title="Admin uses script to bypass firewall", category="other", severity="low", description="desc", impact="i", remediation="r")
    f2 = Finding(id="f2", title="Firewall uses script to bypass admin", category="other", severity="low", description="desc", impact="i", remediation="r")

    indexer.index_finding(f1, mission_id="m1")
    indexer.index_finding(f2, mission_id="m1")

    res = engine.search_findings("admin bypass firewall", top_k=5)
    assert len(res) == 2
    ids = [r.id for r in res]
    assert any("f1" in i for i in ids)
    assert any("f2" in i for i in ids)


def test_embedding_collision_ranking(vector_store: VectorStore):
    """Verify store returns correct ranking when inputs share lexical terms."""
    indexer = ScanEvidenceIndexer(vector_store=vector_store)
    engine = FindingSemanticSearchEngine(vector_store=vector_store)

    f1 = Finding(id="f1", title="Database administrator monitors SQL queries", category="info", severity="low", description="Internal query monitoring")
    f2 = Finding(id="f2", title="SQL injection attacker extracts database passwords", category="sql_injection", severity="critical", description="Malicious injection attack")

    indexer.index_finding(f1, mission_id="m1")
    indexer.index_finding(f2, mission_id="m1")

    res = engine.search_findings("malicious SQL injection attack extract password", top_k=5)
    assert len(res) >= 1
    assert res[0].id.endswith("f2")
    assert res[0].severity == "critical"


def test_embedding_collision_stability(vector_store: VectorStore):
    """Test retrieval ranking stability across repeated searches."""
    indexer = ScanEvidenceIndexer(vector_store=vector_store)
    engine = FindingSemanticSearchEngine(vector_store=vector_store)

    for i in range(5):
        f = Finding(id=f"f{i}", title=f"Security vulnerability report {i} with authorization flaw", category="auth", severity="high", description="desc")
        indexer.index_finding(f, mission_id="m1")

    res_first = engine.search_findings("authorization flaw vulnerability", top_k=5)
    first_ids = [r.id for r in res_first]
    first_scores = [r.score for r in res_first]

    for _ in range(10):
        res = engine.search_findings("authorization flaw vulnerability", top_k=5)
        assert [r.id for r in res] == first_ids
        assert [r.score for r in res] == first_scores


# ==============================================================================
# Cross-Source Contamination (3 tests)
# ==============================================================================


def test_cross_source_finding_vs_memory(vector_store: VectorStore):
    """Verify source_type filtering prevents finding vs memory cross-bleed."""
    indexer = ScanEvidenceIndexer(vector_store=vector_store)
    mem_mgr = MemoryManager(vector_store=vector_store)

    shared_text = "Sensitive internal credential exposed in config"
    finding = Finding(id="f1", title=shared_text, category="info", severity="high", description=shared_text)
    indexer.index_finding(finding, mission_id="m1")

    mem_mgr.record_note(content=shared_text, title="Note on credential")

    # Search with source_type='finding' filter
    res_findings = vector_store.search(shared_text, filters=VectorFilter(source_type="finding"))
    assert len(res_findings) >= 1
    assert all(r.source_type == "finding" for r in res_findings)
    assert not any(r.source_type == "memory" for r in res_findings)

    # Search with source_type='memory' filter
    res_mem = vector_store.search(shared_text, filters=VectorFilter(source_type="memory"))
    assert len(res_mem) >= 1
    assert all(r.source_type == "memory" for r in res_mem)
    assert not any(r.source_type == "finding" for r in res_mem)


def test_cross_source_cve_vs_finding(vector_store: VectorStore):
    """Verify CVE and finding with overlapping text are isolated by source_type."""
    indexer = ScanEvidenceIndexer(vector_store=vector_store)
    kb = CVEKnowledgeBase(vector_store=vector_store)

    shared_text = "Apache Log4j remote code execution via JNDI lookup"
    finding = Finding(id="f_log4j", title=shared_text, category="rce", severity="critical", description=shared_text)
    indexer.index_finding(finding, mission_id="m1")

    cve = CVEEntry(
        cve_id="CVE-2021-44228",
        title=shared_text,
        description=shared_text,
        severity="critical",
        cvss_score=10.0,
        cwes=["CWE-502"],
        affected_products=["log4j"],
    )
    kb.ingest_entries([cve])

    res_cve = vector_store.search(shared_text, filters=VectorFilter(source_type="cve"))
    assert len(res_cve) >= 1
    assert all(r.source_type == "cve" for r in res_cve)
    assert not any(r.source_type == "finding" for r in res_cve)


def test_cross_source_multiple_filters(vector_store: VectorStore):
    """Verify list-based source_type filtering allows specified sources and excludes others."""
    indexer = ScanEvidenceIndexer(vector_store=vector_store)
    kb = CVEKnowledgeBase(vector_store=vector_store)
    mem_mgr = MemoryManager(vector_store=vector_store)

    text = "SQL injection attack vector on payment gateway"
    indexer.index_finding(Finding(id="f_sqli", title=text, category="sql_injection", severity="critical", description=text), mission_id="m1")
    kb.ingest_entries([CVEEntry(cve_id="CVE-2023-0001", title=text, description=text, severity="critical")])
    mem_mgr.record_note(content=text, title="Payment SQLi note")

    # Filter for finding + cve only
    res = vector_store.search(text, filters=VectorFilter(source_type=["finding", "cve"]))
    assert len(res) >= 2
    types = {r.source_type for r in res}
    assert "memory" not in types
    assert types.issubset({"finding", "cve"})


# ==============================================================================
# Ranking Manipulation (3 tests)
# ==============================================================================


def test_ranking_manipulation_keyword_stuffing(vector_store: VectorStore):
    """Verify well-written finding still appears in top results against keyword-stuffed finding."""
    indexer = ScanEvidenceIndexer(vector_store=vector_store)
    engine = FindingSemanticSearchEngine(vector_store=vector_store)

    f1 = Finding(id="stuffed", title="SQL SQL SQL SQL Injection Injection Injection", category="sql_injection", severity="low", description="SQL SQL SQL SQL Injection", impact="i", remediation="r")
    f2 = Finding(id="normal", title="SQL Injection vulnerability in login authentication", category="sql_injection", severity="high", description="Union-based SQL injection allows database bypass", impact="i", remediation="r")

    indexer.index_finding(f1, mission_id="m1")
    indexer.index_finding(f2, mission_id="m1")

    res = engine.search_findings("SQL Injection login authentication", top_k=5)
    assert len(res) == 2
    top_ids = [r.id for r in res]
    assert any("normal" in i for i in top_ids)
    assert res[0].id.endswith("normal")


def test_ranking_manipulation_repeated_queries(vector_store: VectorStore):
    """Verify repeating query terms does not cause score inflation beyond unit interval."""
    indexer = ScanEvidenceIndexer(vector_store=vector_store)
    engine = FindingSemanticSearchEngine(vector_store=vector_store)

    f1 = Finding(id="f1", title="Cross Site Scripting in Comments", category="xss", severity="high", description="XSS vulnerability allows script injection", impact="i", remediation="r")
    indexer.index_finding(f1, mission_id="m1")

    res1 = engine.search_findings("XSS", top_k=1)
    res2 = engine.search_findings("XSS XSS XSS XSS XSS XSS XSS", top_k=1)

    assert 0.0 <= res1[0].score <= 1.0
    assert 0.0 <= res2[0].score <= 1.0


def test_ranking_manipulation_long_query(vector_store: VectorStore):
    """Verify extremely long repetitive queries handle bounded scoring without failure."""
    indexer = ScanEvidenceIndexer(vector_store=vector_store)
    engine = FindingSemanticSearchEngine(vector_store=vector_store)

    f1 = Finding(id="f1", title="Path Traversal in File Download", category="traversal", severity="high", description="Directory traversal ../../ allows arbitrary file read", impact="i", remediation="r")
    indexer.index_finding(f1, mission_id="m1")

    query = "path traversal directory ../../ " * 100
    res = engine.search_findings(query, top_k=1)
    assert len(res) == 1
    assert 0.0 <= res[0].score <= 1.0


# ==============================================================================
# Large-Scale Stress (2 tests)
# ==============================================================================


def test_large_scale_stress_documents(vector_store: VectorStore):
    """Index 500+ documents with diverse security content and verify semantic search."""
    indexer = ScanEvidenceIndexer(vector_store=vector_store)
    engine = FindingSemanticSearchEngine(vector_store=vector_store)

    findings = [
        Finding(
            id=f"f_{i}",
            title=f"Vulnerability report {i}: {'SQL Injection' if i % 3 == 0 else ('XSS Flaw' if i % 3 == 1 else 'Remote Code Execution')}",
            category="sql_injection" if i % 3 == 0 else ("xss" if i % 3 == 1 else "rce"),
            severity="critical" if i % 5 == 0 else "high",
            description=f"Automated scan found issue index {i} on target host server_{i % 10}.corp",
        )
        for i in range(500)
    ]
    indexer.index_findings(findings, mission_id="m_stress")

    assert vector_store.count() == 500

    res = engine.search_findings("Remote Code Execution server_3.corp", top_k=5)
    assert len(res) > 0
    assert any(r.category == "rce" for r in res)


def test_large_scale_stress_concurrent(vector_store: VectorStore):
    """Test concurrent indexing and searching using ThreadPoolExecutor."""
    indexer = ScanEvidenceIndexer(vector_store=vector_store)
    engine = FindingSemanticSearchEngine(vector_store=vector_store)

    def writer(worker_id: int):
        for i in range(25):
            f = Finding(
                id=f"w{worker_id}_{i}",
                title=f"Concurrent Worker {worker_id} Finding {i} XSS",
                category="xss",
                severity="medium",
                description="Concurrent injection finding",
            )
            indexer.index_finding(f, mission_id="m_conc")

    def reader(worker_id: int):
        for _ in range(25):
            results = engine.search_findings("Concurrent Worker XSS", top_k=5)
            assert isinstance(results, list)

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        f_writers = [executor.submit(writer, w) for w in range(2)]
        f_readers = [executor.submit(reader, r) for r in range(2)]
        for f in f_writers + f_readers:
            f.result()

    total = engine.count_findings({"mission_id": "m_conc"})
    assert total == 50
