"""
Unit and Integration Tests for Workspace Copilot Blended Context Engine.

Covers:
1. ContextSource model extensions (vector_score, constants, metadata sync).
2. Blended Context Ranker hybrid scoring formula:
   S_hybrid = w_vec * S_vec + w_lex * S_lex + S_scope + S_type
3. Backward-compatible lexical fallback when vector score is absent or zero.
4. Thresholding and priority filtering (Critical, High, Medium, Low).
5. Semantic vector retrieval in ResearchContextEngine across Findings, Evidence, and CVEs.
6. Evidence deduplication and vector score enrichment.
7. Mission and project isolation during vector retrieval and policy enforcement.
8. ContextAssembler rendering of CVE knowledge and historical memories.
9. End-to-end prompt resolution in ResearchContextEngine.
"""

import pytest
from argus.workspace.context.models import (
    ContextQuery,
    ContextSource,
    ContextResult,
    SEMANTIC_STATUS_OBSERVATION,
    SEMANTIC_STATUS_EVIDENCE,
    SEMANTIC_STATUS_FINDING,
    SEMANTIC_STATUS_CVE_KNOWLEDGE,
    SEMANTIC_STATUS_HISTORICAL_MEMORY,
    SEMANTIC_STATUS_VECTOR_FINDING,
    SEMANTIC_STATUS_VECTOR_EVIDENCE,
    SOURCE_TYPE_CVE_KNOWLEDGE,
    SOURCE_TYPE_HISTORICAL_MEMORY,
    SOURCE_TYPE_VECTOR_FINDING,
    SOURCE_TYPE_VECTOR_EVIDENCE,
)
from argus.workspace.context.ranker import ContextRanker
from argus.workspace.context.policy import ContextPolicy
from argus.workspace.context.assembler import ContextAssembler
from argus.workspace.context.engine import ResearchContextEngine
from argus.vector import VectorStore, VectorDocument
from argus.reporting.vector_indexer import FindingSemanticSearchEngine, ScanEvidenceIndexer
from argus.knowledge.cve_kb import CVEKnowledgeBase
from argus.knowledge.cve_models import CVEEntry
from argus.reporting.models import Finding, ReportSeverity
from argus.evidence.model import Evidence


# ==============================================================================
# 1. Models & ContextSource Tests
# ==============================================================================

def test_context_source_vector_score_support():
    """Verify vector_score attribute and metadata synchronization."""
    src = ContextSource(
        source_id="src_1",
        source_type=SOURCE_TYPE_VECTOR_FINDING,
        title="SQL Injection in Auth",
        content="Bypass via ' OR 1=1--",
        semantic_status=SEMANTIC_STATUS_VECTOR_FINDING,
        vector_score=0.88,
    )
    assert src.vector_score == 0.88
    assert src.metadata.get("vector_score") == 0.88

    # Verify reverse synchronization from metadata
    src_meta = ContextSource(
        source_id="src_2",
        source_type=SOURCE_TYPE_CVE_KNOWLEDGE,
        title="Log4j RCE",
        content="JNDI vulnerability",
        semantic_status=SEMANTIC_STATUS_CVE_KNOWLEDGE,
        metadata={"vector_score": 0.92},
    )
    assert src_meta.vector_score == 0.92

    # Verify default is None
    src_default = ContextSource(
        source_id="src_3",
        source_type="evidence",
        title="Plain Evidence",
        content="Logs",
        semantic_status=SEMANTIC_STATUS_EVIDENCE,
    )
    assert src_default.vector_score is None


# ==============================================================================
# 2. Blended Context Ranker Tests
# ==============================================================================

def test_blended_ranker_hybrid_score_calculation():
    """
    Verify exact mathematical calculation:
    S_hybrid = w_vec * S_vec + w_lex * S_lex + S_scope + S_type
    with w_vec=0.6, w_lex=0.4
    """
    ranker = ContextRanker(w_vec=0.6, w_lex=0.4)
    query = ContextQuery(
        conversation_id="conv_1",
        query="database injection vulnerability",
        mission_id="mission_100",
        investigation_id="inv_50",
    )

    # Source with:
    # - Vector score = 0.85 -> S_vec = 8.5 -> w_vec * S_vec = 0.6 * 8.5 = 5.10
    # - Overlap: "database", "injection", "vulnerability" (all >3 chars) -> overlap = 3
    #   S_lex = 3 * 2.0 = 6.0 -> w_lex * S_lex = 0.4 * 6.0 = 2.40
    # - Scope: mission match (+5.0) + investigation match (+10.0) -> S_scope = 15.0
    # - Type: VECTOR_FINDING -> S_type = 3.0
    # Expected S_hybrid = 5.10 + 2.40 + 15.0 + 3.0 = 25.50 -> "Critical"
    source = ContextSource(
        source_id="find_1",
        source_type=SOURCE_TYPE_VECTOR_FINDING,
        title="Database Injection Vulnerability in login",
        content="Exploited database injection vulnerability successfully",
        semantic_status=SEMANTIC_STATUS_VECTOR_FINDING,
        mission_id="mission_100",
        investigation_id="inv_50",
        vector_score=0.85,
    )

    ranked = ranker.rank(query, [source])
    assert len(ranked) == 1
    assert ranked[0].relevance_score == "Critical"
    assert pytest.approx(ranked[0].metadata["hybrid_score"], 0.01) == 25.50
    assert pytest.approx(ranked[0].metadata["vector_score_component"], 0.01) == 5.10
    assert pytest.approx(ranked[0].metadata["lexical_score_component"], 0.01) == 2.40
    assert pytest.approx(ranked[0].metadata["scope_score_component"], 0.01) == 15.0
    assert pytest.approx(ranked[0].metadata["type_score_component"], 0.01) == 3.0


def test_pure_lexical_fallback_backward_compatibility():
    """
    CRITICAL: Ensure 100% backward compatibility.
    When vector score is absent or 0, w_lex defaults to 1.0.
    """
    ranker = ContextRanker(w_vec=0.6, w_lex=0.4)
    query = ContextQuery(
        conversation_id="conv_1",
        query="admin token bypass",
        mission_id="m1",
    )

    # Replicate legacy test_context.py scenario:
    # Source 1: Irrelevant OBSERVATION, mission_id="m1", vector_score=None
    # Scope: mission (+5.0), Overlap: 0, Type: 0, Vector: None
    # S_hybrid = 1.0 * 0 + 5.0 + 0 = 5.0 -> "Medium"
    source1 = ContextSource(
        source_id="1",
        source_type="ev",
        title="Irrelevant",
        content="Some logs",
        semantic_status=SEMANTIC_STATUS_OBSERVATION,
        mission_id="m1",
        vector_score=None,
    )

    # Source 2: Admin Token Bypass EVIDENCE, mission_id="m1", vector_score=0.0
    # Scope: mission (+5.0), Overlap: 3 terms * 2.0 = 6.0, Type: EVIDENCE (+3.0)
    # S_hybrid = 1.0 * 6.0 + 5.0 + 3.0 = 14.0 -> "High"
    source2 = ContextSource(
        source_id="2",
        source_type="ev",
        title="Admin Token Bypass",
        content="The token was bypassed.",
        semantic_status=SEMANTIC_STATUS_EVIDENCE,
        mission_id="m1",
        vector_score=0.0,
    )

    ranked = ranker.rank(query, [source1, source2])
    assert len(ranked) == 2
    assert ranked[0].source_id == "2"
    assert ranked[0].relevance_score == "High"
    assert pytest.approx(ranked[0].metadata["hybrid_score"], 0.01) == 14.0
    assert ranked[0].metadata["lexical_score_component"] == 6.0
    assert ranked[0].metadata["vector_score_component"] == 0.0

    assert ranked[1].source_id == "1"
    assert ranked[1].relevance_score == "Medium"
    assert pytest.approx(ranked[1].metadata["hybrid_score"], 0.01) == 5.0


def test_blended_ranker_semantic_reordering():
    """
    Verify that semantic similarity elevates high-signal documents
    over keyword-only matches with weak semantics.
    """
    ranker = ContextRanker(w_vec=0.6, w_lex=0.4)
    query = ContextQuery(
        conversation_id="conv_1",
        query="database query parameter manipulation",
        mission_id="m1",
    )

    # Candidate A: High lexical overlap (3 words), but zero vector score
    # S_lex = 6.0 -> 1.0 * 6.0 = 6.0; scope = 5.0; type = 0. Total = 11.0
    candidate_a = ContextSource(
        source_id="lex_only",
        source_type="observation",
        title="Database Query Parameter",
        content="Standard query parameter log output",
        semantic_status=SEMANTIC_STATUS_OBSERVATION,
        mission_id="m1",
        vector_score=None,
    )

    # Candidate B: Lower lexical overlap (1 word), but very high vector similarity (0.95)
    # S_vec = 9.5 -> 0.6 * 9.5 = 5.7
    # S_lex = 2.0 -> 0.4 * 2.0 = 0.8
    # scope = 5.0; type = 3.0 (VECTOR_FINDING)
    # Total = 5.7 + 0.8 + 5.0 + 3.0 = 14.5
    candidate_b = ContextSource(
        source_id="vec_high",
        source_type="vector_finding",
        title="SQL Injection Vulnerability",
        content="Manipulated parameter in authentication endpoint extracting records",
        semantic_status=SEMANTIC_STATUS_VECTOR_FINDING,
        mission_id="m1",
        vector_score=0.95,
    )

    ranked = ranker.rank(query, [candidate_a, candidate_b])
    assert len(ranked) == 2
    assert ranked[0].source_id == "vec_high"
    assert ranked[1].source_id == "lex_only"


def test_blended_ranker_filters_low_relevance_and_caps():
    """Verify items below threshold (<5.0) are filtered and max limit is respected."""
    ranker = ContextRanker(max_context_sources=3)
    query = ContextQuery(conversation_id="c1", query="crypto keys")

    sources = [
        ContextSource(
            source_id="low_1",
            source_type="obs",
            title="Irrelevant log",
            content="Random networking data",
            semantic_status=SEMANTIC_STATUS_OBSERVATION,
            vector_score=0.0,
        ),
        ContextSource(
            source_id="high_1",
            source_type="finding",
            title="Hardcoded Crypto Keys in config",
            content="Found AES keys in settings.json",
            semantic_status=SEMANTIC_STATUS_FINDING,
            vector_score=0.9,
        ),
        ContextSource(
            source_id="high_2",
            source_type="finding",
            title="Exposed Crypto Private Keys",
            content="RSA key discovered in repo",
            semantic_status=SEMANTIC_STATUS_FINDING,
            vector_score=0.85,
        ),
        ContextSource(
            source_id="high_3",
            source_type="finding",
            title="Weak Crypto Initialization",
            content="DES used in session encryption",
            semantic_status=SEMANTIC_STATUS_FINDING,
            vector_score=0.8,
        ),
        ContextSource(
            source_id="high_4",
            source_type="finding",
            title="Insecure Crypto Hashing",
            content="MD5 used for passwords",
            semantic_status=SEMANTIC_STATUS_FINDING,
            vector_score=0.75,
        ),
    ]

    ranked = ranker.rank(query, sources)
    # low_1 score < 5.0 -> filtered out
    # max_context_sources = 3 -> only top 3 of the 4 high candidates returned
    assert len(ranked) == 3
    assert all(s.source_id != "low_1" for s in ranked)
    assert ranked[0].source_id == "high_1"


# ==============================================================================
# 3. ContextAssembler Tests (CVE & Memory Rendering)
# ==============================================================================

def test_context_assembler_cve_and_memory_rendering():
    """Verify assembler renders CVE knowledge and historical memories sections."""
    assembler = ContextAssembler()
    cve_source = ContextSource(
        source_id="CVE-2021-44228",
        source_type=SOURCE_TYPE_CVE_KNOWLEDGE,
        title="Apache Log4j Remote Code Execution",
        content="JNDI lookup feature allows remote code execution via LDAP/RMI vectors.",
        semantic_status=SEMANTIC_STATUS_CVE_KNOWLEDGE,
        relevance_score="High",
        metadata={
            "cve_id": "CVE-2021-44228",
            "cvss_score": 10.0,
            "severity": "critical",
            "cwes": ["CWE-502", "CWE-400"],
            "affected_products": ["Apache Log4j"],
        },
    )

    mem_source = ContextSource(
        source_id="mem_101",
        source_type=SOURCE_TYPE_HISTORICAL_MEMORY,
        title="Bypassed Cloudflare WAF via Chunked Transfer",
        content="Applied Transfer-Encoding chunked payload to evade inspection on /api/upload.",
        semantic_status=SEMANTIC_STATUS_HISTORICAL_MEMORY,
        relevance_score="High",
        metadata={
            "memory_type": "ATTACK_PATTERN",
        },
    )

    result = ContextResult(
        context_status="OK",
        sources=[cve_source, mem_source],
        user_permission_state="AUTHORIZED_FOR_MISSION",
        authorization_scope="RESTRICTED_TO_MISSION_SCOPE",
    )

    output = assembler.assemble(result)

    # Verify CVE section
    assert "### RELEVANT CVE & VULNERABILITY KNOWLEDGE" in output
    assert "CVE-2021-44228" in output
    assert "Apache Log4j" in output
    assert "CVSS: 10.0" in output
    assert "CWE-502" in output
    assert "Description: JNDI lookup feature allows remote code execution" in output

    # Verify Memory section
    assert "### RECALLED MEMORIES & HISTORICAL PATTERNS" in output
    assert "[Memory #mem_101] (ATTACK_PATTERN) Bypassed Cloudflare WAF" in output
    assert "Transfer-Encoding chunked" in output


def test_context_assembler_omits_empty_sections():
    """Ensure CVE and memory sections are omitted when not in result."""
    assembler = ContextAssembler()
    result = ContextResult(
        context_status="OK",
        sources=[
            ContextSource(
                source_id="1",
                source_type="ev",
                title="Evidence 1",
                content="Standard evidence",
                semantic_status=SEMANTIC_STATUS_EVIDENCE,
            )
        ],
    )
    output = assembler.assemble(result)
    assert "### RELEVANT EVIDENCE" in output
    assert "### RELEVANT CVE & VULNERABILITY KNOWLEDGE" not in output
    assert "### RECALLED MEMORIES & HISTORICAL PATTERNS" not in output


# ==============================================================================
# 4. ResearchContextEngine Semantic Retrieval Integration Tests
# ==============================================================================

def test_research_context_engine_vector_retrieval_integration():
    """
    Test ResearchContextEngine retrieving from VectorStore,
    FindingSemanticSearchEngine, and CVEKnowledgeBase.
    """
    # Isolated in-memory vector store
    vstore = VectorStore(db_path=":memory:")
    finding_engine = FindingSemanticSearchEngine(vector_store=vstore)
    cve_kb = CVEKnowledgeBase(vector_store=vstore)

    # 1. Index a finding into vector store
    finding = Finding(
        id="f_yaml_rce",
        title="YAML Deserialization Leading to RCE",
        category="rce",
        severity="critical",
        endpoint="/api/v1/load_profile",
        parameter="profile_data",
        description="Unsafe PyYAML load enables remote code execution",
        status="CONFIRMED",
    )
    finding_engine.indexer.index_finding(finding, mission_id="mission_sec_1")

    # 2. Ingest a CVE into knowledge base
    cve_entry = CVEEntry(
        cve_id="CVE-2020-14343",
        title="PyYAML Arbitrary Code Execution",
        description="A vulnerability was discovered in the PyYAML library where yaml.load allows arbitrary Python code execution.",
        severity="critical",
        cvss_score=9.8,
        cwes=["CWE-502"],
        affected_products=["PyYAML"],
    )
    cve_kb.ingest_entries([cve_entry])

    # 3. Instantiate ResearchContextEngine with these vector sources
    engine = ResearchContextEngine(
        vector_store=vstore,
        finding_search_engine=finding_engine,
        cve_knowledge_base=cve_kb,
        min_semantic_score=0.25,
    )

    query = ContextQuery(
        conversation_id="conv_sec_test",
        query="python yaml deserialization remote code execution",
        mission_id="mission_sec_1",
    )

    sources = engine._retrieve_sources(query)
    source_ids = [s.source_id for s in sources]

    # Verify both finding and CVE were retrieved
    assert "f_yaml_rce" in source_ids
    assert "CVE-2020-14343" in source_ids

    # Verify vector scores attached
    finding_src = next(s for s in sources if s.source_id == "f_yaml_rce")
    assert finding_src.vector_score is not None and finding_src.vector_score > 0.0
    assert finding_src.semantic_status == SEMANTIC_STATUS_VECTOR_FINDING

    cve_src = next(s for s in sources if s.source_id == "CVE-2020-14343")
    assert cve_src.vector_score is not None and cve_src.vector_score > 0.0
    assert cve_src.semantic_status == SEMANTIC_STATUS_CVE_KNOWLEDGE

    # 4. Resolve Context into final assembled prompt
    prompt = engine.resolve_context(query)
    assert "### CONFIRMED FINDINGS" in prompt
    assert "YAML Deserialization Leading to RCE" in prompt
    assert "### RELEVANT CVE & VULNERABILITY KNOWLEDGE" in prompt
    assert "CVE-2020-14343" in prompt


def test_research_context_engine_mission_and_project_isolation():
    """
    Verify strict mission and project isolation during semantic retrieval:
    Sources belonging to mission_B must not leak into mission_A context.
    """
    vstore = VectorStore(db_path=":memory:")
    finding_engine = FindingSemanticSearchEngine(vector_store=vstore)

    finding_a = Finding(
        id="find_alpha",
        title="SQL Injection on Internal Admin",
        category="sql_injection",
        severity="high",
        description="Auth bypass via SQLi",
        status="CONFIRMED",
    )
    finding_b = Finding(
        id="find_beta",
        title="SQL Injection on Public API",
        category="sql_injection",
        severity="high",
        description="Public endpoint SQLi",
        status="CONFIRMED",
    )

    finding_engine.indexer.index_finding(finding_a, mission_id="mission_alpha")
    finding_engine.indexer.index_finding(finding_b, mission_id="mission_beta")

    engine = ResearchContextEngine(
        vector_store=vstore,
        finding_search_engine=finding_engine,
        min_semantic_score=0.25,
    )

    # Query scoped strictly to mission_alpha
    query_alpha = ContextQuery(
        conversation_id="conv_a",
        query="sql injection vulnerability",
        mission_id="mission_alpha",
    )

    sources = engine._retrieve_sources(query_alpha)
    ids = [s.source_id for s in sources]
    assert "find_alpha" in ids
    assert "find_beta" not in ids  # Isolated!

    # Verify through resolve_context
    prompt_alpha = engine.resolve_context(query_alpha)
    assert "find_alpha" in prompt_alpha
    assert "find_beta" not in prompt_alpha


def test_evidence_deduplication_and_enrichment():
    """
    Verify that an evidence item already retrieved via EvidenceManager
    is not duplicated when matched by vector search, but enriched with vector_score.
    """
    vstore = VectorStore(db_path=":memory:")
    finding_engine = FindingSemanticSearchEngine(vector_store=vstore)

    engine = ResearchContextEngine(
        vector_store=vstore,
        finding_search_engine=finding_engine,
        min_semantic_score=0.25,
    )

    # Save evidence in EvidenceManager
    ev = Evidence(
        evidence_id="ev_dedup_1",
        title="Admin Portal Access Logs",
        description="Contains evidence of brute force attack",
        investigation_id="inv_dedup",
        status="CONFIRMED",
    )
    engine.evidence_manager.save(ev)

    # Also index in vector store
    finding_engine.indexer.index_evidence(ev)

    query = ContextQuery(
        conversation_id="conv_1",
        query="brute force access logs",
        investigation_id="inv_dedup",
    )

    sources = engine._retrieve_sources(query)

    # Must contain exactly 1 occurrence of ev_dedup_1
    ev_sources = [s for s in sources if s.source_id == "ev_dedup_1"]
    assert len(ev_sources) == 1
    # Enriched with vector score from search
    assert ev_sources[0].vector_score is not None
    assert ev_sources[0].vector_score > 0.0


def test_research_context_engine_project_isolation():
    """
    Verify project-level isolation:
    Findings belonging to project_2 are excluded when querying project_1.
    """
    vstore = VectorStore(db_path=":memory:")
    finding_engine = FindingSemanticSearchEngine(vector_store=vstore)

    finding_p1 = Finding(
        id="find_proj1",
        title="IDOR in User Profile",
        category="idor",
        severity="high",
        description="Direct object reference accessing other user profiles",
        status="CONFIRMED",
        metadata={"project_id": "proj_1"},
    )
    finding_p2 = Finding(
        id="find_proj2",
        title="IDOR in Billing System",
        category="idor",
        severity="high",
        description="Direct object reference accessing invoices",
        status="CONFIRMED",
        metadata={"project_id": "proj_2"},
    )

    finding_engine.indexer.index_finding(finding_p1, mission_id="m1")
    finding_engine.indexer.index_finding(finding_p2, mission_id="m1")

    engine = ResearchContextEngine(
        vector_store=vstore,
        finding_search_engine=finding_engine,
        min_semantic_score=0.25,
    )

    query = ContextQuery(
        conversation_id="conv_p1",
        query="insecure direct object reference",
        project_id="proj_1",
    )

    sources = engine._retrieve_sources(query)
    source_ids = [s.source_id for s in sources]
    assert "find_proj1" in source_ids
    assert "find_proj2" not in source_ids


def test_research_context_engine_memory_manager_recall():
    """
    Verify that if a memory manager is configured, recalled memories are
    converted to HISTORICAL_MEMORY sources.
    """
    class MockMemoryEntry:
        def __init__(self, id, title, content, memory_type):
            self.id = id
            self.title = title
            self.content = content
            self.metadata = {"memory_type": memory_type}

    class MockMemorySearchResult:
        def __init__(self, entry, score):
            self.entry = entry
            self.score = score

    class MockMemoryManager:
        def recall(self, query):
            if "ssrf" in query.query.lower():
                return [
                    MockMemorySearchResult(
                        entry=MockMemoryEntry(
                            id="mem_ssrf_bypass",
                            title="SSRF DNS Rebinding Strategy",
                            content="Used 127.0.0.1 nip.io domain to bypass host whitelist",
                            memory_type="ATTACK_PATTERN",
                        ),
                        score=0.88,
                    )
                ]
            return []

    engine = ResearchContextEngine(
        enable_semantic_retrieval=True,
        memory_manager=MockMemoryManager(),
    )

    query = ContextQuery(
        conversation_id="conv_mem",
        query="ssrf dns rebinding cloud bypass",
    )

    sources = engine._retrieve_sources(query)
    mem_sources = [s for s in sources if s.semantic_status == SEMANTIC_STATUS_HISTORICAL_MEMORY]
    assert len(mem_sources) == 1
    assert mem_sources[0].source_id == "mem_ssrf_bypass"
    assert mem_sources[0].vector_score == 0.88
    assert "nip.io" in mem_sources[0].content


def test_custom_ranker_weights():
    """Verify custom ranker weights: w_vec=0.8, w_lex=0.2."""
    ranker = ContextRanker(w_vec=0.8, w_lex=0.2)
    query = ContextQuery(conversation_id="c1", query="buffer overflow exploit")

    # Overlap: "buffer" (6), "overflow" (8), "exploit" (7) -> 3 terms -> S_lex = 6.0
    # w_lex * S_lex = 0.2 * 6.0 = 1.20
    # S_vec = 0.9 * 10 = 9.0 -> w_vec * S_vec = 0.8 * 9.0 = 7.20
    # Type priority: VECTOR_FINDING -> +3.0
    # S_hybrid = 7.20 + 1.20 + 0 + 3.0 = 11.40
    source = ContextSource(
        source_id="bo_1",
        source_type=SOURCE_TYPE_VECTOR_FINDING,
        title="Buffer Overflow Exploit in Parser",
        content="Stack buffer overflow exploit payload",
        semantic_status=SEMANTIC_STATUS_VECTOR_FINDING,
        vector_score=0.9,
    )

    ranked = ranker.rank(query, [source])
    assert len(ranked) == 1
    assert pytest.approx(ranked[0].metadata["hybrid_score"], 0.01) == 11.40
    assert ranked[0].relevance_score == "High"


def test_empty_query_handles_gracefully():
    """Verify empty or whitespace query skips semantic retrieval without errors."""
    engine = ResearchContextEngine(enable_semantic_retrieval=True)
    query = ContextQuery(conversation_id="c1", query="   ")
    sources = engine._retrieve_sources(query)
    # Should not throw any exception and return only non-semantic sources
    assert isinstance(sources, list)


def test_vector_store_failure_resilience():
    """Verify engine degrades gracefully if vector store raises an exception."""
    class FailingVectorStore:
        def search(self, *args, **kwargs):
            raise RuntimeError("Database disk full or locked")

    class FailingSearchEngine:
        def search_findings(self, *args, **kwargs):
            raise RuntimeError("Engine disconnected")
        def search_evidence(self, *args, **kwargs):
            raise RuntimeError("Engine disconnected")

    engine = ResearchContextEngine(
        finding_search_engine=FailingSearchEngine(),
        vector_store=FailingVectorStore(),
    )

    query = ContextQuery(conversation_id="c1", query="remote code execution")
    # Must not raise RuntimeError; should proceed gracefully
    sources = engine._retrieve_sources(query)
    assert isinstance(sources, list)
