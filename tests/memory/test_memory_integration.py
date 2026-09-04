"""Integration tests for conversational memory system and ResearchContextEngine."""

import pytest

from argus.evidence.manager import EvidenceManager
from argus.evidence.model import Evidence
from argus.knowledge.cve_kb import CVEEntry, CVEKnowledgeBase
from argus.memory.manager import MemoryManager
from argus.memory.models import MemoryEntry, MemoryType
from argus.reporting.models import Finding
from argus.reporting.vector_indexer import FindingSemanticSearchEngine
from argus.vector.store import VectorStore
from argus.workspace.context.engine import ResearchContextEngine
from argus.workspace.context.models import (
    ContextQuery,
    SEMANTIC_STATUS_CVE_KNOWLEDGE,
    SEMANTIC_STATUS_HISTORICAL_MEMORY,
    SEMANTIC_STATUS_VECTOR_FINDING,
)


@pytest.fixture
def integrated_setup():
    vstore = VectorStore(db_path=":memory:")
    finding_engine = FindingSemanticSearchEngine(vector_store=vstore)
    cve_kb = CVEKnowledgeBase(vector_store=vstore)
    mem_mgr = MemoryManager(vector_store=vstore)

    engine = ResearchContextEngine(
        vector_store=vstore,
        finding_search_engine=finding_engine,
        cve_knowledge_base=cve_kb,
        memory_manager=mem_mgr,
        min_semantic_score=0.20,
        enable_semantic_retrieval=True,
    )
    return engine, mem_mgr, finding_engine, cve_kb, vstore


def test_research_context_engine_memory_manager_auto_initialization():
    vstore = VectorStore(db_path=":memory:")
    engine = ResearchContextEngine(vector_store=vstore)
    mgr = engine._get_memory_manager()
    assert mgr is not None
    assert isinstance(mgr, MemoryManager)
    # Shares vector store
    assert mgr.store.vector_store is vstore


def test_research_context_engine_resolve_with_memories(integrated_setup):
    engine, mem_mgr, _, _, _ = integrated_setup

    # Record attack pattern and strategic decision
    mem_mgr.record_attack_pattern(
        content="Target API uses HMAC signature verification with replay window of 60 seconds",
        mission_id="mission_api_test",
        tags=["hmac", "api_security"],
        title="HMAC Replay Window Rule",
    )
    mem_mgr.record_strategic_decision(
        content="Skip aggressive fuzzing on /api/v1/auth/token to avoid account lockouts",
        mission_id="mission_api_test",
        tags=["rate_limit", "strategy"],
        title="Token Endpoint Fuzzing Policy",
    )

    query = ContextQuery(
        conversation_id="conv_int_test",
        query="HMAC signature verification replay window api",
        mission_id="mission_api_test",
    )

    # 1. Test _retrieve_sources directly
    sources = engine._retrieve_sources(query)
    mem_sources = [s for s in sources if s.semantic_status == SEMANTIC_STATUS_HISTORICAL_MEMORY]
    assert len(mem_sources) >= 1
    assert any("HMAC" in s.content for s in mem_sources)

    # 2. Test resolve() method
    prompt = engine.resolve(query)
    assert isinstance(prompt, str)
    assert "### RECALLED MEMORIES & HISTORICAL PATTERNS" in prompt
    assert "HMAC" in prompt


def test_research_context_engine_semantic_retrieval_flag_disabled(integrated_setup):
    engine, mem_mgr, _, _, _ = integrated_setup
    engine.enable_semantic_retrieval = False

    mem_mgr.record_attack_pattern(
        content="Known SSTI payload for Jinja2 template engine",
        mission_id="mission_ssti",
    )

    query = ContextQuery(
        conversation_id="conv_no_sem",
        query="SSTI Jinja2 payload",
        mission_id="mission_ssti",
    )

    sources = engine._retrieve_sources(query)
    mem_sources = [s for s in sources if s.semantic_status == SEMANTIC_STATUS_HISTORICAL_MEMORY]
    assert len(mem_sources) == 0

    prompt = engine.resolve(query)
    assert "### RECALLED MEMORIES & HISTORICAL PATTERNS" not in prompt


def test_research_context_engine_memory_mission_isolation(integrated_setup):
    engine, mem_mgr, _, _, _ = integrated_setup

    # Memory in Mission Alpha
    mem_mgr.record_note(
        content="Confidential API key leaked in comment: AKIA_TEST_KEY_ALPHA",
        mission_id="mission_alpha",
    )
    # Memory in Mission Beta
    mem_mgr.record_note(
        content="Confidential API key leaked in comment: AKIA_TEST_KEY_BETA",
        mission_id="mission_beta",
    )

    # Query Mission Alpha
    query_alpha = ContextQuery(
        conversation_id="conv_iso_alpha",
        query="API key leaked comment",
        mission_id="mission_alpha",
    )
    prompt_alpha = engine.resolve(query_alpha)
    assert "AKIA_TEST_KEY_ALPHA" in prompt_alpha
    assert "AKIA_TEST_KEY_BETA" not in prompt_alpha

    # Query Mission Beta
    query_beta = ContextQuery(
        conversation_id="conv_iso_beta",
        query="API key leaked comment",
        mission_id="mission_beta",
    )
    prompt_beta = engine.resolve(query_beta)
    assert "AKIA_TEST_KEY_BETA" in prompt_beta
    assert "AKIA_TEST_KEY_ALPHA" not in prompt_beta


def test_research_context_engine_global_memory_shared_across_missions(integrated_setup):
    engine, mem_mgr, _, _, _ = integrated_setup

    # Global memory with no mission_id
    mem_mgr.record_strategic_decision(
        content="Corporate policy: Always suppress automated SQLMap against production hosts",
        mission_id=None,
    )

    # Both Mission A and Mission B should receive the global strategic decision
    for m_id in ["mission_corp_a", "mission_corp_b"]:
        query = ContextQuery(
            conversation_id=f"conv_{m_id}",
            query="policy automated SQLMap production hosts",
            mission_id=m_id,
        )
        prompt = engine.resolve(query)
        assert "Always suppress automated SQLMap" in prompt


def test_research_context_engine_blended_context_all_sources(integrated_setup):
    engine, mem_mgr, finding_engine, cve_kb, _ = integrated_setup

    # 1. Finding
    finding = Finding(
        id="f_graphql_dos",
        title="GraphQL Batch Query Depth Denial of Service",
        category="graphql",
        severity="high",
        endpoint="/graphql",
        parameter="query",
        description="Nested circular GraphQL query causes thread exhaustion",
        status="CONFIRMED",
    )
    finding_engine.indexer.index_finding(finding, mission_id="mission_blend")

    # 2. CVE
    cve = CVEEntry(
        cve_id="CVE-2021-39184",
        title="Apollo Server GraphQL Query Complexity DoS",
        description="Apollo Server is vulnerable to denial of service via query complexity amplification.",
        severity="high",
        cvss_score=7.5,
        cwes=["CWE-400"],
        affected_products=["Apollo Server"],
    )
    cve_kb.ingest_entries([cve])

    # 3. Memory
    mem_mgr.record_attack_pattern(
        content="GraphQL denial of service via array batching and query complexity depth amplification",
        mission_id="mission_blend",
        tags=["graphql", "evasion"],
        title="GraphQL Depth Evasion Technique",
    )

    query = ContextQuery(
        conversation_id="conv_blended_all",
        query="GraphQL denial of service query complexity batching",
        mission_id="mission_blend",
    )

    sources = engine._retrieve_sources(query)
    source_statuses = {s.semantic_status for s in sources}

    assert SEMANTIC_STATUS_VECTOR_FINDING in source_statuses
    assert SEMANTIC_STATUS_CVE_KNOWLEDGE in source_statuses
    assert SEMANTIC_STATUS_HISTORICAL_MEMORY in source_statuses

    prompt = engine.resolve(query)
    assert "### CONFIRMED FINDINGS" in prompt
    assert "### RELEVANT CVE & VULNERABILITY KNOWLEDGE" in prompt
    assert "### RECALLED MEMORIES & HISTORICAL PATTERNS" in prompt
    assert "GraphQL" in prompt


def test_research_context_engine_global_memory_recalled_when_project_id_specified(integrated_setup):
    engine, mem_mgr, _, _, _ = integrated_setup

    mem_mgr.record_attack_pattern(
        content="Global AWS IMDSv2 token extraction via PUT request with header X-aws-ec2-metadata-token-ttl-seconds",
        mission_id=None,
        title="Global AWS IMDSv2 Rule",
    )

    # Query with specific project_id and mission_id
    query = ContextQuery(
        conversation_id="conv_proj_test",
        query="AWS IMDSv2 token extraction metadata",
        project_id="project_cloud_alpha",
        mission_id="mission_cloud_1",
    )

    sources = engine._retrieve_sources(query)
    mem_sources = [s for s in sources if s.semantic_status == SEMANTIC_STATUS_HISTORICAL_MEMORY]
    assert len(mem_sources) >= 1
    assert any("IMDSv2" in s.content for s in mem_sources)
    assert mem_sources[0].metadata.get("memory_type") == "attack_pattern"

    prompt = engine.resolve(query)
    assert "### RECALLED MEMORIES & HISTORICAL PATTERNS" in prompt
    assert "(attack_pattern)" in prompt


def test_research_context_engine_project_isolation(integrated_setup):
    engine, mem_mgr, _, _, _ = integrated_setup

    mem_mgr.record_note(
        content="Secret project token for Alpha: SEC_ALPHA_TOKEN_99",
        mission_id="m1",
        metadata={"project_id": "proj_alpha"},
    )
    mem_mgr.record_note(
        content="Secret project token for Beta: SEC_BETA_TOKEN_77",
        mission_id="m1",
        metadata={"project_id": "proj_beta"},
    )

    # Query scoped to proj_alpha
    q_alpha = ContextQuery(
        conversation_id="conv_p_alpha",
        query="Secret project token",
        project_id="proj_alpha",
        mission_id="m1",
    )
    prompt_alpha = engine.resolve(q_alpha)
    assert "SEC_ALPHA_TOKEN_99" in prompt_alpha
    assert "SEC_BETA_TOKEN_77" not in prompt_alpha

    # Query scoped to proj_beta
    q_beta = ContextQuery(
        conversation_id="conv_p_beta",
        query="Secret project token",
        project_id="proj_beta",
        mission_id="m1",
    )
    prompt_beta = engine.resolve(q_beta)
    assert "SEC_BETA_TOKEN_77" in prompt_beta
    assert "SEC_ALPHA_TOKEN_99" not in prompt_beta


def test_research_context_engine_shared_id_collision_resilience(integrated_setup):
    engine, mem_mgr, finding_engine, _, _ = integrated_setup

    shared_id = "colliding_id_100"

    # Index a finding with shared_id
    finding = Finding(
        id=shared_id,
        title="Collision Finding Authentication Bypass",
        category="auth",
        severity="medium",
        endpoint="/auth",
        description="Collision finding authentication bypass in login",
        status="CONFIRMED",
    )
    finding_engine.indexer.index_finding(finding, mission_id="m_coll")

    # Index a memory with the exact same shared_id
    mem = MemoryEntry(
        id=shared_id,
        content="Collision memory authentication bypass strategy for login",
        memory_type=MemoryType.STRATEGIC_DECISION,
        mission_id="m_coll",
        title="Collision Memory Title",
    )
    mem_mgr.store.add(mem)

    query = ContextQuery(
        conversation_id="conv_coll",
        query="Collision authentication bypass login",
        mission_id="m_coll",
    )

    sources = engine._retrieve_sources(query)
    source_types = [s.source_type for s in sources]

    # Both sources must exist without one overwriting the other
    assert "vector_finding" in source_types
    assert "historical_memory" in source_types

    prompt = engine.resolve(query)
    assert "Collision Finding Authentication Bypass" in prompt
    assert "Collision memory authentication bypass" in prompt


def test_research_context_engine_excludes_archived_and_superseded_memories(integrated_setup):
    engine, mem_mgr, _, _, _ = integrated_setup

    # 1. Add active memory
    mem_mgr.record_strategic_decision(
        content="Active strategy: Focus on NoSQL injection in search API",
        mission_id="m_active_test",
        title="Active Strategy NoSQL",
    )

    # 2. Add superseded memory
    old_entry = mem_mgr.record_strategic_decision(
        content="Superseded strategy: Focus on SQL injection in search API",
        mission_id="m_active_test",
        title="Superseded Strategy SQLi",
    )
    mem_mgr.supersede_with_new(
        old_entry_id=old_entry.id,
        new_content="Replacement active strategy: Test GraphSQL injection in search API",
        mission_id="m_active_test",
        title="Replacement Strategy GraphSQL",
    )

    # 3. Add archived memory
    arch_entry = mem_mgr.record_note(
        content="Archived note: Outdated credentials for search API",
        mission_id="m_active_test",
        title="Archived Credentials Note",
    )
    mem_mgr.archive_entry(arch_entry.id)

    query = ContextQuery(
        conversation_id="conv_lifecycle_test",
        query="search API strategy injection credentials",
        mission_id="m_active_test",
    )

    sources = engine._retrieve_sources(query)
    mem_sources = [s for s in sources if s.semantic_status == SEMANTIC_STATUS_HISTORICAL_MEMORY]
    mem_contents = [s.content for s in mem_sources]

    # Active and replacement memories must be present
    assert any("NoSQL" in c for c in mem_contents)
    assert any("GraphSQL" in c for c in mem_contents)

    # Archived and superseded memories must NOT be present
    assert not any("Superseded strategy" in c for c in mem_contents)
    assert not any("Archived note" in c for c in mem_contents)

    prompt = engine.resolve(query)
    assert "NoSQL" in prompt
    assert "GraphSQL" in prompt
    assert "Superseded strategy" not in prompt
    assert "Archived note" not in prompt
