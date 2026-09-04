"""Unit tests for ARGUS conversational memory system."""

import os
import tempfile
import uuid
import pytest

from argus.memory.manager import MemoryManager, get_memory_manager
from argus.memory.models import (
    MemoryEntry,
    MemoryQuery,
    MemorySearchResult,
    MemoryStatus,
    MemoryType,
)
from argus.memory.store import MemoryStore
from argus.vector.models import VectorDocument
from argus.vector.store import VectorStore


# ==============================================================================
# Model Unit Tests
# ==============================================================================

def test_memory_entry_initialization_defaults():
    entry = MemoryEntry(content="Found endpoint vulnerable to SQL injection")
    assert entry.id is not None
    assert len(entry.id) > 0
    assert entry.content == "Found endpoint vulnerable to SQL injection"
    assert entry.memory_type == MemoryType.NOTE
    assert entry.status == MemoryStatus.ACTIVE
    assert entry.confidence == 1.0
    assert entry.mission_id is None
    assert entry.tags == []
    assert isinstance(entry.metadata, dict)
    assert entry.created_at is not None
    assert entry.updated_at is not None
    assert "Found endpoint" in entry.title


def test_memory_entry_custom_fields():
    custom_id = "mem_custom_123"
    entry = MemoryEntry(
        id=custom_id,
        content="Target uses Cloudflare WAF bypass header",
        memory_type=MemoryType.ATTACK_PATTERN,
        mission_id="mission_alpha",
        tags=["waf", "bypass", "cloudflare"],
        confidence=0.85,
        status=MemoryStatus.ARCHIVED,
        title="Cloudflare Bypass Rule",
        metadata={"priority": "high", "cve": "CVE-2023-1234"},
    )
    assert entry.id == custom_id
    assert entry.memory_type == MemoryType.ATTACK_PATTERN
    assert entry.mission_id == "mission_alpha"
    assert entry.tags == ["waf", "bypass", "cloudflare"]
    assert entry.confidence == 0.85
    assert entry.status == MemoryStatus.ARCHIVED
    assert entry.title == "Cloudflare Bypass Rule"
    assert entry.metadata["priority"] == "high"
    assert entry.metadata["mission_id"] == "mission_alpha"


def test_memory_type_enum_and_string_conversion():
    types = [
        ("attack_pattern", MemoryType.ATTACK_PATTERN),
        ("user_correction", MemoryType.USER_CORRECTION),
        ("strategic_decision", MemoryType.STRATEGIC_DECISION),
        ("session_context", MemoryType.SESSION_CONTEXT),
        ("note", MemoryType.NOTE),
    ]
    for str_val, enum_val in types:
        assert MemoryType.from_str(str_val) == enum_val
        assert MemoryType.from_str(str_val.upper()) == enum_val
        assert MemoryType.from_str(str_val.replace("_", "-")) == enum_val

    with pytest.raises(ValueError):
        MemoryType.from_str("nonexistent_memory_type")


def test_memory_status_enum_and_string_conversion():
    statuses = [
        ("active", MemoryStatus.ACTIVE),
        ("archived", MemoryStatus.ARCHIVED),
        ("superseded", MemoryStatus.SUPERSEDED),
    ]
    for str_val, enum_val in statuses:
        assert MemoryStatus.from_str(str_val) == enum_val
        assert MemoryStatus.from_str(str_val.upper()) == enum_val

    with pytest.raises(ValueError):
        MemoryStatus.from_str("deleted")


def test_memory_entry_title_autogen():
    entry_long = MemoryEntry(
        content="First line of analysis\nSecond line detailing payload",
        memory_type=MemoryType.STRATEGIC_DECISION,
    )
    assert "First line of analysis" in entry_long.title

    entry_empty = MemoryEntry(content="", id="test_id_123")
    assert "test_id_" in entry_empty.title


def test_memory_entry_to_dict_and_from_dict():
    entry = MemoryEntry(
        content="Avoid scanning admin port 8443 directly",
        memory_type=MemoryType.STRATEGIC_DECISION,
        mission_id="mission_beta",
        tags=["port_policy", "scope"],
        confidence=0.9,
        metadata={"reason": "Customer SLA"},
    )
    d = entry.to_dict()
    assert d["content"] == entry.content
    assert d["memory_type"] == "strategic_decision"
    assert d["mission_id"] == "mission_beta"
    assert d["tags"] == ["port_policy", "scope"]
    assert d["confidence"] == 0.9
    assert d["status"] == "active"

    reconstituted = MemoryEntry.from_dict(d)
    assert reconstituted.id == entry.id
    assert reconstituted.content == entry.content
    assert reconstituted.memory_type == MemoryType.STRATEGIC_DECISION
    assert reconstituted.mission_id == entry.mission_id
    assert reconstituted.tags == entry.tags
    assert reconstituted.confidence == entry.confidence


def test_memory_entry_to_vector_document_and_from_vector_document():
    entry = MemoryEntry(
        id="mem_vec_test",
        content="Reflected XSS on parameter redirect_uri",
        memory_type=MemoryType.ATTACK_PATTERN,
        mission_id="mission_gamma",
        tags=["xss", "oauth"],
        confidence=0.95,
        metadata={"endpoint": "/oauth/authorize"},
    )
    doc = entry.to_vector_document()
    assert doc.id == "mem_vec_test"
    assert doc.content == entry.content
    assert doc.source_type == "memory"
    assert doc.mission_id == "mission_gamma"
    assert doc.category == "attack_pattern"
    assert doc.metadata["tags"] == ["xss", "oauth"]
    assert doc.metadata["confidence"] == 0.95
    assert doc.metadata["status"] == "active"

    rebuilt = MemoryEntry.from_vector_document(doc)
    assert rebuilt.id == entry.id
    assert rebuilt.content == entry.content
    assert rebuilt.memory_type == MemoryType.ATTACK_PATTERN
    assert rebuilt.mission_id == "mission_gamma"
    assert rebuilt.tags == ["xss", "oauth"]
    assert rebuilt.confidence == 0.95
    assert rebuilt.metadata.get("endpoint") == "/oauth/authorize"


def test_memory_query_initialization():
    mq = MemoryQuery(
        query="SQL injection bypass",
        top_k=5,
        min_score=0.4,
        mission_id="mission_1",
        project_id="proj_1",
        memory_type=MemoryType.ATTACK_PATTERN,
        status=MemoryStatus.ACTIVE,
        tags=["sqli"],
        filters={"waf": "modsecurity"},
    )
    assert mq.query == "SQL injection bypass"
    assert mq.top_k == 5
    assert mq.min_score == 0.4
    assert mq.mission_id == "mission_1"
    assert mq.project_id == "proj_1"
    assert mq.memory_type == MemoryType.ATTACK_PATTERN
    assert mq.status == MemoryStatus.ACTIVE
    assert mq.tags == ["sqli"]
    assert mq.filters["waf"] == "modsecurity"


def test_memory_search_result_properties_and_delegation():
    entry = MemoryEntry(
        id="mem_res_1",
        content="User clarified that staging host is in scope",
        memory_type=MemoryType.USER_CORRECTION,
        mission_id="mission_delta",
        tags=["scope", "staging"],
        confidence=1.0,
        metadata={"project_id": "proj_scope"},
    )
    assert entry.project_id == "proj_scope"

    res = MemorySearchResult(entry=entry, score=0.88, distance=0.12)
    assert res.id == entry.id
    assert res.content == entry.content
    assert res.title == entry.title
    assert res.memory_type == MemoryType.USER_CORRECTION
    assert res.mission_id == "mission_delta"
    assert res.project_id == "proj_scope"
    assert res.status == MemoryStatus.ACTIVE
    assert res.tags == ["scope", "staging"]
    assert res.confidence == 1.0
    assert res.score == 0.88
    assert res.distance == 0.12

    d = res.to_dict()
    assert d["score"] == 0.88
    assert d["id"] == "mem_res_1"
    
    reconstituted = MemorySearchResult.from_dict(d)
    assert reconstituted.id == entry.id
    assert reconstituted.project_id == "proj_scope"
    assert reconstituted.score == 0.88


def test_memory_confidence_clamping():
    e1 = MemoryEntry(content="low confidence", confidence=-0.5)
    assert e1.confidence == 0.0

    e2 = MemoryEntry(content="high confidence", confidence=1.5)
    assert e2.confidence == 1.0


# ==============================================================================
# Store CRUD & Persistence Tests
# ==============================================================================

@pytest.fixture
def memory_store():
    vstore = VectorStore(db_path=":memory:")
    return MemoryStore(vector_store=vstore)


def test_memory_store_add_and_get(memory_store):
    entry = MemoryEntry(
        id="mem_crud_1",
        content="Target returns HTTP 429 when concurrency exceeds 5",
        memory_type=MemoryType.STRATEGIC_DECISION,
        mission_id="mission_test_1",
    )
    added_id = memory_store.add(entry)
    assert added_id == "mem_crud_1"

    retrieved = memory_store.get("mem_crud_1")
    assert retrieved is not None
    assert retrieved.id == "mem_crud_1"
    assert retrieved.content == entry.content
    assert retrieved.memory_type == MemoryType.STRATEGIC_DECISION
    assert retrieved.mission_id == "mission_test_1"


def test_memory_store_get_nonexistent(memory_store):
    assert memory_store.get("nonexistent_id") is None
    assert memory_store.get("") is None


def test_memory_store_get_ignores_non_memory_source_type(memory_store):
    # Insert a raw document with source_type='finding'
    non_mem_doc = VectorDocument(
        id="finding_123",
        content="XSS in query parameter",
        source_type="finding",
    )
    memory_store.vector_store.add_document(non_mem_doc)

    # MemoryStore.get should return None for non-memory source types
    assert memory_store.get("finding_123") is None


def test_memory_store_add_batch(memory_store):
    entries = [
        MemoryEntry(id=f"batch_{i}", content=f"Batch memory item {i}", memory_type=MemoryType.NOTE)
        for i in range(5)
    ]
    ids = memory_store.add_batch(entries)
    assert len(ids) == 5
    for i in range(5):
        got = memory_store.get(f"batch_{i}")
        assert got is not None
        assert got.content == f"Batch memory item {i}"


def test_memory_store_update_content(memory_store):
    entry = MemoryEntry(
        id="mem_update_1",
        content="Initial observation about API auth",
        memory_type=MemoryType.SESSION_CONTEXT,
    )
    memory_store.add(entry)

    updated = memory_store.update("mem_update_1", content="Updated observation: Bearer token is JWT")
    assert updated is not None
    assert updated.content == "Updated observation: Bearer token is JWT"

    fetched = memory_store.get("mem_update_1")
    assert fetched.content == "Updated observation: Bearer token is JWT"


def test_memory_store_update_metadata_and_tags(memory_store):
    entry = MemoryEntry(
        id="mem_update_meta",
        content="Rate limiting observation",
        tags=["rate_limit"],
        metadata={"limit": 100},
    )
    memory_store.add(entry)

    updated = memory_store.update(
        "mem_update_meta",
        tags=["rate_limit", "strict"],
        confidence=0.75,
        metadata={"limit": 50, "window": "1m"},
    )
    assert updated.tags == ["rate_limit", "strict"]
    assert updated.confidence == 0.75
    assert updated.metadata["limit"] == 50
    assert updated.metadata["window"] == "1m"


def test_memory_store_archive(memory_store):
    entry = MemoryEntry(
        id="mem_archive_1",
        content="Temporary credential found in test environment",
        status=MemoryStatus.ACTIVE,
    )
    memory_store.add(entry)

    success = memory_store.archive("mem_archive_1")
    assert success is True

    fetched = memory_store.get("mem_archive_1")
    assert fetched.status == MemoryStatus.ARCHIVED


def test_memory_store_supersede(memory_store):
    old_entry = MemoryEntry(
        id="mem_old_1",
        content="Host 10.0.0.5 is offline",
        status=MemoryStatus.ACTIVE,
    )
    memory_store.add(old_entry)

    success = memory_store.supersede("mem_old_1", superseded_by_id="mem_new_1")
    assert success is True

    fetched = memory_store.get("mem_old_1")
    assert fetched.status == MemoryStatus.SUPERSEDED
    assert fetched.superseded_by == "mem_new_1"


def test_memory_store_delete(memory_store):
    entry = MemoryEntry(id="mem_del_1", content="To be deleted")
    memory_store.add(entry)
    assert memory_store.get("mem_del_1") is not None

    deleted = memory_store.delete("mem_del_1")
    assert deleted is True
    assert memory_store.get("mem_del_1") is None

    # Deleting again returns False
    assert memory_store.delete("mem_del_1") is False


def test_memory_store_disk_persistence():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_memory_persist.db")

        # 1. Instantiate and store entries
        store1 = MemoryStore(db_path=db_path)
        entry1 = MemoryEntry(
            id="persist_1",
            content="Critical finding: SQL injection via XML parser",
            memory_type=MemoryType.ATTACK_PATTERN,
            mission_id="mission_persist",
        )
        store1.add(entry1)

        # 2. Re-instantiate MemoryStore on the same database
        store2 = MemoryStore(db_path=db_path)
        retrieved = store2.get("persist_1")
        assert retrieved is not None
        assert retrieved.id == "persist_1"
        assert retrieved.content == entry1.content
        assert retrieved.memory_type == MemoryType.ATTACK_PATTERN
        assert retrieved.mission_id == "mission_persist"


# ==============================================================================
# Search & Filtering Tests
# ==============================================================================

def test_memory_store_semantic_search_basic(memory_store):
    entries = [
        MemoryEntry(
            id="mem_sqli",
            content="Union-based SQL injection discovered in /api/products search parameter",
            memory_type=MemoryType.ATTACK_PATTERN,
        ),
        MemoryEntry(
            id="mem_xss",
            content="Stored cross-site scripting payload executes in comment field",
            memory_type=MemoryType.ATTACK_PATTERN,
        ),
        MemoryEntry(
            id="mem_creds",
            content="Default admin credentials admin:admin accepted on management console",
            memory_type=MemoryType.NOTE,
        ),
    ]
    memory_store.add_batch(entries)

    results = memory_store.search("SQL injection database exploit", top_k=2)
    assert len(results) > 0
    top_hit = results[0]
    assert top_hit.id == "mem_sqli"
    assert 0.0 <= top_hit.score <= 1.0


def test_memory_store_search_filter_by_memory_type(memory_store):
    memory_store.add(MemoryEntry(
        id="mem_type_attack",
        content="SQL injection union select payload",
        memory_type=MemoryType.ATTACK_PATTERN,
    ))
    memory_store.add(MemoryEntry(
        id="mem_type_note",
        content="SQL injection test performed by analyst",
        memory_type=MemoryType.NOTE,
    ))

    attack_results = memory_store.search("SQL injection", memory_type=MemoryType.ATTACK_PATTERN)
    result_ids = [r.id for r in attack_results]
    assert "mem_type_attack" in result_ids
    assert "mem_type_note" not in result_ids


def test_memory_store_search_filter_by_mission_id(memory_store):
    memory_store.add(MemoryEntry(
        id="mem_m1",
        content="Bypass authentication via Bearer token manipulation",
        mission_id="mission_1",
    ))
    memory_store.add(MemoryEntry(
        id="mem_m2",
        content="Bypass authentication via JWT none algorithm",
        mission_id="mission_2",
    ))

    res_m1 = memory_store.search("authentication bypass", mission_id="mission_1")
    res_m1_ids = [r.id for r in res_m1]
    assert "mem_m1" in res_m1_ids
    assert "mem_m2" not in res_m1_ids


def test_memory_store_search_filter_by_status(memory_store):
    memory_store.add(MemoryEntry(
        id="mem_active",
        content="Active directory traversal vulnerability in download endpoint",
        status=MemoryStatus.ACTIVE,
    ))
    memory_store.add(MemoryEntry(
        id="mem_archived",
        content="Patched directory traversal vulnerability in download endpoint",
        status=MemoryStatus.ARCHIVED,
    ))

    active_results = memory_store.search("directory traversal", status=MemoryStatus.ACTIVE)
    active_ids = [r.id for r in active_results]
    assert "mem_active" in active_ids
    assert "mem_archived" not in active_ids


def test_memory_store_search_min_score(memory_store):
    memory_store.add(MemoryEntry(
        id="mem_relevant",
        content="Remote code execution via command injection in system backup function",
    ))
    # Search with very high min_score
    results = memory_store.search("completely unrelated gardening tips", min_score=0.99)
    assert len(results) == 0


def test_memory_store_search_score_bounded(memory_store):
    memory_store.add(MemoryEntry(id="mem_bound_test", content="SSRF AWS metadata retrieval"))
    results = memory_store.search("SSRF 169.254.169.254")
    for r in results:
        assert 0.0 <= r.score <= 1.0


def test_memory_store_list_all_and_filtered(memory_store):
    memory_store.add(MemoryEntry(id="l1", content="Note 1", memory_type=MemoryType.NOTE, mission_id="m1"))
    memory_store.add(MemoryEntry(id="l2", content="Note 2", memory_type=MemoryType.NOTE, mission_id="m2"))
    memory_store.add(MemoryEntry(id="l3", content="Decision 1", memory_type=MemoryType.STRATEGIC_DECISION, mission_id="m1"))

    all_entries = memory_store.list()
    assert len(all_entries) == 3

    m1_entries = memory_store.list(mission_id="m1")
    assert len(m1_entries) == 2

    note_entries = memory_store.list(memory_type=MemoryType.NOTE)
    assert len(note_entries) == 2


def test_memory_store_clear_mission_scoped(memory_store):
    memory_store.add(MemoryEntry(id="clr_m1_1", content="M1 mem 1", mission_id="mission_target"))
    memory_store.add(MemoryEntry(id="clr_m1_2", content="M1 mem 2", mission_id="mission_target"))
    memory_store.add(MemoryEntry(id="clr_m2_1", content="M2 mem 1", mission_id="mission_other"))

    deleted_count = memory_store.clear(mission_id="mission_target")
    assert deleted_count == 2
    assert memory_store.get("clr_m1_1") is None
    assert memory_store.get("clr_m1_2") is None
    assert memory_store.get("clr_m2_1") is not None


def test_memory_store_clear_all_memories(memory_store):
    # Add memory and non-memory
    memory_store.add(MemoryEntry(id="mem_to_clear", content="Will be cleared"))
    memory_store.vector_store.add_document(VectorDocument(
        id="cve_doc",
        content="CVE document",
        source_type="cve",
    ))

    deleted = memory_store.clear()
    assert deleted >= 1
    assert memory_store.get("mem_to_clear") is None
    # Verify non-memory document remains in underlying vector store
    assert memory_store.vector_store.get("cve_doc") is not None


def test_memory_store_count_with_filters(memory_store):
    memory_store.add(MemoryEntry(id="cnt_1", content="C1", memory_type=MemoryType.ATTACK_PATTERN, mission_id="m_cnt"))
    memory_store.add(MemoryEntry(id="cnt_2", content="C2", memory_type=MemoryType.NOTE, mission_id="m_cnt"))
    memory_store.add(MemoryEntry(id="cnt_3", content="C3", memory_type=MemoryType.NOTE, mission_id="m_other"))

    assert memory_store.count() == 3
    assert memory_store.count({"mission_id": "m_cnt"}) == 2
    assert memory_store.count({"category": "attack_pattern"}) == 1


# ==============================================================================
# MemoryManager Facade & Knowledge Transfer Tests
# ==============================================================================

@pytest.fixture
def memory_manager():
    vstore = VectorStore(db_path=":memory:")
    return MemoryManager(vector_store=vstore)


def test_memory_manager_singleton_factory():
    mgr1 = get_memory_manager(force_new=True)
    mgr2 = get_memory_manager()
    assert mgr1 is mgr2

    mgr3 = get_memory_manager(force_new=True)
    assert mgr3 is not mgr1


def test_memory_manager_record_helpers(memory_manager):
    ap = memory_manager.record_attack_pattern("Double-encoded path traversal", mission_id="m1")
    assert ap.memory_type == MemoryType.ATTACK_PATTERN
    assert ap.mission_id == "m1"

    uc = memory_manager.record_user_correction("Host api.internal is actually out of scope")
    assert uc.memory_type == MemoryType.USER_CORRECTION

    sd = memory_manager.record_strategic_decision("Prioritize testing payment gateway over static assets")
    assert sd.memory_type == MemoryType.STRATEGIC_DECISION

    sc = memory_manager.record_session_context("Current hypothesis: session token leaked in URL")
    assert sc.memory_type == MemoryType.SESSION_CONTEXT

    note = memory_manager.record_note("Server returns nginx/1.18.0 header")
    assert note.memory_type == MemoryType.NOTE


def test_memory_manager_recall_with_string_and_query_obj(memory_manager):
    memory_manager.record_attack_pattern(
        "SQL injection via XML entity expansion in SOAP endpoint",
        tags=["sqli", "soap"],
    )

    # String query
    res1 = memory_manager.recall("SQL injection SOAP endpoint", top_k=1)
    assert len(res1) == 1
    assert "SOAP" in res1[0].content

    # MemoryQuery object
    mq = MemoryQuery(query="SQL injection SOAP", top_k=2, min_score=0.1)
    res2 = memory_manager.recall(mq)
    assert len(res2) == 1
    assert "SOAP" in res2[0].content


def test_memory_manager_supersede_with_new(memory_manager):
    old_entry = memory_manager.record_strategic_decision(
        "Scan port 80 and 443 with fast timing template",
        mission_id="mission_strat",
    )
    new_entry = memory_manager.supersede_with_new(
        old_entry_id=old_entry.id,
        new_content="Scan port 80, 443, and 8443 with stealth timing template",
    )
    assert new_entry is not None
    assert new_entry.id != old_entry.id

    # Verify old entry marked superseded
    old_fetched = memory_manager.get_entry(old_entry.id)
    assert old_fetched.status == MemoryStatus.SUPERSEDED
    assert old_fetched.superseded_by == new_entry.id


def test_memory_manager_cross_mission_knowledge_transfer(memory_manager):
    entry = memory_manager.record_attack_pattern(
        "OAuth redirect_uri parameter pollution bypasses regex filter",
        mission_id="mission_target_a",
    )
    assert entry.mission_id == "mission_target_a"

    # Promote to global
    promoted = memory_manager.promote_to_global(entry.id)
    assert promoted is not None
    assert promoted.mission_id is None

    # Transfer to mission_target_b
    cloned = memory_manager.transfer_to_mission(entry.id, target_mission_id="mission_target_b")
    assert cloned is not None
    assert cloned.mission_id == "mission_target_b"
    assert cloned.content == entry.content
    assert cloned.metadata.get("transferred_from_entry") == entry.id


def test_memory_manager_export_and_import_attack_patterns(memory_manager):
    memory_manager.record_attack_pattern("JWT none algorithm exploitation", mission_id="scan_1")
    memory_manager.record_attack_pattern("JWT secret bruteforce attack", mission_id="scan_1")
    memory_manager.record_note("General scan note", mission_id="scan_1")

    exported = memory_manager.export_attack_patterns(mission_id="scan_1")
    assert len(exported) == 2
    for exp in exported:
        assert exp["memory_type"] == "attack_pattern"

    # Import into scan_2
    imported = memory_manager.import_attack_patterns(exported, target_mission_id="scan_2")
    assert len(imported) == 2
    for imp in imported:
        assert imp.mission_id == "scan_2"
        assert imp.memory_type == MemoryType.ATTACK_PATTERN
