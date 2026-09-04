"""Adversarial and robustness tests for ARGUS conversational memory system."""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import uuid
import pytest

from argus.memory.manager import MemoryManager
from argus.memory.models import (
    MemoryEntry,
    MemoryQuery,
    MemorySearchResult,
    MemoryStatus,
    MemoryType,
)
from argus.memory.store import MemoryStore
from argus.vector.store import VectorStore


@pytest.fixture
def memory_store():
    vstore = VectorStore(db_path=":memory:")
    return MemoryStore(vector_store=vstore)


@pytest.fixture
def memory_manager():
    vstore = VectorStore(db_path=":memory:")
    return MemoryManager(vector_store=vstore)


def test_adversarial_empty_content_creation_and_search(memory_store):
    # Empty content string should not crash
    entry = MemoryEntry(id="empty_content", content="")
    memory_store.add(entry)

    fetched = memory_store.get("empty_content")
    assert fetched is not None
    assert fetched.content == ""

    # Searching with empty or whitespace-only query returns empty list
    assert memory_store.search("") == []
    assert memory_store.search("   \t\n  ") == []


def test_adversarial_none_query_search(memory_store):
    # Calling search with None query or empty vector returns empty list without error
    assert memory_store.search(None) == []
    mq_none = MemoryQuery(query=None)
    assert memory_store.search(mq_none) == []
    assert memory_store.search([]) == []
    mq_empty = MemoryQuery(query="")
    assert memory_store.search(mq_empty) == []


def test_adversarial_extremely_long_content(memory_store):
    # 50,000 character long payload / vulnerability trace
    huge_content = "VULN_PAYLOAD_TEST_" + ("A" * 50000)
    entry = MemoryEntry(id="huge_1", content=huge_content, memory_type=MemoryType.ATTACK_PATTERN)
    memory_store.add(entry)

    retrieved = memory_store.get("huge_1")
    assert retrieved is not None
    assert len(retrieved.content) == len(huge_content)
    assert retrieved.content == huge_content

    # Recall should still succeed
    results = memory_store.search("VULN_PAYLOAD_TEST", top_k=1)
    assert len(results) == 1
    assert results[0].id == "huge_1"


def test_adversarial_special_characters_sql_xss_null_bytes(memory_store):
    adversarial_contents = [
        "'; DROP TABLE documents; --",
        "' OR '1'='1' UNION SELECT null, null, null, null --",
        "<script>alert('XSS')</script>",
        "<?php echo file_get_contents('/etc/passwd'); ?>",
        "../../../../../../etc/shadow\x00.png",
        "🔥 Unicode exploit 💉 👾 \u202e reversed text \u0000",
        '{"json_injection": "value", "nested": {"key": [1, 2, 3]}}',
    ]

    for i, payload in enumerate(adversarial_contents):
        eid = f"adv_payload_{i}"
        entry = MemoryEntry(
            id=eid,
            content=payload,
            metadata={"payload_idx": i, "raw": payload},
            tags=["exploit", "fuzz"],
        )
        memory_store.add(entry)

        retrieved = memory_store.get(eid)
        assert retrieved is not None
        assert retrieved.content == payload
        assert retrieved.metadata["raw"] == payload


def test_adversarial_score_bound_invariants_never_exceed_unit_interval(memory_store):
    # Add diverse memories
    entries = [
        MemoryEntry(id="s1", content="Remote code execution via YAML deserialization"),
        MemoryEntry(id="s2", content="Path traversal in document download controller"),
        MemoryEntry(id="s3", content="SQL injection union based in search parameter"),
    ]
    memory_store.add_batch(entries)

    queries = [
        "Remote code execution via YAML deserialization",  # exact match
        "YAML deserialization",
        "SQL injection",
        "completely unrelated astronomy galaxies stars",
        "a",
        "../../../",
        "'; DROP TABLE documents; --",
    ]

    for q in queries:
        results = memory_store.search(q, top_k=5)
        for r in results:
            assert isinstance(r.score, float)
            assert 0.0 <= r.score <= 1.0, f"Score {r.score} out of bounds for query: {q}"
            assert r.distance >= 0.0


def test_adversarial_confidence_invalid_types_and_extremes():
    # Negative confidence
    e1 = MemoryEntry(content="Negative conf", confidence=-100.5)
    assert e1.confidence == 0.0

    # Overly high confidence
    e2 = MemoryEntry(content="Super conf", confidence=999.9)
    assert e2.confidence == 1.0

    # Non-numeric string
    e3 = MemoryEntry(content="Invalid str conf", confidence="invalid")  # type: ignore
    assert e3.confidence == 1.0

    # None confidence
    e4 = MemoryEntry(content="None conf", confidence=None)  # type: ignore
    assert e4.confidence == 1.0


def test_adversarial_strict_state_isolation_between_missions(memory_store):
    # Mission Alpha and Mission Beta share identical content
    memory_store.add(MemoryEntry(
        id="mem_iso_alpha",
        content="Sensitive internal credential api_key=secret_alpha",
        mission_id="mission_alpha",
    ))
    memory_store.add(MemoryEntry(
        id="mem_iso_beta",
        content="Sensitive internal credential api_key=secret_beta",
        mission_id="mission_beta",
    ))

    # Search isolated to mission_alpha
    results_alpha = memory_store.search("sensitive internal credential", mission_id="mission_alpha")
    ids_alpha = [r.id for r in results_alpha]
    assert "mem_iso_alpha" in ids_alpha
    assert "mem_iso_beta" not in ids_alpha

    # Search isolated to mission_beta
    results_beta = memory_store.search("sensitive internal credential", mission_id="mission_beta")
    ids_beta = [r.id for r in results_beta]
    assert "mem_iso_beta" in ids_beta
    assert "mem_iso_alpha" not in ids_beta

    # Search isolated to mission_gamma (empty)
    results_gamma = memory_store.search("sensitive internal credential", mission_id="mission_gamma")
    assert len(results_gamma) == 0


def test_adversarial_cross_mission_leak_prevention_on_clear(memory_store):
    memory_store.add(MemoryEntry(id="leak_1", content="Mission 1 data", mission_id="m1"))
    memory_store.add(MemoryEntry(id="leak_2", content="Mission 2 data", mission_id="m2"))

    memory_store.clear(mission_id="m1")
    assert memory_store.get("leak_1") is None
    assert memory_store.get("leak_2") is not None
    assert memory_store.get("leak_2").content == "Mission 2 data"


def test_adversarial_concurrent_writes(memory_store):
    num_threads = 8
    items_per_thread = 15

    def worker(worker_id: int):
        for i in range(items_per_thread):
            eid = f"conc_{worker_id}_{i}"
            entry = MemoryEntry(
                id=eid,
                content=f"Concurrent memory entry from worker {worker_id} item {i}",
                mission_id=f"mission_{worker_id}",
            )
            memory_store.add(entry)

    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(worker, w) for w in range(num_threads)]
        for f in futures:
            f.result()

    total_expected = num_threads * items_per_thread
    assert memory_store.count() == total_expected


def test_adversarial_concurrent_read_write(memory_store):
    # Pre-seed store
    memory_store.add(MemoryEntry(id="seed_1", content="SQL injection test endpoint"))

    def reader():
        for _ in range(25):
            results = memory_store.search("SQL injection", top_k=5)
            assert isinstance(results, list)

    def writer(wid: int):
        for i in range(15):
            entry = MemoryEntry(
                id=f"rw_{wid}_{i}",
                content=f"Reader writer test content {wid} {i}",
            )
            memory_store.add(entry)

    with ThreadPoolExecutor(max_workers=6) as executor:
        f_writers = [executor.submit(writer, w) for w in range(3)]
        f_readers = [executor.submit(reader) for _ in range(3)]
        for f in f_writers + f_readers:
            f.result()


def test_adversarial_duplicate_ids_upsert(memory_store):
    e1 = MemoryEntry(id="dup_id", content="Original content", confidence=0.5)
    memory_store.add(e1)
    assert memory_store.get("dup_id").content == "Original content"

    # Upsert with new content
    e2 = MemoryEntry(id="dup_id", content="Overwritten content", confidence=0.9)
    memory_store.add(e2)

    fetched = memory_store.get("dup_id")
    assert fetched.content == "Overwritten content"
    assert fetched.confidence == 0.9
    assert memory_store.count() == 1


def test_adversarial_deep_nested_metadata(memory_store):
    nested_meta = {
        "level1": {
            "level2": {
                "level3": ["a", "b", {"key": "val"}],
                "boolean": True,
                "null_val": None,
                "float_val": 3.14159,
            }
        },
        "tags_meta": ["alpha", "beta"],
    }
    entry = MemoryEntry(id="deep_meta", content="Deep metadata test", metadata=nested_meta)
    memory_store.add(entry)

    fetched = memory_store.get("deep_meta")
    assert fetched.metadata["level1"]["level2"]["boolean"] is True
    assert fetched.metadata["level1"]["level2"]["level3"][2]["key"] == "val"


def test_adversarial_update_nonexistent_id(memory_store):
    res = memory_store.update("nonexistent_id", content="New content")
    assert res is None


def test_adversarial_delete_nonexistent_id(memory_store):
    res = memory_store.delete("nonexistent_id")
    assert res is False


def test_adversarial_archive_already_archived(memory_store):
    entry = MemoryEntry(id="arch_id", content="Archived entry", status=MemoryStatus.ARCHIVED)
    memory_store.add(entry)

    # Archive again
    res = memory_store.archive("arch_id")
    assert res is True
    assert memory_store.get("arch_id").status == MemoryStatus.ARCHIVED


def test_adversarial_supersede_chain(memory_store):
    memory_store.add(MemoryEntry(id="chain_A", content="Version A"))
    memory_store.add(MemoryEntry(id="chain_B", content="Version B"))
    memory_store.add(MemoryEntry(id="chain_C", content="Version C"))

    memory_store.supersede("chain_A", "chain_B")
    memory_store.supersede("chain_B", "chain_C")

    entry_a = memory_store.get("chain_A")
    entry_b = memory_store.get("chain_B")
    entry_c = memory_store.get("chain_C")

    assert entry_a.status == MemoryStatus.SUPERSEDED
    assert entry_a.superseded_by == "chain_B"
    assert entry_b.status == MemoryStatus.SUPERSEDED
    assert entry_b.superseded_by == "chain_C"
    assert entry_c.status == MemoryStatus.ACTIVE


def test_adversarial_high_volume_batch_indexing(memory_store):
    entries = [
        MemoryEntry(
            id=f"vol_{i}",
            content=f"High volume vulnerability pattern description {i} affecting host {i % 10}",
            memory_type=MemoryType.ATTACK_PATTERN,
            mission_id=f"mission_{i % 5}",
        )
        for i in range(100)
    ]
    ids = memory_store.add_batch(entries)
    assert len(ids) == 100
    assert memory_store.count() == 100

    results = memory_store.search("vulnerability pattern affecting host", top_k=10)
    assert len(results) == 10
    for r in results:
        assert 0.0 <= r.score <= 1.0


def test_adversarial_score_nan_and_inf_handling():
    entry = MemoryEntry(content="Score bounds edge case test")
    
    # NaN score should map strictly to 0.0
    r_nan = MemorySearchResult(entry=entry, score=float("nan"))
    assert r_nan.score == 0.0
    
    # Positive infinity should clamp to 1.0
    r_inf = MemorySearchResult(entry=entry, score=float("inf"))
    assert r_inf.score == 1.0
    
    # Negative infinity should clamp to 0.0
    r_neginf = MemorySearchResult(entry=entry, score=float("-inf"))
    assert r_neginf.score == 0.0


def test_adversarial_store_update_invariant_preservation(memory_store):
    entry = MemoryEntry(id="inv_update_test", content="Original invariant text", confidence=0.8)
    memory_store.add(entry)

    # Update with extreme confidence and uppercase status/type
    updated = memory_store.update(
        "inv_update_test",
        confidence=999.0,
        status="ARCHIVED",
        memory_type="STRATEGIC_DECISION",
    )
    assert updated is not None
    assert updated.confidence == 1.0
    assert updated.status == MemoryStatus.ARCHIVED
    assert updated.memory_type == MemoryType.STRATEGIC_DECISION

    # Ensure persisted entry also preserves invariants
    fetched = memory_store.get("inv_update_test")
    assert fetched.confidence == 1.0
    assert fetched.status == MemoryStatus.ARCHIVED
    assert fetched.memory_type == MemoryType.STRATEGIC_DECISION


def test_adversarial_case_insensitive_filtering(memory_store):
    memory_store.add(MemoryEntry(
        id="case_1",
        content="PostgreSQL injection in user filter parameter",
        memory_type=MemoryType.ATTACK_PATTERN,
        status=MemoryStatus.ACTIVE,
    ))

    # Test list with uppercase and hyphenated variants
    assert len(memory_store.list(memory_type="ATTACK_PATTERN")) == 1
    assert len(memory_store.list(memory_type="attack-pattern")) == 1
    assert len(memory_store.list(status="ACTIVE")) == 1

    # Test search with uppercase variants
    assert len(memory_store.search("PostgreSQL", memory_type="ATTACK_PATTERN")) == 1
    assert len(memory_store.search("PostgreSQL", status="ACTIVE")) == 1

    # Test count with uppercase variants and kwargs
    assert memory_store.count(memory_type="ATTACK_PATTERN") == 1
    assert memory_store.count(status="ACTIVE") == 1


def test_adversarial_malformed_from_dict_and_non_string_content():
    # Malformed confidence
    e1 = MemoryEntry.from_dict({"content": "test", "confidence": None})
    assert e1.confidence == 1.0
    e2 = MemoryEntry.from_dict({"content": "test", "confidence": "non_numeric"})
    assert e2.confidence == 1.0

    # Non-dict metadata or non-list tags
    e3 = MemoryEntry.from_dict({"content": "test", "metadata": "not_a_dict", "tags": None})
    assert e3.metadata == {}
    assert e3.tags == []

    # Non-string content autogen title
    e4 = MemoryEntry(content=12345)  # type: ignore
    assert isinstance(e4.content, str)
    assert e4.content == "12345"
    assert "12345" in e4.title


def test_adversarial_add_batch_invalid_types(memory_store):
    with pytest.raises(TypeError):
        memory_store.add_batch([MemoryEntry(content="valid"), "invalid_entry"])  # type: ignore


def test_adversarial_tags_kwarg_in_search_and_recall(memory_store, memory_manager):
    # Test tags kwarg does not crash VectorStore.search
    e1 = MemoryEntry(id="waf_1", content="WAF bypass payload with chunked encoding", tags=["waf", "evasion"])
    e2 = MemoryEntry(id="waf_2", content="SQL injection payload union based", tags=["sqli"])
    memory_store.add(e1)
    memory_store.add(e2)

    # Search with tags list kwarg
    res = memory_store.search("payload", tags=["waf"])
    assert len(res) == 1
    assert res[0].id == "waf_1"

    # Search with single tag string kwarg
    res_str = memory_store.search("payload", tags="sqli")
    assert len(res_str) == 1
    assert res_str[0].id == "waf_2"

    # Test manager.recall with tags
    mgr_res = memory_manager.recall("payload", tags=["waf"])
    assert isinstance(mgr_res, list)

    # Verify single string tag on MemoryEntry does not split into char list
    e_str_tag = MemoryEntry(content="Single string tag test", tags="security")
    assert e_str_tag.tags == ["security"]


def test_adversarial_arbitrary_metadata_kwargs_in_search(memory_store, memory_manager):
    # Passing unknown/custom kwargs to search or recall must not crash
    memory_store.add(MemoryEntry(
        id="meta_kw_1",
        content="Production server vulnerability report",
        metadata={"environment": "production", "region": "us-east-1"},
    ))

    # Search with custom kwargs (should be absorbed into metadata filters without VectorStore TypeError)
    res = memory_store.search("Production server", environment="production")
    assert len(res) == 1
    assert res[0].id == "meta_kw_1"

    # Mismatched custom kwarg should filter it out
    res_mismatch = memory_store.search("Production server", environment="staging")
    assert len(res_mismatch) == 0

    # Recall with custom kwarg
    res_mgr = memory_manager.recall("Production server", custom_filter="unused")
    assert isinstance(res_mgr, list)


def test_adversarial_count_with_status_list(memory_store):
    mgr = MemoryManager(store=memory_store)
    memory_store.add(MemoryEntry(id="c_act", content="Active memory", status=MemoryStatus.ACTIVE))
    memory_store.add(MemoryEntry(id="c_arch", content="Archived memory", status=MemoryStatus.ARCHIVED))
    memory_store.add(MemoryEntry(id="c_sup", content="Superseded memory", status=MemoryStatus.SUPERSEDED))

    # Count with list of 2 statuses must sum both, not return 0
    c_two = memory_store.count(status=["active", "archived"])
    assert c_two == 2

    # Count with all 3 statuses
    c_three = memory_store.count(status=["active", "archived", "superseded"])
    assert c_three == 3

    # Count with empty list
    c_empty = memory_store.count(status=[])
    assert c_empty == 0

    # MemoryManager count_entries delegation
    c_mgr = mgr.count_entries(status=["active", "superseded"])
    assert c_mgr == 2


def test_adversarial_search_with_list_filters_dict(memory_store):
    memory_store.add(MemoryEntry(id="f_act", content="SQL injection test 1", status=MemoryStatus.ACTIVE, memory_type=MemoryType.ATTACK_PATTERN))
    memory_store.add(MemoryEntry(id="f_sup", content="SQL injection test 2", status=MemoryStatus.SUPERSEDED, memory_type=MemoryType.NOTE))

    # Search with status list inside filters dict
    res_stat = memory_store.search("SQL injection", filters={"status": ["active", "superseded"]})
    assert len(res_stat) == 2

    # Search with memory_type list inside filters dict
    res_type = memory_store.search("SQL injection", filters={"memory_type": ["attack_pattern", "note"]})
    assert len(res_type) == 2

    # Search with tags inside filters dict
    e_tag = MemoryEntry(id="f_tag", content="SQL injection test 3", tags=["custom_tag"])
    memory_store.add(e_tag)
    res_tag = memory_store.search("SQL injection", filters={"tags": ["custom_tag"]})
    assert any(r.id == "f_tag" for r in res_tag)


def test_adversarial_memory_query_top_k_precedence(memory_store):
    mgr = MemoryManager(store=memory_store)
    for i in range(10):
        memory_store.add(MemoryEntry(id=f"topk_{i}", content=f"Top K test item {i} with common payload"))

    # MemoryQuery has default top_k=10; passing top_k=3 to search must return at most 3
    mq = MemoryQuery("Top K test item")
    res_search = memory_store.search(mq, top_k=3)
    assert len(res_search) == 3

    # Manager recall with top_k=2 must return at most 2
    res_recall = mgr.recall(mq, top_k=2)
    assert len(res_recall) == 2


def test_adversarial_string_and_invalid_top_k(memory_store):
    memory_store.add(MemoryEntry(id="tk_1", content="String top k test"))

    # String top_k should be safely coerced to int
    res_str = memory_store.search("top k test", top_k="5")
    assert len(res_str) == 1

    # Zero or negative top_k returns empty list
    assert memory_store.search("top k test", top_k=0) == []
    assert memory_store.search("top k test", top_k=-5) == []
    assert memory_store.search("top k test", top_k="0") == []

    # Invalid non-numeric string top_k defaults safely
    res_inv = memory_store.search("top k test", top_k="invalid")
    assert len(res_inv) == 1


def test_adversarial_string_and_invalid_min_score(memory_store):
    memory_store.add(MemoryEntry(id="ms_1", content="Min score parsing test"))

    # String min_score should be safely coerced to float without TypeError
    res = memory_store.search("Min score", min_score="0.0")
    assert len(res) == 1

    # Invalid non-numeric min_score falls back gracefully
    res_inv = memory_store.search("Min score", min_score="invalid")
    assert len(res_inv) == 1


def test_adversarial_non_serializable_metadata_set_uuid_datetime(memory_store):
    # Set, UUID, datetime in metadata must not fail json.dumps()
    sample_uuid = uuid.uuid4()
    sample_dt = datetime.now()
    entry = MemoryEntry(
        id="non_serial_meta",
        content="Complex metadata payload test",
        metadata={
            "tag_set": {"alpha", "beta"},
            "unique_id": sample_uuid,
            "recorded_time": sample_dt,
            "nested": {"inner_set": {1, 2, 3}},
        },
    )
    # Should not raise TypeError: Object of type set is not JSON serializable
    memory_store.add(entry)

    fetched = memory_store.get("non_serial_meta")
    assert fetched is not None
    assert fetched.content == entry.content
    assert isinstance(fetched.metadata["tag_set"], list)
    assert set(fetched.metadata["tag_set"]) == {"alpha", "beta"}
    assert fetched.metadata["unique_id"] == str(sample_uuid)


def test_adversarial_list_limit_zero_and_offset(memory_store):
    for i in range(5):
        memory_store.add(MemoryEntry(id=f"lim_{i}", content=f"Limit test item {i}"))

    # limit=0 must return empty list, not all entries!
    assert memory_store.list(limit=0) == []

    # limit=2 must return exactly 2
    assert len(memory_store.list(limit=2)) == 2

    # offset=2, limit=2
    res = memory_store.list(offset=2, limit=2)
    assert len(res) == 2


def test_adversarial_mission_id_synchronization(memory_store):
    # If metadata has a conflicting mission_id, entry.mission_id takes strict precedence
    entry = MemoryEntry(
        id="sync_mid",
        content="Mission ID sync test",
        mission_id="mission_correct",
        metadata={"mission_id": "mission_conflicting"},
    )
    assert entry.metadata["mission_id"] == "mission_correct"

    memory_store.add(entry)
    fetched = memory_store.get("sync_mid")
    assert fetched.mission_id == "mission_correct"
    assert fetched.metadata["mission_id"] == "mission_correct"

    # Updating with mission_id=None must remove mission_id from metadata
    updated = memory_store.update("sync_mid", mission_id=None)
    assert updated.mission_id is None
    assert "mission_id" not in updated.metadata


def test_adversarial_memory_search_result_project_id_and_from_dict():
    entry = MemoryEntry(
        id="msr_test",
        content="SearchResult project_id and from_dict test",
        metadata={"project_id": "proj_omega"},
    )
    assert entry.project_id == "proj_omega"

    res = MemorySearchResult(entry=entry, score=0.88, distance=0.12)
    # Property delegation
    assert res.project_id == "proj_omega"
    assert res.id == "msr_test"

    # Deserialization from dictionary
    d = res.to_dict()
    assert d["score"] == 0.88
    reconstituted = MemorySearchResult.from_dict(d)
    assert reconstituted.id == res.id
    assert reconstituted.score == 0.88
    assert reconstituted.project_id == "proj_omega"


def test_adversarial_title_whitespace_handling():
    # Whitespace-only title must trigger title autogeneration
    entry = MemoryEntry(content="Active reconnaissance on target.example.com", title="    ")
    assert entry.title != "    "
    assert "Active reconnaissance" in entry.title


def test_adversarial_transfer_to_mission_validation(memory_manager):
    entry = memory_manager.record("Transfer validation content", mission_id="source_m")

    # Empty or whitespace target mission ID must return None
    assert memory_manager.transfer_to_mission(entry.id, "") is None
    assert memory_manager.transfer_to_mission(entry.id, "   ") is None
    assert memory_manager.transfer_to_mission(entry.id, None) is None  # type: ignore


def test_adversarial_clear_mission_empty_and_none_protection(memory_manager):
    # Setup global memory and mission memories
    memory_manager.record("Important global security policy", mission_id=None)
    memory_manager.record("Mission Alpha critical finding", mission_id="mission_alpha")
    memory_manager.record("Mission Beta critical finding", mission_id="mission_beta")

    assert memory_manager.count_entries() == 3

    # Attempting to clear mission with None, empty string, or whitespace must NOT wipe out everything
    assert memory_manager.clear_mission(None) == 0  # type: ignore
    assert memory_manager.clear_mission("") == 0
    assert memory_manager.clear_mission("   ") == 0
    assert memory_manager.count_entries() == 3

    # Only valid mission_id clears that specific mission
    assert memory_manager.clear_mission("mission_alpha") == 1
    assert memory_manager.count_entries() == 2
    assert memory_manager.list_entries(mission_id="mission_alpha") == []


def test_adversarial_recall_global_strictly_excludes_mission_scoped_memories(memory_manager):
    # Add a global memory
    memory_manager.record("Global pattern: SSRF cloud metadata endpoint", mission_id=None)
    # Add a mission-scoped memory with sensitive target info
    memory_manager.record("Mission confidential: admin password for target host in mission_999", mission_id="mission_999")

    # Global recall must NOT return mission_999's memory
    res_global = memory_manager.recall_global("admin password target host SSRF")
    assert len(res_global) >= 1
    for r in res_global:
        assert r.mission_id is None
        assert "mission_999" not in (r.content or "")


def test_adversarial_add_batch_generator_and_iterable_support(memory_store):
    entries = [
        MemoryEntry(id=f"gen_{i}", content=f"Generator entry {i}")
        for i in range(5)
    ]
    # Pass a generator
    gen = (e for e in entries)
    added_ids = memory_store.add_batch(gen)
    assert len(added_ids) == 5
    assert memory_store.count() == 5
    for i in range(5):
        assert memory_store.get(f"gen_{i}") is not None


def test_adversarial_search_non_string_non_vector_types(memory_store, memory_manager):
    memory_store.add(MemoryEntry(content="Valid memory item"))

    # Searching with ints, booleans, dicts, objects, or empty structures returns [] safely
    assert memory_store.search(12345) == []
    assert memory_store.search(False) == []
    assert memory_store.search(True) == []
    assert memory_store.search(object()) == []
    assert memory_store.search({"not": "a query"}) == []

    # Recall with invalid query types returns [] safely
    assert memory_manager.recall(12345) == []
    assert memory_manager.recall(False) == []


def test_adversarial_search_control_flags_in_filters_and_kwargs(memory_store):
    memory_store.add(MemoryEntry(id="act_1", content="Active SQL injection finding", status=MemoryStatus.ACTIVE))
    memory_store.add(MemoryEntry(id="arch_1", content="Archived SQL injection finding", status=MemoryStatus.ARCHIVED))

    # active_only via kwargs
    res_kw = memory_store.search("SQL injection", active_only=True)
    res_kw_ids = [r.id for r in res_kw]
    assert "act_1" in res_kw_ids
    assert "arch_1" not in res_kw_ids

    # active_only via filters dict
    res_filt = memory_store.search("SQL injection", filters={"active_only": True})
    res_filt_ids = [r.id for r in res_filt]
    assert "act_1" in res_filt_ids
    assert "arch_1" not in res_filt_ids


def test_adversarial_to_dict_json_serializable_with_uuid_datetime_set():
    import json
    entry = MemoryEntry(
        id=str(uuid.uuid4()),
        content="Complex metadata serialization test",
        metadata={
            "uid": uuid.uuid4(),
            "time": datetime.now(),
            "items": {"alpha", "beta"},
            "status_enum": MemoryStatus.ACTIVE,
        },
    )
    d = entry.to_dict()
    # Must dump without TypeError: Object of type ... is not JSON serializable
    dumped = json.dumps(d)
    assert isinstance(dumped, str)
    assert "Complex metadata" in dumped


def test_adversarial_from_dict_preserves_nested_mission_id_and_project_id():
    d = {
        "content": "Nested metadata id test",
        "metadata": {
            "mission_id": "nested_m1",
            "project_id": "nested_p1",
        },
    }
    entry = MemoryEntry.from_dict(d)
    assert entry.mission_id == "nested_m1"
    assert entry.project_id == "nested_p1"
    assert entry.metadata.get("mission_id") == "nested_m1"
    assert entry.metadata.get("project_id") == "nested_p1"


def test_adversarial_from_dict_defaults_none_status_to_active():
    d = {"content": "None status test", "status": None}
    entry = MemoryEntry.from_dict(d)
    assert entry.status == MemoryStatus.ACTIVE
    assert entry.is_active is True
    assert entry.is_archived is False


def test_adversarial_project_id_setter_and_helper_properties():
    entry = MemoryEntry(content="Setter test")
    assert entry.project_id is None

    entry.project_id = "proj_42"
    assert entry.project_id == "proj_42"
    assert entry.metadata["project_id"] == "proj_42"

    entry.project_id = None
    assert entry.project_id is None
    assert "project_id" not in entry.metadata

    # Helper properties
    assert entry.is_active is True
    assert entry.is_archived is False
    assert entry.is_superseded is False

    entry.status = MemoryStatus.ARCHIVED
    assert entry.is_active is False
    assert entry.is_archived is True

    res = MemorySearchResult(entry=entry, score=0.95)
    assert res.is_archived is True
    assert res.is_active is False


def test_adversarial_store_list_project_id_and_global_only(memory_store):
    memory_store.add(MemoryEntry(id="gl_1", content="Global entry 1", mission_id=None))
    memory_store.add(MemoryEntry(id="m_1", content="Mission 1 entry", mission_id="m1", metadata={"project_id": "p_alpha"}))
    memory_store.add(MemoryEntry(id="m_2", content="Mission 2 entry", mission_id="m2", metadata={"project_id": "p_beta"}))

    # List global only
    gl_entries = memory_store.list(global_only=True)
    assert len(gl_entries) == 1
    assert gl_entries[0].id == "gl_1"

    # List by project_id
    p_entries = memory_store.list(project_id="p_alpha")
    assert len(p_entries) == 1
    assert p_entries[0].id == "m_1"


def test_adversarial_store_count_global_only(memory_store):
    memory_store.add(MemoryEntry(content="Global 1", mission_id=None))
    memory_store.add(MemoryEntry(content="Global 2", mission_id=None))
    memory_store.add(MemoryEntry(content="Mission entry", mission_id="m1"))

    assert memory_store.count() == 3
    assert memory_store.count(global_only=True) == 2


def test_adversarial_singleton_factory_thread_safety():
    from argus.memory.manager import get_memory_manager
    managers = []

    def _get():
        mgr = get_memory_manager(force_new=False)
        managers.append(mgr)

    with ThreadPoolExecutor(max_workers=8) as ex:
        futures = [ex.submit(_get) for _ in range(20)]
        for f in futures:
            f.result()

    assert len(managers) == 20
    first = managers[0]
    for m in managers[1:]:
        assert m is first
