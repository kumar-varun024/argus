import pytest
from argus.correlation.deduplication import EvidenceDeduplicator

def test_evidence_deduplication():
    dedup = EvidenceDeduplicator()
    
    evidence_list = ["token1", "token2", "token1", "token3"]
    unique = dedup.deduplicate(evidence_list)
    
    assert len(unique) == 3
    assert "token1" in unique
    assert "token2" in unique
    assert "token3" in unique
    
def test_evidence_deduplication_unhashable():
    dedup = EvidenceDeduplicator()
    
    e1 = {"id": 1, "val": "A"}
    e2 = {"id": 1, "val": "A"}
    
    unique = dedup.deduplicate([e1, e2])
    # Dictionaries stringify to the same thing if keys are ordered identically
    # so they should deduplicate.
    assert len(unique) == 1
