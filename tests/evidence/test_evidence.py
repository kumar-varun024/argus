import pytest
from argus.evidence.model import Evidence, ProvenanceData
from argus.evidence.manager import EvidenceManager

def test_evidence_manager_save_and_retrieve(tmp_path):
    manager = EvidenceManager(storage_dir=str(tmp_path))
    
    ev = Evidence(
        title="Test Evidence",
        description="A cool finding",
        investigation_id="inv-123",
        provenance=ProvenanceData(conversation_id="conv-1", original_ai_description="An finding")
    )
    
    manager.save(ev)
    
    retrieved = manager.get(ev.evidence_id)
    assert retrieved is not None
    assert retrieved.title == "Test Evidence"
    assert retrieved.investigation_id == "inv-123"
    assert retrieved.provenance.conversation_id == "conv-1"
    
def test_evidence_manager_supersede(tmp_path):
    manager = EvidenceManager(storage_dir=str(tmp_path))
    
    old_ev = Evidence(title="Old", investigation_id="inv-1")
    manager.save(old_ev)
    
    new_ev = Evidence(title="New", investigation_id="inv-1")
    
    manager.supersede(old_ev.evidence_id, new_ev)
    
    updated_old = manager.get(old_ev.evidence_id)
    assert updated_old.status == "SUPERSEDED"
    assert updated_old.relationships[0].relationship_type == "SUPERSEDED_BY"
    
    updated_new = manager.get(new_ev.evidence_id)
    assert updated_new.relationships[0].relationship_type == "SUPERSEDES"

def test_get_by_investigation(tmp_path):
    manager = EvidenceManager(storage_dir=str(tmp_path))
    manager.save(Evidence(title="E1", investigation_id="inv-A"))
    manager.save(Evidence(title="E2", investigation_id="inv-B"))
    manager.save(Evidence(title="E3", investigation_id="inv-A"))
    
    inv_a = manager.get_by_investigation("inv-A")
    assert len(inv_a) == 2
