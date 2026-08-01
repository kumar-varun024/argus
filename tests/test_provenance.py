import pytest
from argus.provenance.engine import ProvenanceEngine
from argus.provenance.models import ProvenanceRecord

def test_provenance_trace_lineage():
    engine = ProvenanceEngine()
    
    # 1. Create root evidence
    evidence = ProvenanceRecord(id="ev_1", artifact_type="Evidence", source_evidence=["raw_http_log"])
    engine.register_artifact(evidence)
    
    # 2. Create Knowledge Graph Node
    kg_node = ProvenanceRecord(id="kg_1", artifact_type="KnowledgeGraph")
    engine.register_artifact(kg_node)
    engine.link_artifacts(evidence.id, kg_node.id)
    
    # 3. Create Workflow
    wf_node = ProvenanceRecord(id="wf_1", artifact_type="Workflow")
    engine.register_artifact(wf_node)
    engine.link_artifacts(kg_node.id, wf_node.id)
    
    # 4. Create AI Research
    ai_node = ProvenanceRecord(id="ai_1", artifact_type="AIResearch")
    engine.register_artifact(ai_node)
    engine.link_artifacts(wf_node.id, ai_node.id)
    
    # 5. Create Research Card
    card = ProvenanceRecord(id="card_1", artifact_type="ResearchCard")
    engine.register_artifact(card)
    engine.link_artifacts(ai_node.id, card.id)
    
    # Validate entire graph is healthy
    assert engine.validate() is True
    
    # Check trace output
    trace_data = engine.trace(card.id)
    assert trace_data["id"] == "card_1"
    assert "ai_1" in trace_data["parents"]
    
    # Check explanation format
    explanation = engine.explain(card.id)
    assert "ResearchCard (card_1)" in explanation
    assert "AIResearch (ai_1)" in explanation
    assert "Workflow (wf_1)" in explanation
    assert "KnowledgeGraph (kg_1)" in explanation
    assert "Source Evidence: raw_http_log" in explanation

def test_provenance_unsupported_node():
    engine = ProvenanceEngine()
    
    # AI generates a card out of nowhere (hallucination)
    card = ProvenanceRecord(id="card_orphan", artifact_type="ResearchCard")
    engine.register_artifact(card)
    
    # Validation should fail
    assert engine.validate() is False
    
    stats = engine.get_stats()
    assert stats["total_artifacts"] == 1
    assert stats["unsupported_artifacts"] == 1
