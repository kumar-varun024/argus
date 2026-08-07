import pytest
from argus.runtime.mission import Mission
from argus.investigation.models import Investigation, InvestigationCategory
from argus.correlation.evidence import EvidenceBundle
from argus.hypothesis.engine import HypothesisEngine
from argus.hypothesis.models import HypothesisStatus
from argus.hypothesis.registry import HypothesisRegistry

def test_full_hypothesis_pipeline():
    # Setup mission and hypothesis engine
    mission = Mission(target="test.local")
    
    # Normally, __post_init__ would create mission.hypotheses if the module exists. 
    # Just to be safe, we assign it.
    mission.hypotheses = HypothesisRegistry()
    
    engine = HypothesisEngine(registry=mission.hypotheses)
    
    # Create evidence
    bundle1 = EvidenceBundle(title="B1", description="D1", confidence=0.8)
    mission.evidence_bundles.add(bundle1)
    
    bundle2 = EvidenceBundle(title="B2", description="D2", confidence=0.7)
    mission.evidence_bundles.add(bundle2)
    
    # Create investigation
    inv = Investigation(
        title="Auth Bypass", summary="S", description="D", 
        category=InvestigationCategory.AUTHORIZATION,
        confidence=0.8
    )
    inv.evidence_bundles = [bundle1.id, bundle2.id]
    inv.business_objects = ["Order", "User"]
    mission.investigations.add(inv)
    
    # Process
    hyp = engine.process_investigation(inv, mission)
    
    assert hyp is not None
    assert hyp.title == "Hypothesis: Auth Bypass"
    assert hyp.confidence > 0.7  # Calculated from evidence bundles
    assert hyp.priority_score > 0
    assert "Order" in hyp.business_objects
    assert "User" in hyp.business_objects
    
    # High confidence should have auto-proposed it
    assert hyp.status == HypothesisStatus.PROPOSED
    assert len(hyp.history) == 1
    assert hyp.history[0].status == HypothesisStatus.PROPOSED
    
    # Rank
    ranked = engine.get_ranked_hypotheses()
    assert len(ranked) == 1
    assert ranked[0] == hyp
