import pytest
import uuid
from argus.hypothesis.models import Hypothesis, HypothesisCategory, HypothesisStatus
from argus.hypothesis.registry import HypothesisRegistry
from argus.hypothesis.confidence import HypothesisConfidenceScorer
from argus.hypothesis.ranking import HypothesisRanker
from argus.hypothesis.generator import HypothesisGenerator
from argus.investigation.models import Investigation, InvestigationCategory

class MockMission:
    def __init__(self):
        self.evidence_bundles = self
        self.investigations = self
    def find(self, uid):
        class MockItem:
            def __init__(self):
                self.confidence = 0.5
        return MockItem()

def test_process_investigation_low_confidence_rejected():
    generator = HypothesisGenerator(HypothesisRegistry(), HypothesisConfidenceScorer(), HypothesisRanker())
    inv = Investigation(
        title="Test Inv", summary="S", description="D", category=InvestigationCategory.AUTHORIZATION,
        confidence=0.2
    )
    inv.evidence_bundles.append(uuid.uuid4()) # Only 1 bundle
    
    hyp = generator.process_investigation(inv)
    assert hyp is None

def test_process_investigation_generates_new():
    generator = HypothesisGenerator(HypothesisRegistry(), HypothesisConfidenceScorer(), HypothesisRanker())
    inv = Investigation(
        title="Test Inv", summary="S", description="D", category=InvestigationCategory.AUTHORIZATION,
        confidence=0.8
    )
    inv.evidence_bundles.append(uuid.uuid4())
    inv.business_objects = ["User"]
    
    hyp = generator.process_investigation(inv)
    
    assert hyp is not None
    assert hyp.title == "Hypothesis: Test Inv"
    assert hyp.category == HypothesisCategory.AUTHORIZATION
    assert hyp.status == HypothesisStatus.DRAFT
    assert "User" in hyp.business_objects
    assert len(generator.registry.get_all()) == 1

def test_process_investigation_refines_existing():
    registry = HypothesisRegistry()
    generator = HypothesisGenerator(registry, HypothesisConfidenceScorer(), HypothesisRanker())
    
    # Generate first
    inv1 = Investigation(
        title="Inv 1", summary="S", description="D", category=InvestigationCategory.AUTHORIZATION,
        confidence=0.8
    )
    inv1.business_objects = ["User"]
    inv1.evidence_bundles = [uuid.uuid4()]
    hyp1 = generator.process_investigation(inv1)
    
    assert len(registry.get_all()) == 1
    
    # Generate second with overlap
    inv2 = Investigation(
        title="Inv 2", summary="S", description="D", category=InvestigationCategory.AUTHORIZATION,
        confidence=0.9
    )
    inv2.business_objects = ["User"] # Overlaps on User
    inv2.evidence_bundles = [uuid.uuid4()]
    
    hyp2 = generator.process_investigation(inv2)
    
    # Should be the same hypothesis refined
    assert hyp2.id == hyp1.id
    assert len(registry.get_all()) == 1
    assert len(hyp2.related_investigations) == 2
    assert len(hyp2.related_evidence) == 2
