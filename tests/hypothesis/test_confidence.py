import pytest
import uuid
from argus.hypothesis.models import Hypothesis, HypothesisCategory
from argus.hypothesis.confidence import HypothesisConfidenceScorer

class MockMission:
    def __init__(self, inv_conf=0.8, bundle_conf=0.7):
        self.inv_conf = inv_conf
        self.bundle_conf = bundle_conf
        self.investigations = self
        self.evidence_bundles = self
        
    def find(self, uid):
        class MockItem:
            def __init__(self, c):
                self.confidence = c
        # Distinguish between inv and bundle somehow, or just return based on some condition
        # For simplicity we'll just return a mock with 0.8 confidence
        return MockItem(0.8)

def test_confidence_no_context():
    hyp = Hypothesis(
        title="Test Hyp", summary="S", description="D", category=HypothesisCategory.AUTHORIZATION
    )
    scorer = HypothesisConfidenceScorer()
    
    # 0 evidence -> 0.0
    conf = scorer.calculate_confidence(hyp)
    assert conf == 0.0
    
    # 1 evidence -> penalized
    hyp.related_evidence.append(uuid.uuid4())
    hyp.metadata['max_investigation_confidence'] = 0.5
    conf = scorer.calculate_confidence(hyp)
    assert conf == pytest.approx(0.5 * 0.8)
    
def test_confidence_with_context():
    hyp = Hypothesis(
        title="Test Hyp", summary="S", description="D", category=HypothesisCategory.AUTHORIZATION
    )
    scorer = HypothesisConfidenceScorer()
    mission = MockMission()
    
    hyp.related_evidence.append(uuid.uuid4())
    hyp.related_evidence.append(uuid.uuid4())
    hyp.related_investigations.append(uuid.uuid4())
    
    conf = scorer.calculate_confidence(hyp, mission)
    # max(0.8, 0.8, 0.8) + (3 - 1) * 0.05 = 0.90
    assert conf == pytest.approx(0.90)
