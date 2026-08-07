import pytest
from argus.hypothesis.models import Hypothesis, HypothesisCategory, HypothesisStatus
from argus.hypothesis.lifecycle import HypothesisLifecycleManager

class MockMission:
    def __init__(self):
        self.hypothesis_history = []

def test_transition():
    hyp = Hypothesis(title="Test", summary="S", description="D", category=HypothesisCategory.AUTHORIZATION)
    manager = HypothesisLifecycleManager()
    
    assert hyp.status == HypothesisStatus.DRAFT
    
    # Transition
    assert manager.propose(hyp) is True
    assert hyp.status == HypothesisStatus.PROPOSED
    assert len(hyp.history) == 1
    assert hyp.history[0].status == HypothesisStatus.PROPOSED
    
    # Transition to same state does nothing
    assert manager.propose(hyp) is False
    assert len(hyp.history) == 1
    
    # Mission history
    mission = MockMission()
    manager.validate(hyp, "Validated by researcher", mission)
    
    assert hyp.status == HypothesisStatus.VALIDATED
    assert len(hyp.history) == 2
    assert len(mission.hypothesis_history) == 1
    assert mission.hypothesis_history[0]["new_status"] == HypothesisStatus.VALIDATED.value

def test_other_transitions():
    hyp = Hypothesis(title="Test", summary="S", description="D", category=HypothesisCategory.AUTHORIZATION)
    manager = HypothesisLifecycleManager()
    
    manager.review(hyp)
    assert hyp.status == HypothesisStatus.UNDER_REVIEW
    
    manager.reject(hyp, "Not enough evidence")
    assert hyp.status == HypothesisStatus.REJECTED
    
    manager.archive(hyp, "Old")
    assert hyp.status == HypothesisStatus.ARCHIVED
