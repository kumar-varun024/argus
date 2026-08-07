import pytest
import uuid
from argus.hypothesis.models import Hypothesis, HypothesisCategory, HypothesisPriority
from argus.hypothesis.ranking import HypothesisRanker

def test_evaluate_priority():
    ranker = HypothesisRanker()
    hyp = Hypothesis(
        title="Test Hyp", summary="S", description="D", category=HypothesisCategory.AUTHORIZATION
    )
    
    # Baseline
    hyp.confidence = 0.5 # 20 points
    hyp.business_objects = ["User", "Order"] # 10 points
    hyp.workflows = ["Checkout"] # 10 points
    hyp.related_evidence = [uuid.uuid4()] # 5 points
    
    score = ranker.evaluate_priority(hyp)
    assert score == 45.0
    assert hyp.priority == HypothesisPriority.MEDIUM

def test_rank():
    ranker = HypothesisRanker()
    
    h1 = Hypothesis(title="H1", summary="S", description="D", category=HypothesisCategory.AUTHORIZATION)
    h1.priority_score = 50.0
    h1.confidence = 0.5
    
    h2 = Hypothesis(title="H2", summary="S", description="D", category=HypothesisCategory.API)
    h2.priority_score = 80.0
    h2.confidence = 0.9
    
    h3 = Hypothesis(title="H3", summary="S", description="D", category=HypothesisCategory.AUTHORIZATION)
    h3.priority_score = 50.0
    h3.confidence = 0.8
    
    ranked = ranker.rank([h1, h2, h3])
    
    assert ranked[0] == h2
    assert ranked[1] == h3 # same score as h1, but higher confidence
    assert ranked[2] == h1
    
    auth_only = ranker.rank([h1, h2, h3], category=HypothesisCategory.AUTHORIZATION.value)
    assert len(auth_only) == 2
    assert h2 not in auth_only
