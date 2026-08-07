import pytest
from argus.benchmark.ground_truth.models import GroundTruth, MatchStatus
from argus.benchmark.ground_truth.matcher import GroundTruthMatcher
from argus.benchmark.ground_truth.comparison import GroundTruthComparer
from argus.runtime.mission import Mission
from argus.benchmark.ground_truth.engine import GroundTruthEngine

def test_matcher_exact():
    res = GroundTruthMatcher.match_item("Tech", "React", ["react", "node"])
    assert res.status == MatchStatus.MATCHED
    assert res.confidence == 1.0
    
def test_matcher_partial():
    res = GroundTruthMatcher.match_item("Tech", "React", ["reactjs", "node"])
    assert res.status == MatchStatus.PARTIALLY_MATCHED
    assert res.confidence == 0.5
    
def test_matcher_miss():
    res = GroundTruthMatcher.match_item("Tech", "Django", ["reactjs", "node"])
    assert res.status == MatchStatus.NOT_MATCHED
    assert res.confidence == 0.0

def test_matcher_unexpected():
    un = GroundTruthMatcher.identify_unexpected("Tech", ["React"], ["Vue", "reactjs"])
    assert len(un) == 1
    assert un[0].actual == "Vue"
    
def test_comparer():
    gt = GroundTruth(
        id="gt-1", dataset="ds-1", version="1.0",
        expected_technologies=["React", "PostgreSQL"],
        expected_business_objects=["User", "Order"]
    )
    
    m = Mission(
        id="m-1", target="example.com", policy={}, scope={}
    )
    m.technologies = ["React", "Express"]
    m.business_objects = [{"name": "User"}]
    
    res = GroundTruthComparer.compare(gt, m)
    
    assert res.total_expected == 4
    assert res.total_matched == 2 # React, User
    assert len(res.misses) == 2 # PostgreSQL, Order
    assert len(res.unexpected_findings) == 1 # Express
    
def test_engine_integration():
    gt = GroundTruth(
        id="gt-2", dataset="ds-2", version="1.0",
        expected_technologies=["React"]
    )
    m = Mission(
        id="m-2", target="example.com", policy={}, scope={}
    )
    m.dataset_id = "ds-2"
    m.technologies = ["React"]
    
    engine = GroundTruthEngine()
    engine.registry.register(gt)
    
    res = engine.evaluate(m)
    assert res.total_matched == 1
