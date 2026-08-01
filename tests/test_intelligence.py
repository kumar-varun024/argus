import pytest
from argus.runtime.mission import Mission
from argus.intelligence.models import Investigation
from argus.intelligence.heuristics import BaseHeuristic
from argus.intelligence.registry import HeuristicRegistry
from argus.intelligence.hypothesis import HypothesisGenerator
from argus.intelligence.confidence import ConfidenceScorer
from argus.intelligence.prioritizer import InvestigationPrioritizer
from argus.intelligence.engine import VulnerabilityIntelligenceEngine

class MockHeuristic(BaseHeuristic):
    @property
    def id(self) -> str: return "mock_heuristic"
    @property
    def name(self) -> str: return "Mock Heuristic"
    @property
    def description(self) -> str: return "Mock"
    @property
    def category(self) -> str: return "Authorization"
    @property
    def required_inputs(self) -> list: return []
    
    def run(self, mission: Mission) -> list:
        inv = Investigation(
            title="Mock Auth Finding",
            category="Authorization",
            affected_objects=["User"],
            reasoning="Because mock.",
            supporting_evidence=["mock_evidence_1", "mock_evidence_2", "mock_evidence_3"],
            workflow="User Login"
        )
        return [inv]
        
    def score(self, investigation: Investigation) -> float:
        return 0.8

def test_heuristic_registry():
    registry = HeuristicRegistry()
    h = MockHeuristic()
    registry.register(h)
    
    with pytest.raises(ValueError):
        registry.register(h)
        
    assert len(registry.get_all()) == 1
    assert registry.get("mock_heuristic") == h
    assert len(registry.get_by_category("Authorization")) == 1

def test_confidence_scorer():
    registry = HeuristicRegistry()
    scorer = ConfidenceScorer(registry)
    mission = Mission("test.local")
    
    inv = Investigation(
        title="Test",
        category="Test",
        supporting_evidence=["a", "b", "c"], # > 2 gives 1.2 multiplier
        workflow="Test Workflow" # gives 1.1 multiplier
    )
    
    # base 0.5 * 1.2 * 1.1 = 0.66 -> 66.0
    score = scorer.score(inv, mission)
    assert score == 66.0
    
def test_prioritizer():
    prioritizer = InvestigationPrioritizer()
    
    inv1 = Investigation(title="1", category="Authorization", confidence=95.0)
    inv2 = Investigation(title="2", category="Business Logic", confidence=75.0)
    inv3 = Investigation(title="3", category="Other", confidence=20.0)
    
    results = prioritizer.prioritize([inv3, inv2, inv1])
    
    assert results[0].priority == "Critical"
    assert results[1].priority == "Medium" 
    assert results[2].priority == "Informational"

def test_intelligence_engine():
    registry = HeuristicRegistry()
    registry.register(MockHeuristic())
    
    engine = VulnerabilityIntelligenceEngine(registry)
    mission = Mission("test.local")
    
    engine.run(mission)
    
    assert len(mission.investigations) == 1
    
    inv = mission.investigations[0]
    assert inv.title == "Mock Auth Finding"
    assert inv.priority == "High" # 66 confidence in auth -> High
    assert len(mission.priority_queue) == 1
