import pytest
from argus.correlation.scoring import CorrelationScorer
from argus.correlation.correlation import Correlation
from argus.correlation.observation import Observation
from argus.correlation.models import ObservationCategory, ObservationPriority
from argus.correlation.registry import ObservationRegistry

def test_correlation_scoring():
    registry = ObservationRegistry()
    obs1 = Observation(source="test", category=ObservationCategory.API, title="t", description="d", confidence=1.0, priority=ObservationPriority.LOW)
    obs2 = Observation(source="test", category=ObservationCategory.API, title="t", description="d", confidence=0.5, priority=ObservationPriority.LOW)
    
    registry.add(obs1)
    registry.add(obs2)
    
    scorer = CorrelationScorer(registry)
    
    corr = Correlation(title="Test", description="Test")
    corr.observations = [obs1.id, obs2.id]
    
    corr.business_objects = ["User", "Org"]  # 2 * 5 = 10 pts
    corr.workflows = ["Login"]               # 1 * 5 = 5 pts
    corr.technologies = ["React", "Node"]    # 2 * 3 = 6 pts
    
    score = scorer.calculate_score(corr)
    
    # Confidence: (1.0 + 0.5) / 2 = 0.75 => 0.75 * 40 = 30 pts
    # BO: 10 pts
    # WF: 5 pts
    # Tech: 6 pts
    # Auth: 0 pts
    # Total: 30 + 10 + 5 + 6 = 51
    assert score == 51

def test_correlation_scoring_empty():
    registry = ObservationRegistry()
    scorer = CorrelationScorer(registry)
    corr = Correlation(title="Test", description="Test")
    assert scorer.calculate_score(corr) == 0
