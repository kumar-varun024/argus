import pytest
from argus.benchmark.metrics.engine import MetricsEngine
from argus.benchmark.ground_truth.models import ComparisonResult, MatchResult, MatchStatus
from argus.runtime.mission import Mission

def test_metrics_engine_evaluate():
    engine = MetricsEngine()
    
    mission = Mission(target="http://test")
    comparison = ComparisonResult(dataset_id="ds-1", mission_id=mission.id)
    comparison.matches.append(MatchResult(category="Technologies", expected="React", actual="React", status=MatchStatus.MATCHED, explanation="", confidence=1.0))
    comparison.total_expected = 1
    
    score, coverage, quality, performance = engine.evaluate(mission, comparison, execution_time_ms=100.0)
    
    assert score is not None
    assert coverage is not None
    assert quality is not None
    assert performance is not None
    
    assert coverage.technology_coverage == 100.0
    
    # Check registry
    assert engine.registry.get_score(mission.id) == score
    assert engine.registry.get_coverage(mission.id) == coverage
    assert engine.registry.get_quality(mission.id) == quality
    assert engine.registry.get_performance(mission.id) == performance
