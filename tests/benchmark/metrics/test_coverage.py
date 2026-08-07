import pytest
from argus.benchmark.ground_truth.models import ComparisonResult, MatchResult, MatchStatus
from argus.benchmark.metrics.coverage import CoverageCalculator

def test_coverage_calculation():
    result = ComparisonResult(dataset_id="ds-1", mission_id="ms-1")
    
    # 2 expected Technologies, 1 matched, 1 missed (50%)
    result.matches.append(MatchResult(category="Technologies", expected="React", actual="React", status=MatchStatus.MATCHED, explanation="", confidence=1.0))
    result.misses.append(MatchResult(category="Technologies", expected="Node", actual=None, status=MatchStatus.NOT_MATCHED, explanation="", confidence=1.0))
    
    # 0 expected Frameworks -> 100%
    
    # 1 expected Endpoint, 1 matched (100%)
    result.matches.append(MatchResult(category="Endpoints", expected="/api/v1/users", actual="/api/v1/users", status=MatchStatus.MATCHED, explanation="", confidence=1.0))
    
    report = CoverageCalculator.calculate(result)
    
    assert report.technology_coverage == 50.0
    assert report.framework_coverage == 100.0
    assert report.api_coverage == 100.0
