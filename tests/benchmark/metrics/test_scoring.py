import pytest
from argus.benchmark.metrics.models import CoverageReport, QualityReport, PerformanceReport
from argus.benchmark.metrics.scoring import ScoringEngine
from argus.benchmark.ground_truth.models import ComparisonResult, MatchResult, MatchStatus

def test_scoring_calculation_perfect():
    coverage = CoverageReport(
        technology_coverage=100.0, framework_coverage=100.0, api_coverage=100.0,
        graphql_coverage=100.0, business_object_coverage=100.0, workflow_coverage=100.0,
        relationship_coverage=100.0, authentication_coverage=100.0, authorization_coverage=100.0,
        investigation_coverage=100.0
    )
    
    quality = QualityReport(
        observation_quality=100.0, correlation_quality=100.0, evidence_quality=100.0,
        investigation_quality=100.0, hypothesis_quality=100.0, explainability_quality=100.0
    )
    
    performance = PerformanceReport()
    
    comparison = ComparisonResult(dataset_id="1", mission_id="1")
    comparison.total_expected = 10 # Just for normalization of fp/fn
    
    score = ScoringEngine.calculate(coverage, quality, performance, comparison)
    
    assert score.overall_score == 100.0
    assert score.false_positive_score == 0.0
    assert score.false_negative_score == 0.0

def test_scoring_penalties():
    coverage = CoverageReport(
        technology_coverage=100.0, framework_coverage=100.0, api_coverage=100.0,
        graphql_coverage=100.0, business_object_coverage=100.0, workflow_coverage=100.0,
        relationship_coverage=100.0, authentication_coverage=100.0, authorization_coverage=100.0,
        investigation_coverage=100.0
    )
    quality = QualityReport(
        observation_quality=100.0, correlation_quality=100.0, evidence_quality=100.0,
        investigation_quality=100.0, hypothesis_quality=100.0, explainability_quality=100.0
    )
    performance = PerformanceReport()
    
    comparison = ComparisonResult(dataset_id="1", mission_id="1")
    comparison.total_expected = 10
    
    # Add 5 unexpected findings (50% FP)
    for i in range(5):
        comparison.unexpected_findings.append(MatchResult(category="T", expected="", actual="A", status=MatchStatus.UNEXPECTED_FINDING, explanation="", confidence=1.0))
        
    # Add 2 misses (20% FN)
    for i in range(2):
        comparison.misses.append(MatchResult(category="T", expected="E", actual="", status=MatchStatus.NOT_MATCHED, explanation="", confidence=1.0))
        
    score = ScoringEngine.calculate(coverage, quality, performance, comparison)
    
    assert score.false_positive_score > 0
    assert score.false_negative_score > 0
    assert score.overall_score < 100.0
