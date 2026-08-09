import pytest
from argus.benchmark.runner.models import EvaluationResult
from argus.benchmark.metrics.models import BenchmarkScore, CoverageReport
from argus.benchmark.ground_truth.models import ComparisonResult, MatchResult, MatchStatus
from argus.benchmark.reports.generator import ReportGenerator

def test_report_generator_summary():
    eval_result = EvaluationResult(
        id="eval-1",
        benchmark_id="bench-1",
        dataset="dataset-1",
        runtime=100.0,
        score=BenchmarkScore(overall_score=85.0, false_positive_score=5.0, false_negative_score=10.0),
        coverage=CoverageReport(
            api_coverage=100.0,
            workflow_coverage=30.0 # Creates a gap
        ),
        comparison=ComparisonResult(dataset_id="d", mission_id="m")
    )
    
    report = ReportGenerator.generate(eval_result)
    
    assert report.summary.overall_score == 85.0
    assert "workflow_coverage" in report.summary.important_coverage_gaps
    assert report.summary.false_positive_rate == 5.0
    assert "Workflow Coverage is below acceptable threshold. Review detection rules." in report.recommendations
    
def test_historical_comparison():
    past_result = EvaluationResult(id="eval-0", benchmark_id="bench-1", dataset="dataset-1", runtime=100.0, score=BenchmarkScore(overall_score=80.0))
    current_result = EvaluationResult(id="eval-1", benchmark_id="bench-1", dataset="dataset-1", runtime=100.0, score=BenchmarkScore(overall_score=85.0))
    
    report = ReportGenerator.generate(current_result, previous_results=[past_result])
    
    assert report.historical_comparison["overall_score_trend"] == "Improved"
    assert report.historical_comparison["difference"] == 5.0
    assert "Overall score improved by 5.00 points." in report.summary.comparison_summary
