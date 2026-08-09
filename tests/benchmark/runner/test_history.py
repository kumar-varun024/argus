import pytest
from argus.benchmark.runner.history import HistoryManager
from argus.benchmark.runner.models import EvaluationResult
from argus.benchmark.metrics.models import BenchmarkScore

def test_history_append_and_trend():
    manager = HistoryManager()
    
    # Run 1
    res1 = EvaluationResult(id="1", benchmark_id="b1", dataset="d1", runtime=100.0, score=BenchmarkScore(overall_score=50.0))
    manager.append(res1)
    
    # Run 2
    res2 = EvaluationResult(id="2", benchmark_id="b1", dataset="d1", runtime=90.0, score=BenchmarkScore(overall_score=70.0))
    manager.append(res2)
    
    trend = manager.get_trend("b1")
    
    assert trend["total_runs"] == 2
    assert trend["latest_score"] == 70.0
    assert trend["average_score"] == 60.0
    assert trend["highest_score"] == 70.0
    assert trend["lowest_score"] == 50.0
    assert trend["trend"] == "improving"
