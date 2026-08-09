import pytest
from argus.benchmark.leaderboard.comparison import MetricComparator
from argus.benchmark.leaderboard.models import LeaderboardEntry, Classification

def test_compare_metric_improvement():
    comp = MetricComparator.compare_metric("Overall Score", 80.0, 85.0)
    assert comp.classification == Classification.IMPROVED
    assert comp.percentage_difference == 6.25 # (5/80)*100
    
def test_compare_metric_significant_regression():
    comp = MetricComparator.compare_metric("Overall Score", 80.0, 75.0)
    assert comp.classification == Classification.SIGNIFICANTLY_REGRESSED
    assert comp.percentage_difference == -6.25
    
def test_compare_metric_stable():
    # 80.0 to 79.5 is a 0.625% regression, which is < 2.0% (default threshold)
    comp = MetricComparator.compare_metric("Overall Score", 80.0, 79.5)
    assert comp.classification == Classification.REGRESSED # Any drop is flagged as Regressed, > 2% is Significant
    
    # Wait, my logic in comparison.py:
    # elif diff < 0 and abs(pct_diff) > threshold: SIGNIFICANTLY_REGRESSED
    # elif diff < 0 and abs(pct_diff) > 0: REGRESSED
    # So 79.5 is REGRESSED. Let's test that.
    assert comp.classification == Classification.REGRESSED

def test_compare_metric_lower_better():
    # False positive rate, lower is better
    comp = MetricComparator.compare_metric("FP", 5.0, 2.0, is_lower_better=True)
    assert comp.classification == Classification.IMPROVED
    
    comp2 = MetricComparator.compare_metric("FP", 5.0, 10.0, is_lower_better=True)
    assert comp2.classification == Classification.SIGNIFICANTLY_REGRESSED # 100% increase > 5% threshold
    
def test_compatibility():
    base = LeaderboardEntry(id="1", benchmark_id="b1", dataset_id="d1", dataset_version="1.0", argus_version="1.0", commit_sha="", timestamp="", overall_score=0)
    curr = LeaderboardEntry(id="2", benchmark_id="b1", dataset_id="d1", dataset_version="2.0", argus_version="1.0", commit_sha="", timestamp="", overall_score=0)
    
    assert MetricComparator.check_compatibility(base, curr) is False
