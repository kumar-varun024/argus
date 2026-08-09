import pytest
from argus.benchmark.leaderboard.models import LeaderboardEntry, Classification
from argus.benchmark.leaderboard.regression import RegressionDetector

def test_regression_detection_incompatible():
    base = LeaderboardEntry(id="1", benchmark_id="b1", dataset_id="d1", dataset_version="1.0", argus_version="1.0", commit_sha="", timestamp="", overall_score=0)
    curr = LeaderboardEntry(id="2", benchmark_id="b1", dataset_id="d1", dataset_version="2.0", argus_version="1.0", commit_sha="", timestamp="", overall_score=0)
    
    report = RegressionDetector.detect(base, curr)
    assert report.overall_status == Classification.INCOMPATIBLE
    
def test_regression_detection_regressed():
    base = LeaderboardEntry(id="1", benchmark_id="b1", dataset_id="d1", dataset_version="1.0", argus_version="1.0", commit_sha="", timestamp="", overall_score=80.0)
    curr = LeaderboardEntry(id="2", benchmark_id="b1", dataset_id="d1", dataset_version="1.0", argus_version="1.0", commit_sha="", timestamp="", overall_score=75.0)
    
    report = RegressionDetector.detect(base, curr)
    assert report.overall_status == Classification.SIGNIFICANTLY_REGRESSED
    assert len(report.regressions) > 0
    
def test_regression_detection_improved():
    base = LeaderboardEntry(id="1", benchmark_id="b1", dataset_id="d1", dataset_version="1.0", argus_version="1.0", commit_sha="", timestamp="", overall_score=80.0)
    curr = LeaderboardEntry(id="2", benchmark_id="b1", dataset_id="d1", dataset_version="1.0", argus_version="1.0", commit_sha="", timestamp="", overall_score=85.0)
    
    report = RegressionDetector.detect(base, curr)
    assert report.overall_status == Classification.IMPROVED
    assert len(report.improvements) > 0
