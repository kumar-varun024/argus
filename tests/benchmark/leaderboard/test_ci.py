import pytest
from argus.benchmark.leaderboard.ci import CIIntegration
from argus.benchmark.leaderboard.models import RegressionReport, Classification

def test_get_commit_sha(monkeypatch):
    monkeypatch.setenv("ARGUS_COMMIT_SHA", "testsha123")
    assert CIIntegration.get_commit_sha() == "testsha123"
    
def test_handle_regression_exit_incompatible(monkeypatch):
    report = RegressionReport(
        overall_status=Classification.INCOMPATIBLE,
        baseline_id="1", current_id="2",
        regressions=[], improvements=[], stable_metrics=[],
        incompatible_metrics=["dataset_version"],
        affected_benchmarks=[], affected_categories=[], recommendations=[]
    )
    
    with pytest.raises(SystemExit) as excinfo:
        CIIntegration.handle_regression_exit(report, fail_on_regression=True)
    assert excinfo.value.code == 2
    
def test_handle_regression_exit_regression(monkeypatch):
    report = RegressionReport(
        overall_status=Classification.SIGNIFICANTLY_REGRESSED,
        baseline_id="1", current_id="2",
        regressions=[], improvements=[], stable_metrics=[],
        incompatible_metrics=[],
        affected_benchmarks=[], affected_categories=[], recommendations=[]
    )
    
    with pytest.raises(SystemExit) as excinfo:
        CIIntegration.handle_regression_exit(report, fail_on_regression=True)
    assert excinfo.value.code == 1
    
def test_handle_regression_exit_success(monkeypatch):
    report = RegressionReport(
        overall_status=Classification.IMPROVED,
        baseline_id="1", current_id="2",
        regressions=[], improvements=[], stable_metrics=[],
        incompatible_metrics=[],
        affected_benchmarks=[], affected_categories=[], recommendations=[]
    )
    
    with pytest.raises(SystemExit) as excinfo:
        CIIntegration.handle_regression_exit(report, fail_on_regression=True)
    assert excinfo.value.code == 0
