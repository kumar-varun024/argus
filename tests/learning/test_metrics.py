"""Unit tests for argus.learning.metrics"""
import pytest
from argus.learning.metrics import MissionMetricsCalculator
from argus.runtime.mission import Mission


def _make_mission(**kwargs) -> Mission:
    m = Mission(target="test.example.com")
    for k, v in kwargs.items():
        setattr(m, k, v)
    return m


class TestMissionMetricsCalculator:
    def setup_method(self):
        self.calc = MissionMetricsCalculator()

    def test_coverage_from_dict(self):
        m = _make_mission(coverage={"overall_coverage": 0.75})
        r = self.calc.calculate(m)
        assert r.coverage_pct == pytest.approx(0.75)

    def test_coverage_missing(self):
        m = Mission(target="t")
        r = self.calc.calculate(m)
        assert r.coverage_pct == 0.0

    def test_execution_time(self):
        m = Mission(target="t")
        m.metrics["durations"] = {"total_execution_time": 120.5}
        r = self.calc.calculate(m)
        assert r.execution_time_seconds == pytest.approx(120.5)

    def test_investigation_count(self):
        m = Mission(target="t")
        from argus.correlation.evidence import EvidenceBundle
        from argus.correlation.registry import EvidenceBundleRegistry
        from argus.investigation.models import Investigation, InvestigationCategory
        inv = Investigation(
            title="Test", summary="S", description="D",
            category=InvestigationCategory.AUTHORIZATION
        )
        m.investigations.add(inv)
        r = self.calc.calculate(m)
        assert r.investigation_count == 1

    def test_hypothesis_count_missing(self):
        m = Mission(target="t")
        # hypotheses field may be list or HypothesisRegistry
        r = self.calc.calculate(m)
        assert r.hypothesis_count >= 0

    def test_evidence_quality_avg(self):
        m = Mission(target="t")
        from argus.correlation.evidence import EvidenceBundle
        b1 = EvidenceBundle(title="B1", description="d", confidence=0.6)
        b2 = EvidenceBundle(title="B2", description="d", confidence=0.8)
        m.evidence_bundles.add(b1)
        m.evidence_bundles.add(b2)
        r = self.calc.calculate(m)
        assert r.evidence_quality == pytest.approx(0.7)

    def test_evidence_quality_no_bundles(self):
        m = Mission(target="t")
        r = self.calc.calculate(m)
        assert r.evidence_quality == 0.0

    def test_task_completion_rate_no_history(self):
        m = Mission(target="t")
        r = self.calc.calculate(m)
        assert r.task_completion_rate == 0.0
        assert r.failed_task_count == 0

    def test_task_completion_rate_mixed(self):
        m = Mission(target="t")
        m.execution_history = [
            {"id": "t1", "status": "COMPLETED"},
            {"id": "t2", "status": "SUCCEEDED"},
            {"id": "t3", "status": "FAILED"},
        ]
        r = self.calc.calculate(m)
        assert r.task_completion_rate == pytest.approx(2 / 3)
        assert r.failed_task_count == 1

    def test_task_completion_rate_all_failed(self):
        m = Mission(target="t")
        m.execution_history = [
            {"id": "t1", "status": "FAILED"},
            {"id": "t2", "status": "FAILED"},
        ]
        r = self.calc.calculate(m)
        assert r.task_completion_rate == 0.0
        assert r.failed_task_count == 2

    def test_mission_id_and_target_populated(self):
        m = Mission(target="example.com")
        r = self.calc.calculate(m)
        assert r.mission_id == str(m.id)
        assert r.target == "example.com"
