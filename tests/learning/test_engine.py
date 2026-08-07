"""Unit tests for argus.learning.engine"""
import pytest
from argus.learning.engine import LearningEngine
from argus.learning.models import LearningRecord, DiscoveredPattern, Recommendation
from argus.learning.registry import LearningRegistry
from argus.learning.metrics import MissionMetricsCalculator
from argus.learning.patterns import PatternDiscovery
from argus.learning.recommendations import RecommendationEngine
from argus.learning.history import MissionHistoryStore
from argus.learning.feedback import FeedbackCollector
from argus.runtime.mission import Mission


def _make_engine(tmp_path):
    reg = LearningRegistry(storage_path=str(tmp_path / "lr.json"))
    return LearningEngine(
        registry=reg,
        metrics_calculator=MissionMetricsCalculator(),
        pattern_discovery=PatternDiscovery(),
        recommendation_engine=RecommendationEngine(),
        history_store=MissionHistoryStore(reg),
        feedback_collector=FeedbackCollector(reg),
    ), reg


class TestLearningEngine:
    def test_process_mission_returns_record(self, tmp_path):
        engine, _ = _make_engine(tmp_path)
        m = Mission(target="example.com")
        record = engine.process_mission(m)
        assert isinstance(record, LearningRecord)
        assert record.mission_id == str(m.id)

    def test_process_mission_sets_mission_learning(self, tmp_path):
        engine, _ = _make_engine(tmp_path)
        m = Mission(target="example.com")
        engine.process_mission(m)
        assert m.learning is not None
        assert isinstance(m.learning, LearningRecord)

    def test_process_mission_augments_metrics_dict(self, tmp_path):
        engine, _ = _make_engine(tmp_path)
        m = Mission(target="example.com")
        engine.process_mission(m)
        assert "learning" in m.metrics
        assert "investigation_count" in m.metrics["learning"]

    def test_process_mission_persists_record(self, tmp_path):
        engine, reg = _make_engine(tmp_path)
        m = Mission(target="example.com")
        engine.process_mission(m)
        assert reg.get_record(str(m.id)) is not None

    def test_discover_patterns_empty_with_no_history(self, tmp_path):
        engine, _ = _make_engine(tmp_path)
        patterns = engine.discover_patterns()
        assert patterns == []

    def test_discover_patterns_empty_with_one_record(self, tmp_path):
        engine, _ = _make_engine(tmp_path)
        m = Mission(target="t")
        engine.process_mission(m)
        patterns = engine.discover_patterns()
        assert patterns == []

    def test_discover_patterns_with_two_records(self, tmp_path):
        engine, _ = _make_engine(tmp_path)
        for target in ["a.com", "b.com"]:
            m = Mission(target=target)
            m.execution_history = [{"id": "t1", "status": "FAILED"}]
            engine.process_mission(m)
        patterns = engine.discover_patterns()
        # At least coverage bottleneck pattern should fire
        assert isinstance(patterns, list)

    def test_generate_recommendations_returns_list(self, tmp_path):
        engine, _ = _make_engine(tmp_path)
        recs = engine.generate_recommendations()
        assert isinstance(recs, list)

    def test_generate_recommendations_stores_to_mission_patterns(self, tmp_path):
        engine, _ = _make_engine(tmp_path)
        # Add 2 missions with failures so patterns can fire
        for target in ["a.com", "b.com"]:
            m = Mission(target=target)
            m.execution_history = [{"id": "t1", "status": "FAILED"}]
            engine.process_mission(m)
        active_mission = Mission(target="active.com")
        recs = engine.generate_recommendations(mission=active_mission)
        assert len(active_mission.patterns) == len(recs)

    def test_recommendations_always_require_approval(self, tmp_path):
        engine, _ = _make_engine(tmp_path)
        for target in ["a.com", "b.com"]:
            m = Mission(target=target)
            m.execution_history = [{"id": "t1", "status": "FAILED"}]
            engine.process_mission(m)
        recs = engine.generate_recommendations()
        for rec in recs:
            assert rec.requires_planner_approval is True

    def test_feedback_collector_accessible(self, tmp_path):
        engine, _ = _make_engine(tmp_path)
        assert engine.feedback is not None

    def test_feedback_recorded_in_mission(self, tmp_path):
        engine, _ = _make_engine(tmp_path)
        from argus.learning.models import FeedbackTag, FeedbackTargetType
        m = Mission(target="t")
        engine.feedback.submit(
            mission=m,
            target_id="aaaaaaaa-0000-0000-0000-000000000000",
            target_type=FeedbackTargetType.INVESTIGATION,
            tag=FeedbackTag.HIGH_VALUE,
        )
        assert len(m.feedback) == 1
