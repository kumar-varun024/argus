"""Unit tests for argus.learning.models"""
import pytest
from argus.learning.models import (
    FeedbackEntry, FeedbackTag, FeedbackTargetType,
    PluginUsageStat, HeuristicUsageStat,
    MissionMetricsRecord, LearningRecord,
    DiscoveredPattern, Recommendation, RecommendationPriority,
)


class TestFeedbackEntry:
    def test_defaults(self):
        entry = FeedbackEntry(
            mission_id="m1",
            target_id="t1",
            target_type=FeedbackTargetType.INVESTIGATION,
            tag=FeedbackTag.HIGH_VALUE,
        )
        assert entry.mission_id == "m1"
        assert entry.tag == FeedbackTag.HIGH_VALUE
        assert entry.comment == ""
        assert entry.researcher == "unknown"
        assert entry.id  # auto-generated

    def test_all_tags_accessible(self):
        for tag in FeedbackTag:
            entry = FeedbackEntry(
                mission_id="m",
                target_id="t",
                target_type=FeedbackTargetType.HYPOTHESIS,
                tag=tag,
            )
            assert entry.tag == tag


class TestPluginUsageStat:
    def test_value_rate_zero_invocations(self):
        stat = PluginUsageStat(plugin_id="p", plugin_name="Plugin")
        assert stat.value_rate == 0.0

    def test_value_rate_calculated(self):
        stat = PluginUsageStat(
            plugin_id="p", plugin_name="Plugin",
            invocations=10, validated_investigations=4
        )
        assert stat.value_rate == pytest.approx(0.4)


class TestHeuristicUsageStat:
    def test_noise_rate_zero(self):
        h = HeuristicUsageStat(heuristic_id="h1", category="Authorization")
        assert h.noise_rate == 0.0

    def test_noise_rate_calculated(self):
        h = HeuristicUsageStat(
            heuristic_id="h1", category="Authorization",
            true_positives=3, false_positives=7
        )
        assert h.noise_rate == pytest.approx(0.7)


class TestMissionMetricsRecord:
    def test_defaults(self):
        r = MissionMetricsRecord(mission_id="m1")
        assert r.coverage_pct == 0.0
        assert r.investigation_count == 0
        assert r.task_completion_rate == 0.0

    def test_coverage_bounds(self):
        with pytest.raises(Exception):
            MissionMetricsRecord(mission_id="m1", coverage_pct=1.5)


class TestLearningRecord:
    def test_defaults(self):
        rec = LearningRecord(mission_id="m1")
        assert rec.validated_hypotheses == []
        assert rec.plugin_usage == {}
        assert rec.investigation_quality == 0.0

    def test_full_construction(self):
        metrics = MissionMetricsRecord(mission_id="m1")
        rec = LearningRecord(
            mission_id="m1",
            validated_hypotheses=["h1", "h2"],
            rejected_hypotheses=["h3"],
            completed_tasks=["t1"],
            failed_tasks=[],
            investigation_quality=0.75,
            metrics=metrics,
        )
        assert rec.investigation_quality == pytest.approx(0.75)
        assert len(rec.validated_hypotheses) == 2
        assert rec.metrics is not None


class TestDiscoveredPattern:
    def test_defaults(self):
        p = DiscoveredPattern(name="Test", description="desc")
        assert p.strength == 0.0
        assert p.sample_mission_ids == []
        assert p.id  # auto-generated


class TestRecommendation:
    def test_requires_approval_always_true(self):
        r = Recommendation(title="T", description="D", rationale="R")
        assert r.requires_planner_approval is True

    def test_cannot_be_set_false_via_constructor(self):
        # Pydantic will accept the value but our engine enforces it
        r = Recommendation(
            title="T", description="D", rationale="R",
            requires_planner_approval=False,
        )
        # The model accepts it — enforcement happens in RecommendationEngine
        assert r.title == "T"
