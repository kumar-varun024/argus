"""Unit tests for argus.learning.patterns"""
import pytest
from argus.learning.models import (
    LearningRecord, MissionMetricsRecord,
    PluginUsageStat, HeuristicUsageStat,
)
from argus.learning.patterns import PatternDiscovery


def _rec(mission_id: str, **kwargs) -> LearningRecord:
    rec = LearningRecord(mission_id=mission_id, **kwargs)
    return rec


class TestPatternDiscovery:
    def setup_method(self):
        self.discovery = PatternDiscovery()

    # ------------------------------------------------------------------
    # Insufficient history guard
    # ------------------------------------------------------------------

    def test_no_patterns_with_zero_records(self):
        assert self.discovery.discover([]) == []

    def test_no_patterns_with_one_record(self):
        rec = _rec("m1", validated_hypotheses=["h1", "h2"])
        assert self.discovery.discover([rec]) == []

    # ------------------------------------------------------------------
    # High Authorization validation rate
    # ------------------------------------------------------------------

    def test_auth_validation_pattern_fires(self):
        records = [
            _rec("m1", validated_hypotheses=["h1"]),
            _rec("m2", validated_hypotheses=["h2", "h3"]),
            _rec("m3", validated_hypotheses=["h4"]),
        ]
        patterns = self.discovery.discover(records)
        names = [p.name for p in patterns]
        assert any("frequently validated" in n for n in names)

    def test_auth_validation_pattern_no_fire_below_threshold(self):
        # 0 out of 3 missions have validated hypotheses → rate=0 < 0.60
        records = [
            _rec("m1", validated_hypotheses=[]),
            _rec("m2", validated_hypotheses=[]),
            _rec("m3", validated_hypotheses=[]),
        ]
        patterns = self.discovery.discover(records)
        names = [p.name for p in patterns]
        assert not any("frequently validated" in n for n in names)

    # ------------------------------------------------------------------
    # Noisy heuristic
    # ------------------------------------------------------------------

    def test_noisy_heuristic_pattern_fires(self):
        h_stat = HeuristicUsageStat(
            heuristic_id="h_authz", category="Authorization",
            true_positives=1, false_positives=9  # 90% noise
        )
        records = [
            _rec("m1", heuristic_usage={"h_authz": h_stat}),
            _rec("m2", heuristic_usage={"h_authz": h_stat}),
        ]
        patterns = self.discovery.discover(records)
        names = [p.name for p in patterns]
        assert any("produces excessive noise" in n for n in names)

    def test_noisy_heuristic_no_fire_below_threshold(self):
        h_stat = HeuristicUsageStat(
            heuristic_id="h_clean", category="Authorization",
            true_positives=9, false_positives=1  # 10% noise
        )
        records = [
            _rec("m1", heuristic_usage={"h_clean": h_stat}),
            _rec("m2", heuristic_usage={"h_clean": h_stat}),
        ]
        patterns = self.discovery.discover(records)
        names = [p.name for p in patterns]
        assert not any("excessive noise" in n for n in names)

    # ------------------------------------------------------------------
    # Valuable plugin
    # ------------------------------------------------------------------

    def test_valuable_plugin_pattern_fires(self):
        p_stat = PluginUsageStat(
            plugin_id="js_specialist", plugin_name="JavaScript Specialist",
            invocations=5, validated_investigations=4
        )
        records = [
            _rec("m1", plugin_usage={"js_specialist": p_stat}),
            _rec("m2", plugin_usage={"js_specialist": p_stat}),
        ]
        patterns = self.discovery.discover(records)
        names = [p.name for p in patterns]
        assert any("highest value investigations" in n for n in names)

    def test_valuable_plugin_no_fire_single_mission(self):
        p_stat = PluginUsageStat(
            plugin_id="js_specialist", plugin_name="JavaScript Specialist",
            invocations=5, validated_investigations=4
        )
        records = [_rec("m1", plugin_usage={"js_specialist": p_stat})]
        assert self.discovery.discover(records) == []

    # ------------------------------------------------------------------
    # Coverage bottleneck
    # ------------------------------------------------------------------

    def test_coverage_bottleneck_fires(self):
        records = [
            _rec("m1", failed_tasks=["t1", "t2"]),
            _rec("m2", failed_tasks=["t3"]),
        ]
        patterns = self.discovery.discover(records)
        names = [p.name for p in patterns]
        assert any("Coverage gaps" in n for n in names)

    def test_coverage_bottleneck_no_fire_when_no_failures(self):
        records = [
            _rec("m1", failed_tasks=[]),
            _rec("m2", failed_tasks=[]),
        ]
        patterns = self.discovery.discover(records)
        names = [p.name for p in patterns]
        assert not any("Coverage gaps" in n for n in names)

    # ------------------------------------------------------------------
    # Workflow discovery leader
    # ------------------------------------------------------------------

    def test_workflow_leader_fires(self):
        p_stat = PluginUsageStat(
            plugin_id="js_spec", plugin_name="JavaScript",
            invocations=3, total_observations=50
        )
        records = [
            _rec("m1", plugin_usage={"js_spec": p_stat}),
            _rec("m2", plugin_usage={"js_spec": p_stat}),
        ]
        patterns = self.discovery.discover(records)
        names = [p.name for p in patterns]
        assert any("discovered most workflows" in n for n in names)

    # ------------------------------------------------------------------
    # Pattern strength bounds
    # ------------------------------------------------------------------

    def test_pattern_strength_between_0_and_1(self):
        p_stat = PluginUsageStat(
            plugin_id="huge", plugin_name="Huge Plugin",
            invocations=1, total_observations=10000  # very high, should cap at 1.0
        )
        records = [
            _rec("m1", plugin_usage={"huge": p_stat}),
            _rec("m2", plugin_usage={"huge": p_stat}),
        ]
        patterns = self.discovery.discover(records)
        for p in patterns:
            assert 0.0 <= p.strength <= 1.0
