"""Unit tests for argus.learning.recommendations"""
import pytest
from argus.learning.models import DiscoveredPattern, RecommendationPriority
from argus.learning.recommendations import RecommendationEngine, _build_recommendation


def _pattern(name, strength=0.8, category="Test"):
    return DiscoveredPattern(
        name=name, description="desc", strength=strength,
        category=category, sample_mission_ids=["m1", "m2"]
    )


class TestBuildRecommendation:
    def test_auth_validation_pattern(self):
        p = _pattern("Authorization investigations frequently validated")
        rec = _build_recommendation(p)
        assert "Authorization" in rec.title
        assert rec.rationale

    def test_noisy_heuristic_pattern(self):
        p = _pattern("Heuristic h_authz produces excessive noise")
        rec = _build_recommendation(p)
        assert "h_authz" in rec.title
        assert rec.rationale

    def test_valuable_plugin_pattern(self):
        p = _pattern("JavaScript specialist generated highest value investigations")
        rec = _build_recommendation(p)
        assert "JavaScript" in rec.title
        assert rec.rationale

    def test_coverage_bottleneck_pattern(self):
        p = _pattern("Coverage gaps persist across missions")
        rec = _build_recommendation(p)
        assert "coverage" in rec.title.lower()
        assert rec.rationale

    def test_workflow_leader_pattern(self):
        p = _pattern("JavaScript specialist discovered most workflows")
        rec = _build_recommendation(p)
        assert "JavaScript" in rec.title
        assert rec.rationale

    def test_fallback_pattern(self):
        p = _pattern("Some unknown pattern type")
        rec = _build_recommendation(p)
        assert rec.rationale  # fallback must still produce rationale

    def test_high_strength_maps_to_high_priority(self):
        p = _pattern("Authorization investigations frequently validated", strength=0.9)
        rec = _build_recommendation(p)
        assert rec.priority == RecommendationPriority.HIGH

    def test_low_strength_maps_to_low_priority(self):
        p = _pattern("Authorization investigations frequently validated", strength=0.2)
        rec = _build_recommendation(p)
        assert rec.priority == RecommendationPriority.LOW

    def test_medium_strength_maps_to_medium_priority(self):
        p = _pattern("Authorization investigations frequently validated", strength=0.5)
        rec = _build_recommendation(p)
        assert rec.priority == RecommendationPriority.MEDIUM


class TestRecommendationEngine:
    def setup_method(self):
        self.engine = RecommendationEngine()

    def test_requires_planner_approval_always_true(self):
        patterns = [_pattern("Coverage gaps persist across missions")]
        recs = self.engine.generate(patterns)
        for rec in recs:
            assert rec.requires_planner_approval is True

    def test_empty_patterns_returns_empty(self):
        assert self.engine.generate([]) == []

    def test_sorted_high_first(self):
        patterns = [
            _pattern("Coverage gaps persist across missions", strength=0.2),  # Low
            _pattern("Authorization investigations frequently validated", strength=0.9),  # High
        ]
        recs = self.engine.generate(patterns)
        assert len(recs) == 2
        assert recs[0].priority == RecommendationPriority.HIGH

    def test_stores_to_mission_patterns(self):
        from argus.runtime.mission import Mission
        mission = Mission(target="t")
        patterns = [_pattern("Coverage gaps persist across missions")]
        recs = self.engine.generate(patterns, mission=mission)
        assert len(mission.patterns) == len(recs)

    def test_source_pattern_ids_populated(self):
        p = _pattern("Coverage gaps persist across missions")
        recs = self.engine.generate([p])
        assert recs[0].source_pattern_ids == [p.id]
