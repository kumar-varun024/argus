"""Tests for the Research Planner (PR2 Sprint 11)."""
import pytest
import uuid
from datetime import datetime, timezone

from argus.runtime.mission import Mission
from argus.planning.research_planner import ResearchPlanner
from argus.planning.gap_analysis import GapAnalyzer
from argus.planning.coverage import CoverageTracker
from argus.planning.task_generator import TaskGenerator
from argus.planning.decision_engine import DecisionEngine
from argus.planning.models import (
    ResearchTask, TaskCategory, CoverageGap, CoverageReport,
)
from argus.correlation.observation import Observation
from argus.correlation.models import ObservationCategory, ObservationPriority

from typer.testing import CliRunner
from argus.cli.research_cli import app as research_app

runner = CliRunner()


# ─── Fixtures ──────────────────────────────────────────────────────

@pytest.fixture
def bare_mission():
    """Mission with almost no state — should produce many gaps."""
    return Mission(target="bare.example.com")


@pytest.fixture
def partial_mission():
    """Mission with some technologies and endpoints, but no observations."""
    m = Mission(target="partial.example.com")
    m.technologies = ["React", "Express", "GraphQL"]
    m.endpoints = [
        {"url": "/api/users", "method": "GET"},
        {"url": "/api/orders", "method": "POST"},
    ]
    return m


@pytest.fixture
def mission_with_observations():
    """Mission with observations already present (some gaps filled)."""
    m = Mission(target="full.example.com")
    m.technologies = ["React", "Express"]
    m.endpoints = [{"url": "/api/users", "method": "GET"}]

    obs = Observation(
        source="test",
        category=ObservationCategory.API,
        title="API Observation",
        description="Found an API endpoint.",
        confidence=1.0,
        priority=ObservationPriority.HIGH,
        timestamp=datetime.now(timezone.utc),
    )
    m.observations.add(obs)
    return m


# ─── Gap Analysis ──────────────────────────────────────────────────

class TestGapAnalysis:
    def test_bare_mission_has_technology_gap(self, bare_mission):
        gaps = GapAnalyzer(bare_mission).analyze()
        areas = [g.area for g in gaps]
        assert "Technologies" in areas

    def test_graphql_detected_but_no_schema(self, partial_mission):
        gaps = GapAnalyzer(partial_mission).analyze()
        areas = [g.area for g in gaps]
        assert "GraphQL Schema" in areas

    def test_no_graphql_gap_when_not_in_technologies(self, bare_mission):
        gaps = GapAnalyzer(bare_mission).analyze()
        areas = [g.area for g in gaps]
        assert "GraphQL Schema" not in areas


# ─── Coverage ──────────────────────────────────────────────────────

class TestCoverage:
    def test_bare_mission_low_coverage(self, bare_mission):
        report = CoverageTracker(bare_mission).compute()
        assert report.overall_coverage < 0.5

    def test_partial_mission_has_gaps(self, partial_mission):
        report = CoverageTracker(partial_mission).compute()
        assert len(report.gaps) > 0
        assert report.endpoints_total == 2

    def test_mission_with_observations_improves_coverage(self, mission_with_observations):
        report = CoverageTracker(mission_with_observations).compute()
        # We have 1 endpoint and 1 API observation, so endpoints should be partially covered
        assert report.endpoints_covered >= 1


# ─── Task Generation ──────────────────────────────────────────────

class TestTaskGenerator:
    def test_generates_tasks_from_gaps(self, partial_mission):
        gaps = GapAnalyzer(partial_mission).analyze()
        tasks = TaskGenerator(partial_mission).from_gaps(gaps)
        assert len(tasks) > 0
        assert all(isinstance(t, ResearchTask) for t in tasks)

    def test_no_duplicate_categories(self, partial_mission):
        gaps = GapAnalyzer(partial_mission).analyze()
        tasks = TaskGenerator(partial_mission).from_gaps(gaps)
        categories = [t.category for t in tasks]
        assert len(categories) == len(set(categories))

    def test_graphql_task_generated_when_graphql_gap(self, partial_mission):
        gaps = GapAnalyzer(partial_mission).analyze()
        tasks = TaskGenerator(partial_mission).from_gaps(gaps)
        titles = [t.title for t in tasks]
        assert "Analyze GraphQL Schema" in titles


# ─── Decision Engine ──────────────────────────────────────────────

class TestDecisionEngine:
    def test_tasks_sorted_by_priority(self, partial_mission):
        gaps = GapAnalyzer(partial_mission).analyze()
        tasks = TaskGenerator(partial_mission).from_gaps(gaps)
        coverage = CoverageTracker(partial_mission).compute()

        engine = DecisionEngine(partial_mission)
        prioritized = engine.prioritize(tasks, coverage)
        priorities = [t.priority for t in prioritized]
        assert priorities == sorted(priorities, reverse=True)

    def test_policy_disables_category(self, partial_mission):
        partial_mission.policy = {"disabled_categories": ["GraphQL Analysis"]}
        gaps = GapAnalyzer(partial_mission).analyze()
        tasks = TaskGenerator(partial_mission).from_gaps(gaps)

        engine = DecisionEngine(partial_mission)
        filtered = engine.filter_by_scope(tasks)
        categories = [t.category for t in filtered]
        assert TaskCategory.GRAPHQL_ANALYSIS not in categories


# ─── Research Planner (integration) ───────────────────────────────

class TestResearchPlanner:
    def test_plan_produces_tasks(self, partial_mission):
        planner = ResearchPlanner(partial_mission)
        tasks = planner.plan()
        assert len(tasks) > 0

    def test_plan_stores_into_mission(self, partial_mission):
        planner = ResearchPlanner(partial_mission)
        tasks = planner.plan()

        assert partial_mission.research_tasks == tasks
        assert len(partial_mission.research_queue) == len(tasks)
        assert len(partial_mission.coverage_gaps) > 0

    def test_get_next_task(self, partial_mission):
        planner = ResearchPlanner(partial_mission)
        planner.plan()
        next_task = planner.get_next_task()
        assert next_task is not None
        assert next_task.status == "PENDING"

    def test_deterministic_output(self, partial_mission):
        """Running the planner twice on the same state should produce the same result."""
        p1 = ResearchPlanner(partial_mission)
        tasks1 = p1.plan()

        p2 = ResearchPlanner(partial_mission)
        tasks2 = p2.plan()

        titles1 = [t.title for t in tasks1]
        titles2 = [t.title for t in tasks2]
        assert titles1 == titles2


# ─── CLI ───────────────────────────────────────────────────────────

class TestResearchCLI:
    def test_plan_command(self):
        result = runner.invoke(research_app, ["plan"])
        assert result.exit_code == 0
        assert "Research Queue" in result.stdout

    def test_queue_command(self):
        result = runner.invoke(research_app, ["queue"])
        assert result.exit_code == 0
        assert "Research Queue Order" in result.stdout

    def test_explain_command(self):
        result = runner.invoke(research_app, ["explain"])
        assert result.exit_code == 0
        assert "Research Plan Explanation" in result.stdout

    def test_coverage_command(self):
        result = runner.invoke(research_app, ["coverage"])
        assert result.exit_code == 0
        assert "Coverage Report" in result.stdout
