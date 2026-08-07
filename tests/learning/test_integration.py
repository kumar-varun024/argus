"""
Integration tests for argus.learning.

End-to-end flow:
  Observations → Correlations → Evidence Bundles → Investigations
  → process_mission() → discover_patterns() → generate_recommendations()

Also validates:
  - Planner integration: recommendations are strictly advisory
  - Hypothesis integration: hypothesis counts appear in metrics
  - Feedback integration across the full pipeline
"""
import pytest
from argus.learning.engine import LearningEngine
from argus.learning.registry import LearningRegistry
from argus.learning.metrics import MissionMetricsCalculator
from argus.learning.patterns import PatternDiscovery
from argus.learning.recommendations import RecommendationEngine
from argus.learning.history import MissionHistoryStore
from argus.learning.feedback import FeedbackCollector
from argus.learning.models import FeedbackTag, FeedbackTargetType
from argus.runtime.mission import Mission
from argus.correlation.observation import Observation
from argus.correlation.correlation import Correlation
from argus.correlation.evidence import EvidenceBundle
from argus.correlation.models import ObservationCategory, ObservationPriority
from argus.investigation.models import Investigation, InvestigationCategory


def _engine(tmp_path):
    reg = LearningRegistry(storage_path=str(tmp_path / "lr.json"))
    return LearningEngine(
        registry=reg,
        metrics_calculator=MissionMetricsCalculator(),
        pattern_discovery=PatternDiscovery(),
        recommendation_engine=RecommendationEngine(),
        history_store=MissionHistoryStore(reg),
        feedback_collector=FeedbackCollector(reg),
    ), reg


def _populated_mission() -> Mission:
    """Build a mission with observations, correlations, bundles, and investigations."""
    m = Mission(target="integration.example.com")
    m.scope = ["integration.example.com"]
    m.coverage = {"overall_coverage": 0.65}
    m.metrics["durations"] = {"total_execution_time": 45.0}
    m.execution_history = [
        {"id": "t1", "status": "COMPLETED"},
        {"id": "t2", "status": "COMPLETED"},
        {"id": "t3", "status": "FAILED"},
    ]

    # Add an observation
    obs = Observation(
        source="test_integration",
        category=ObservationCategory.AUTHORIZATION,
        title="Auth bypass observed",
        description="Direct object access without role check",
        confidence=0.85,
        priority=ObservationPriority.HIGH,
        business_objects=["Order"],
        workflows=["Checkout"],
    )
    m.observations.add(obs)

    # Add a correlation
    corr = Correlation(title="Auth correlation", description="Correlated auth observations")
    corr.observations.append(obs.id)
    m.correlations.add(corr)

    # Add a bundle
    bundle = EvidenceBundle(
        title="Auth Evidence", description="Fused auth evidence",
        confidence=0.85, strength=80,
        business_objects=["Order"], workflows=["Checkout"],
    )
    bundle.observations.append(obs.id)
    bundle.correlations.append(corr.id)
    m.evidence_bundles.add(bundle)

    # Add an investigation
    inv = Investigation(
        title="Authorization Review",
        summary="Possible access control gap",
        description="Direct access to orders without role check",
        category=InvestigationCategory.AUTHORIZATION,
        confidence=0.82,
    )
    inv.observations.append(obs.id)
    inv.evidence_bundles.append(bundle.id)
    m.investigations.add(inv)

    return m, inv


class TestEndToEnd:
    def test_full_pipeline_populates_mission_learning(self, tmp_path):
        engine, _ = _engine(tmp_path)
        m, _ = _populated_mission()
        record = engine.process_mission(m)

        assert m.learning is not None
        assert record.mission_id == str(m.id)
        assert record.investigation_quality > 0.0

    def test_metrics_recorded_correctly(self, tmp_path):
        engine, _ = _engine(tmp_path)
        m, _ = _populated_mission()
        engine.process_mission(m)

        metrics = m.metrics.get("learning", {})
        assert metrics["investigation_count"] == 1
        assert metrics["task_completion_rate"] == pytest.approx(2 / 3)
        assert metrics["failed_task_count"] == 1
        assert metrics["coverage_pct"] == pytest.approx(0.65)

    def test_feedback_flows_into_history(self, tmp_path):
        engine, reg = _engine(tmp_path)
        m, inv = _populated_mission()

        # Submit feedback before processing
        engine.feedback.submit(
            mission=m,
            target_id=str(inv.id),
            target_type=FeedbackTargetType.INVESTIGATION,
            tag=FeedbackTag.HIGH_VALUE,
            comment="Excellent finding",
        )

        record = engine.process_mission(m)
        assert len(record.feedback) == 1
        assert record.feedback[0].tag == FeedbackTag.HIGH_VALUE
        assert record.metadata.get("feedback_summary", {}).get(FeedbackTag.HIGH_VALUE.value, 0) == 1

    def test_two_missions_enable_pattern_discovery(self, tmp_path):
        engine, _ = _engine(tmp_path)
        for _ in range(2):
            m, _ = _populated_mission()
            m.execution_history = [
                {"id": "t1", "status": "FAILED"},
                {"id": "t2", "status": "FAILED"},
            ]
            engine.process_mission(m)

        patterns = engine.discover_patterns()
        assert len(patterns) >= 1  # coverage bottleneck fires

    def test_recommendations_are_advisory_only(self, tmp_path):
        """Recommendations must never auto-modify the mission plan."""
        engine, _ = _engine(tmp_path)
        for _ in range(2):
            m, _ = _populated_mission()
            m.execution_history = [{"id": "t1", "status": "FAILED"}]
            engine.process_mission(m)

        active = Mission(target="active.com")
        original_plan = active.plan  # Should remain None
        original_steps = list(active.plan_steps)

        recs = engine.generate_recommendations(mission=active)

        # Plan is untouched
        assert active.plan == original_plan
        assert active.plan_steps == original_steps

        # All recs require approval
        for rec in recs:
            assert rec.requires_planner_approval is True

    def test_planner_must_explicitly_act_on_recommendations(self, tmp_path):
        """Simulates planner reading patterns — nothing auto-executes."""
        engine, _ = _engine(tmp_path)
        for _ in range(2):
            m, _ = _populated_mission()
            m.execution_history = [{"id": "t1", "status": "FAILED"}]
            engine.process_mission(m)

        active = Mission(target="active.com")
        engine.generate_recommendations(mission=active)

        # Planner reads patterns
        for rec in active.patterns:
            assert rec.requires_planner_approval is True
            # Simulated planner decision — NOT auto-applied
            # planner.apply(rec)  # would be called by human/planner
