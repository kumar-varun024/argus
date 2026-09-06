"""Composition root for the autonomous mission runtime.

Single place that constructs :class:`AutonomousMissionRuntime` and all of its
injected engines. ``MissionController`` delegates here so mission lifecycle
management (its own responsibility) stays separate from dependency wiring.
Tests that need a fully wired runtime can call this instead of hand-assembling
a dozen engines.
"""
from argus.runtime.mission import Mission
from argus.runtime.state_machine import MissionStateMachine
from argus.runtime.mission_runtime import AutonomousMissionRuntime
from argus.runtime.checkpoint import MissionCheckpointer
from argus.planning.planner import MissionPlanner
from argus.planning.research_planner import ResearchPlanner
from argus.runtime.executor import TaskScheduler
from argus.runtime.orchestrator import ToolOrchestrator
from argus.correlation.engine import CorrelationEngine
from argus.correlation.fusion import EvidenceFusionEngine
from argus.investigation.builder import InvestigationBuilder
from argus.investigation.priority_engine import PriorityEngine
from argus.hypothesis.engine import HypothesisEngine
from argus.learning.engine import LearningEngine


def build_autonomous_runtime(
    mission: Mission,
    checkpointer: MissionCheckpointer,
) -> AutonomousMissionRuntime:
    """Wire a Mission and every research engine into an AutonomousMissionRuntime."""
    state_machine = MissionStateMachine(mission)
    return AutonomousMissionRuntime(
        mission=mission,
        state_machine=state_machine,
        checkpointer=checkpointer,
        mission_planner=MissionPlanner(mission),
        research_planner=ResearchPlanner(mission),
        task_scheduler=TaskScheduler(mission),
        tool_orchestrator=ToolOrchestrator(),
        correlation_engine=CorrelationEngine(
            mission.observations, mission.correlations, mission.correlation_graph
        ),
        fusion_engine=EvidenceFusionEngine(
            mission.observations, mission.correlations, mission.evidence_bundles
        ),
        investigation_builder=InvestigationBuilder(
            mission.investigations,
            mission.evidence_bundles,
            mission.correlations,
            mission.observations,
        ),
        priority_engine=PriorityEngine(),
        hypothesis_engine=HypothesisEngine(getattr(mission, "hypotheses", None)),
        learning_engine=LearningEngine(),
    )
