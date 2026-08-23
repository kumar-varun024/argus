import logging
import time
from typing import Optional, Any
from argus.runtime.mission import Mission, MissionState
from argus.runtime.state_machine import MissionStateMachine, TransitionError
from argus.runtime.checkpoint import MissionCheckpointer, CheckpointAction
from argus.runtime.execution_context import ExecutionContext

# Domain Engines
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

logger = logging.getLogger(__name__)

class AutonomousMissionRuntime:
    """The central control loop orchestrating an Argus mission from start to finish."""

    def __init__(
        self,
        mission: Mission,
        state_machine: MissionStateMachine,
        checkpointer: MissionCheckpointer,
        mission_planner: MissionPlanner,
        research_planner: ResearchPlanner,
        task_scheduler: TaskScheduler,
        tool_orchestrator: ToolOrchestrator,
        correlation_engine: CorrelationEngine,
        fusion_engine: EvidenceFusionEngine,
        investigation_builder: InvestigationBuilder,
        priority_engine: PriorityEngine,
        hypothesis_engine: HypothesisEngine,
        learning_engine: LearningEngine
    ):
        self.context = ExecutionContext(mission)
        self.state_machine = state_machine
        self.checkpointer = checkpointer
        
        self.mission_planner = mission_planner
        self.research_planner = research_planner
        self.task_scheduler = task_scheduler
        self.tool_orchestrator = tool_orchestrator
        self.correlation_engine = correlation_engine
        self.fusion_engine = fusion_engine
        self.investigation_builder = investigation_builder
        self.priority_engine = priority_engine
        self.hypothesis_engine = hypothesis_engine
        self.learning_engine = learning_engine

    def step(self):
        """Executes a single iteration of the autonomous research loop."""
        mission = self.context.mission
        
        # 1. Planning Phase
        if mission.status == MissionState.PLANNING:
            self.mission_planner.analyze()
            self.research_planner.plan()
            self.state_machine.transition_to(MissionState.RESEARCHING, "Executing scheduled tasks")
            return
            
        # 2. Research Execution Phase
        elif mission.status == MissionState.RESEARCHING:
            # Queue new pending tasks
            if hasattr(mission, "research_tasks") and mission.research_tasks:
                pending = [t for t in mission.research_tasks if t.status == "PENDING"]
                if pending:
                    self.task_scheduler.schedule_tasks(pending)
                    for t in pending:
                        t.status = "SCHEDULED"

            # Execute a batch
            batch = self.task_scheduler.get_executable_batch() or []
            
            from argus.runtime.models import ToolExecutionStatus
            for scheduled_task in batch:
                rt = next((t for t in mission.research_tasks if t.id == scheduled_task.task_id), None)
                if rt:
                    try:
                        result = self.tool_orchestrator.execute_task(mission, rt)
                        if result.status == ToolExecutionStatus.SUCCEEDED:
                            self.task_scheduler.report_success(rt.id)
                            rt.status = "COMPLETED"
                        else:
                            self.task_scheduler.report_failure(rt.id, result.error)
                            rt.status = "FAILED"
                    except Exception as e:
                        logger.error(f"Task {rt.id} failed: {e}")
                        self.task_scheduler.report_failure(rt.id, str(e))
                        rt.status = "FAILED"

            # Evaluate a checkpoint before proceeding to analysis
            action = self.checkpointer.evaluate_checkpoint("post_execution", mission)
            if action == CheckpointAction.PAUSE:
                self.state_machine.transition_to(MissionState.WAITING_FOR_APPROVAL, "Paused by checkpoint")
                return
            elif action == CheckpointAction.ABORT:
                self.state_machine.transition_to(MissionState.CANCELLED, "Aborted by checkpoint")
                return
            
            # If no tasks are running and everything is complete, move to next phase
            if not batch and self.task_scheduler.queue_manager.is_complete():
                self.state_machine.transition_to(MissionState.COLLECTING_EVIDENCE, "Finished executing tasks")
            return

        # 3. Evidence Collection & Correlation
        elif mission.status == MissionState.COLLECTING_EVIDENCE:
            self.state_machine.transition_to(MissionState.CORRELATING, "Correlating evidence")
            return
            
        elif mission.status == MissionState.CORRELATING:
            from argus.correlation.observation import Observation
            from argus.correlation.models import ObservationCategory, ObservationPriority
            
            if hasattr(mission, "evidence") and mission.evidence:
                if not hasattr(mission, "_correlated_evidence_ids"):
                    mission._correlated_evidence_ids = set()
                    
                for ev in mission.evidence.all():
                    if ev.evidence_id not in mission._correlated_evidence_ids:
                        obs = Observation(
                            source="evidence_collector",
                            category=ObservationCategory.TECHNOLOGY,
                            title=f"Evidence: {ev.category}",
                            description=ev.description or str(ev.value),
                            confidence=0.8,
                            priority=ObservationPriority.MEDIUM,
                            evidence=[ev]
                        )
                        self.correlation_engine.process_observation(obs)
                        mission._correlated_evidence_ids.add(ev.evidence_id)
            
            if hasattr(mission, "findings"):
                for finding in mission.findings:
                    if not getattr(finding, "_correlated", False):
                        if isinstance(finding, Observation):
                            self.correlation_engine.process_observation(finding)
                        finding._correlated = True
            
            self.fusion_engine.process_mission_state()
            self.state_machine.transition_to(MissionState.BUILDING_INVESTIGATIONS, "Building investigations")
            return

        # 4. Investigation & Hypothesis
        elif mission.status == MissionState.BUILDING_INVESTIGATIONS:
            from argus.runtime.events import EventBus, RuntimeEventType
            EventBus().publish(RuntimeEventType.INVESTIGATION_STARTED, mission.id)
            self.investigation_builder.build_all()
            self.investigation_builder.prioritize_all(mission)
            self.state_machine.transition_to(MissionState.GENERATING_HYPOTHESES, "Generating hypotheses")
            return

        elif mission.status == MissionState.GENERATING_HYPOTHESES:
            self.hypothesis_engine.evaluate_all(mission)
            self.learning_engine.process_mission(mission)
            
            # Check Completion
            # If we reached GENERATING_HYPOTHESES and queue is empty, we are basically done.
            if self.task_scheduler.queue_manager.is_complete():
                action = self.checkpointer.evaluate_checkpoint("pre_completion", mission)
                if action == CheckpointAction.APPROVE:
                    self.state_machine.transition_to(MissionState.COMPLETED, "Mission complete")
                    from argus.runtime.events import EventBus, RuntimeEventType
                    EventBus().publish(RuntimeEventType.MISSION_COMPLETED, mission.id)
                elif action == CheckpointAction.MODIFY_PLAN:
                    self.state_machine.transition_to(MissionState.PLANNING, "Checkpoint triggered replanning")
                else:
                    self.state_machine.transition_to(MissionState.WAITING_FOR_APPROVAL, "Awaiting completion approval")
            else:
                # If there are somehow more tasks generated, loop back
                self.state_machine.transition_to(MissionState.RESEARCHING, "More tasks to execute")
            return

    def run(self):
        """Runs the mission loop continuously until a terminal or paused state is reached."""
        self.context.activate()
        try:
            while self.context.mission.status not in (
                MissionState.COMPLETED, 
                MissionState.CANCELLED, 
                MissionState.FAILED, 
                MissionState.PAUSED,
                MissionState.WAITING_FOR_APPROVAL
            ):
                self.step()
                time.sleep(1) # Prevent tight spinning if no tasks are available
        except Exception as e:
            logger.error(f"Mission {self.context.mission.id} failed unexpectedly: {e}", exc_info=True)
            try:
                self.state_machine.transition_to(MissionState.FAILED, str(e))
                from argus.runtime.events import EventBus, RuntimeEventType
                EventBus().publish(RuntimeEventType.MISSION_FAILED, self.context.mission.id, details={"error": str(e)})
            except TransitionError:
                pass # Already terminal
        finally:
            self.checkpointer.checkpoint(self.context.mission)
            self.context.deactivate()
