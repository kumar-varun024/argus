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
from argus.runtime.scheduler import MissionScheduler
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
        task_scheduler: MissionScheduler, # or TaskScheduler
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
        if self.state_machine.can_transition(MissionState.PLANNING):
            self.state_machine.transition_to(MissionState.PLANNING, "Updating mission plan")
            self.mission_planner.analyze(mission)
            self.research_planner.plan(mission)
            
        # 2. Research Execution Phase
        if self.state_machine.can_transition(MissionState.RESEARCHING):
            self.state_machine.transition_to(MissionState.RESEARCHING, "Executing scheduled tasks")
            # Pull tasks and orchestrate them
            # This is a simplified block assuming batch processing per step
            # self.task_scheduler.step(mission) or orchestrator interaction
            self.task_scheduler.step(mission) # Assume scheduler pushes to orchestrator internally or we pull
            # Simulating orchestrator processing for this step
            
            # Here we evaluate a checkpoint before proceeding to analysis
            action = self.checkpointer.evaluate_checkpoint("post_execution", mission)
            if action == CheckpointAction.PAUSE:
                self.state_machine.transition_to(MissionState.WAITING_FOR_APPROVAL, "Paused by checkpoint")
                return
            elif action == CheckpointAction.ABORT:
                self.state_machine.transition_to(MissionState.CANCELLED, "Aborted by checkpoint")
                return

        # 3. Evidence Collection & Correlation
        if self.state_machine.can_transition(MissionState.COLLECTING_EVIDENCE):
            self.state_machine.transition_to(MissionState.COLLECTING_EVIDENCE, "Gathering observations")
            # Observations are gathered by orchestrator, now we correlate
            self.state_machine.transition_to(MissionState.CORRELATING, "Correlating evidence")
            self.correlation_engine.correlate_all(mission)
            self.fusion_engine.fuse(mission)

        # 4. Investigation & Hypothesis
        if self.state_machine.can_transition(MissionState.BUILDING_INVESTIGATIONS):
            self.state_machine.transition_to(MissionState.BUILDING_INVESTIGATIONS, "Building investigations")
            self.investigation_builder.build_all(mission)
            self.priority_engine.score_all(mission)

        if self.state_machine.can_transition(MissionState.GENERATING_HYPOTHESES):
            self.state_machine.transition_to(MissionState.GENERATING_HYPOTHESES, "Generating hypotheses")
            self.hypothesis_engine.evaluate_all(mission)

        # 5. Learning & Adaptation
        self.learning_engine.process_mission(mission)
        
        # Check Completion
        # This condition is highly domain specific (e.g. queue empty, time limit reached)
        is_complete = len(mission.research_queue) == 0 and mission.status != MissionState.CREATED
        
        if is_complete:
            action = self.checkpointer.evaluate_checkpoint("pre_completion", mission)
            if action == CheckpointAction.APPROVE:
                self.state_machine.transition_to(MissionState.COMPLETED, "Mission complete")
            elif action == CheckpointAction.MODIFY_PLAN:
                self.state_machine.transition_to(MissionState.PLANNING, "Checkpoint triggered replanning")
            else:
                self.state_machine.transition_to(MissionState.WAITING_FOR_APPROVAL, "Awaiting completion approval")

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
            except TransitionError:
                pass # Already terminal
        finally:
            self.checkpointer.checkpoint(self.context.mission)
            self.context.deactivate()
