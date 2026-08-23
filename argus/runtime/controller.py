import logging
import threading
from typing import Dict, Optional, Any
from argus.runtime.mission import Mission, MissionState
from argus.runtime.state_machine import MissionStateMachine, TransitionError
from argus.runtime.mission_runtime import AutonomousMissionRuntime
from argus.runtime.checkpoint import MissionCheckpointer
from argus.runtime.recovery import RecoveryManager

# Core Engines
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

class MissionController:
    """Manages lifecycle and thread execution of missions via the autonomous runtime."""
    
    def __init__(self, checkpointer: MissionCheckpointer):
        self.checkpointer = checkpointer
        self.recovery_manager = RecoveryManager(checkpointer)
        self.active_runtimes: Dict[str, AutonomousMissionRuntime] = {}
        self.threads: Dict[str, threading.Thread] = {}
        
    def _create_runtime(self, mission: Mission) -> AutonomousMissionRuntime:
        state_machine = MissionStateMachine(mission)
        return AutonomousMissionRuntime(
            mission=mission,
            state_machine=state_machine,
            checkpointer=self.checkpointer,
            mission_planner=MissionPlanner(mission),
            research_planner=ResearchPlanner(mission),
            task_scheduler=TaskScheduler(mission),
            tool_orchestrator=ToolOrchestrator(),
            correlation_engine=CorrelationEngine(mission.observations, mission.correlations, mission.correlation_graph),
            fusion_engine=EvidenceFusionEngine(mission.observations, mission.correlations, mission.evidence_bundles),
            investigation_builder=InvestigationBuilder(mission.investigations, mission.evidence_bundles, mission.correlations, mission.observations),
            priority_engine=PriorityEngine(),
            hypothesis_engine=HypothesisEngine(getattr(mission, 'hypotheses', None)),
            learning_engine=LearningEngine()
        )

    def start(self, mission: Mission):
        """Starts a mission in a background thread."""
        if mission.id in self.threads and self.threads[mission.id].is_alive():
            raise RuntimeError(f"Mission {mission.id} is already running.")
            
        runtime = self._create_runtime(mission)
        
        if mission.status == MissionState.CREATED:
            runtime.state_machine.transition_to(MissionState.PLANNING, "Starting mission")
            
        self.active_runtimes[mission.id] = runtime
        
        thread = threading.Thread(target=runtime.run, name=f"Mission-{mission.id}")
        thread.daemon = True
        self.threads[mission.id] = thread
        thread.start()
        
        logger.info(f"Mission {mission.id} started in background thread.")

    def pause(self, mission: Mission):
        """Signals a mission to pause."""
        runtime = self.active_runtimes.get(mission.id)
        if runtime:
            runtime.state_machine.transition_to(MissionState.PAUSED, "User requested pause")
        else:
            MissionStateMachine(mission).transition_to(MissionState.PAUSED, "User requested pause")
            self.checkpointer.checkpoint(mission)

    def resume(self, mission: Mission):
        """Resumes a paused mission."""
        if mission.status not in (MissionState.PAUSED, MissionState.WAITING_FOR_APPROVAL):
            raise RuntimeError(f"Cannot resume mission from state {mission.status.value}")
            
        runtime = self._create_runtime(mission)
        state_machine = runtime.state_machine
        
        previous_state = MissionState.PLANNING
        if hasattr(mission, 'state_transitions') and mission.state_transitions:
            for transition in reversed(mission.state_transitions):
                if transition['to'] in (MissionState.PAUSED.value, MissionState.WAITING_FOR_APPROVAL.value):
                    try:
                        previous_state = MissionState(transition['from'])
                        break
                    except ValueError:
                        pass
        
        state_machine.transition_to(previous_state, "User requested resume")
        
        self.active_runtimes[mission.id] = runtime
        thread = threading.Thread(target=runtime.run, name=f"Mission-{mission.id}")
        thread.daemon = True
        self.threads[mission.id] = thread
        thread.start()

    def cancel(self, mission: Mission):
        """Cancels a mission."""
        runtime = self.active_runtimes.get(mission.id)
        if runtime:
            runtime.state_machine.transition_to(MissionState.CANCELLED, "User requested cancel")
        else:
            MissionStateMachine(mission).transition_to(MissionState.CANCELLED, "User requested cancel")
            self.checkpointer.checkpoint(mission)
            
    def recover(self, mission_id: str) -> Mission:
        """Recovers and returns a mission, but does not auto-start it."""
        return self.recovery_manager.recover_mission(mission_id)
