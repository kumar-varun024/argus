from argus.runtime.mission import Mission, MissionState
from typing import Callable, List, Dict
import logging

logger = logging.getLogger(__name__)

class MissionScheduler:
    """
    Coordinates the high-level phases of the mission:
    Recon -> Graph -> AI -> Planner -> Agents -> Execution -> Reports
    """
    
    PHASES = [
        "planning",
        "recon",
        "intelligence",
        "graph",
        "ai",
        "planner",
        "agents",
        "execution",
        "reporting",
        "finished"
    ]
    
    def __init__(self):
        self._handlers: Dict[str, Callable[[Mission], None]] = {}

    def register_phase_handler(self, phase: str, handler: Callable[[Mission], None]):
        """Register a callback to be executed for a specific phase."""
        if phase not in self.PHASES:
            raise ValueError(f"Unknown phase: {phase}")
        self._handlers[phase] = handler

    def step(self, mission: Mission):
        """Advances the mission by executing the current phase."""
        if mission.status != MissionState.RUNNING:
            logger.warning(f"Scheduler paused: Mission {mission.id} is in state {mission.status}")
            return
            
        current_phase = mission.phase
        logger.info(f"Executing phase: {current_phase}")
        
        handler = self._handlers.get(current_phase)
        if handler:
            try:
                handler(mission)
            except Exception as e:
                logger.error(f"Phase {current_phase} failed: {e}")
                mission.status = MissionState.FAILED
                return
                
        self._advance_phase(mission)

    def _advance_phase(self, mission: Mission):
        """Moves mission.phase to the next phase in the predefined list."""
        try:
            current_index = self.PHASES.index(mission.phase)
            next_index = current_index + 1
            if next_index < len(self.PHASES):
                mission.phase = self.PHASES[next_index]
            else:
                mission.status = MissionState.COMPLETED
        except ValueError:
            logger.error(f"Invalid current phase '{mission.phase}'. Resetting to finished.")
            mission.phase = "finished"
            mission.status = MissionState.COMPLETED

    def run_until_paused(self, mission: Mission):
        """Continuously steps the mission until it finishes, fails, or is paused."""
        while mission.status == MissionState.RUNNING and mission.phase != "finished":
            self.step(mission)
