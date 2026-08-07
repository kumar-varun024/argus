import logging
from argus.runtime.mission import Mission, MissionState
from argus.runtime.state_machine import MissionStateMachine, TransitionError
from argus.runtime.checkpoint import MissionCheckpointer

logger = logging.getLogger(__name__)

class RecoveryManager:
    """Handles recovery of interrupted or failed missions."""
    
    def __init__(self, checkpointer: MissionCheckpointer):
        self.checkpointer = checkpointer

    def recover_mission(self, mission_id: str) -> Mission:
        """Loads a mission from the checkpoint and reverts it to a resumable state."""
        logger.info(f"Initiating recovery for mission {mission_id}")
        
        try:
            mission = self.checkpointer.recover(mission_id)
        except Exception as e:
            logger.error(f"Failed to load checkpoint for {mission_id}: {e}")
            raise e
            
        state_machine = MissionStateMachine(mission)
        
        try:
            if state_machine.can_transition(MissionState.RECOVERING):
                state_machine.transition_to(MissionState.RECOVERING, "Initiating recovery procedure")
        except TransitionError:
            pass # Might be PAUSED, which is fine to just leave as is
            
        # If we successfully transitioned to RECOVERING, we bounce back to an active state
        if mission.status == MissionState.RECOVERING:
            # Determine the safe state to resume from
            resume_state = MissionState.PLANNING
            if len(mission.research_queue) > 0:
                resume_state = MissionState.RESEARCHING
                
            try:
                state_machine.transition_to(resume_state, "Recovery complete, resuming")
            except TransitionError:
                logger.warning(f"Could not automatically resume from RECOVERING for mission {mission_id}")
                
        logger.info(f"Mission {mission_id} recovered. Current state: {mission.status.value}")
        return mission
