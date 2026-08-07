from datetime import datetime
from typing import List, Dict, Optional
import logging
from argus.runtime.mission import Mission, MissionState

logger = logging.getLogger(__name__)

class TransitionError(Exception):
    pass

class MissionStateMachine:
    """Manages strict state machine transitions for a Mission."""
    
    def __init__(self, mission: Mission):
        self.mission = mission
        self._previous_state: Optional[MissionState] = None
        
        # Deterministic transition matrix
        self.valid_transitions = {
            MissionState.CREATED: [MissionState.PLANNING, MissionState.CANCELLED],
            MissionState.PLANNING: [
                MissionState.RESEARCHING, MissionState.PAUSED, 
                MissionState.CANCELLED, MissionState.FAILED
            ],
            MissionState.RESEARCHING: [
                MissionState.COLLECTING_EVIDENCE, MissionState.PLANNING,
                MissionState.WAITING_FOR_APPROVAL, MissionState.PAUSED, 
                MissionState.CANCELLED, MissionState.FAILED
            ],
            MissionState.COLLECTING_EVIDENCE: [
                MissionState.CORRELATING, MissionState.RESEARCHING, 
                MissionState.PAUSED, MissionState.CANCELLED, MissionState.FAILED
            ],
            MissionState.CORRELATING: [
                MissionState.BUILDING_INVESTIGATIONS, MissionState.RESEARCHING, 
                MissionState.PAUSED, MissionState.CANCELLED, MissionState.FAILED
            ],
            MissionState.BUILDING_INVESTIGATIONS: [
                MissionState.GENERATING_HYPOTHESES, MissionState.RESEARCHING, 
                MissionState.PAUSED, MissionState.CANCELLED, MissionState.FAILED
            ],
            MissionState.GENERATING_HYPOTHESES: [
                MissionState.WAITING_FOR_APPROVAL, MissionState.COMPLETED, 
                MissionState.RESEARCHING, MissionState.PAUSED, 
                MissionState.CANCELLED, MissionState.FAILED
            ],
            MissionState.WAITING_FOR_APPROVAL: [
                MissionState.PLANNING, MissionState.RESEARCHING, 
                MissionState.COMPLETED, MissionState.CANCELLED, MissionState.FAILED
            ],
            MissionState.PAUSED: [MissionState.RECOVERING, MissionState.CANCELLED],
            MissionState.RECOVERING: [
                MissionState.PLANNING, MissionState.RESEARCHING, 
                MissionState.COLLECTING_EVIDENCE, MissionState.CORRELATING, 
                MissionState.BUILDING_INVESTIGATIONS, MissionState.GENERATING_HYPOTHESES, 
                MissionState.FAILED, MissionState.CANCELLED
            ],
            MissionState.COMPLETED: [],
            MissionState.CANCELLED: [],
            MissionState.FAILED: [MissionState.RECOVERING]
        }
        
    def can_transition(self, target_state: MissionState) -> bool:
        """Check if a transition is valid from the current state."""
        return target_state in self.valid_transitions.get(self.mission.status, [])

    def transition_to(self, target_state: MissionState, reason: str = "") -> None:
        """Execute a state transition with validation and history tracking."""
        if not self.can_transition(target_state):
            raise TransitionError(f"Cannot transition from {self.mission.status.value} to {target_state.value}")
        
        now = datetime.utcnow().isoformat()
        
        transition_record = {
            "from": self.mission.status.value,
            "to": target_state.value,
            "reason": reason,
            "timestamp": now
        }
        
        if not hasattr(self.mission, "state_transitions"):
            self.mission.state_transitions = []
            
        self.mission.state_transitions.append(transition_record)
        
        self._previous_state = self.mission.status
        self.mission.status = target_state
        self.mission.updated_at = now
        
        logger.info(f"Mission {self.mission.id} transitioned {transition_record['from']} -> {transition_record['to']} (Reason: {reason})")
        
    def get_previous_state(self) -> Optional[MissionState]:
        return self._previous_state
