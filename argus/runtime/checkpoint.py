import os
import pickle
from enum import Enum
from typing import Dict, Callable, Optional, Any
from argus.runtime.mission import Mission, MissionState

class CheckpointAction(str, Enum):
    APPROVE = "APPROVE"
    REJECT = "REJECT"
    PAUSE = "PAUSE"
    MODIFY_PLAN = "MODIFY_PLAN"
    ABORT = "ABORT"

class MissionCheckpointer:
    """Handles serialization, recovery of Mission state, and logical checkpoints."""
    
    def __init__(self, storage_dir: str = ".argus/checkpoints"):
        self.storage_dir = storage_dir
        if not os.path.exists(self.storage_dir):
            os.makedirs(self.storage_dir, exist_ok=True)
        # Callbacks for specific logical checkpoints
        self.hooks: Dict[str, Callable[[Mission, Any], CheckpointAction]] = {}
            
    def _get_path(self, mission_id: str) -> str:
        return os.path.join(self.storage_dir, f"{mission_id}.ckpt")

    def checkpoint(self, mission: Mission):
        """Serializes the mission state to disk."""
        path = self._get_path(mission.id)
        with open(path, 'wb') as f:
            pickle.dump(mission, f)
            
    def recover(self, mission_id: str) -> Mission:
        """Loads a mission from a checkpoint to resume exactly where it stopped."""
        path = self._get_path(mission_id)
        if not os.path.exists(path):
            raise FileNotFoundError(f"No checkpoint found for mission {mission_id}")
            
        with open(path, 'rb') as f:
            mission = pickle.load(f)
            return mission

    def register_hook(self, name: str, callback: Callable[[Mission, Any], CheckpointAction]):
        """Register a logical checkpoint hook that requires human or policy approval."""
        self.hooks[name] = callback

    def evaluate_checkpoint(self, name: str, mission: Mission, context: Any = None) -> CheckpointAction:
        """Evaluate a logical checkpoint. Defaults to APPROVE if no hook is registered."""
        if name not in self.hooks:
            return CheckpointAction.APPROVE
        
        action = self.hooks[name](mission, context)
        
        # Track checkpoint evaluation in mission history
        if not hasattr(mission, "checkpoints"):
            mission.checkpoints = []
            
        mission.checkpoints.append({
            "name": name,
            "action": action.value,
            "context": str(context) if context else None
        })
        
        return action
