import json
import os
from datetime import datetime, timezone
from argus.runtime.mission import Mission

class MissionStorage:
    """Handles persistent storage of mission execution history, states, and metrics."""
    
    def __init__(self, storage_dir: str = ".argus/history"):
        self.storage_dir = storage_dir
        if not os.path.exists(self.storage_dir):
            os.makedirs(self.storage_dir, exist_ok=True)
            
    def _get_path(self, mission_id: str) -> str:
        return os.path.join(self.storage_dir, f"{mission_id}_history.json")

    def store(self, mission: Mission):
        """Archives the mission runtime state, metrics, and execution history."""
        data = {
            "id": mission.id,
            "target": mission.target,
            "status": mission.status.value,
            "phase": getattr(mission, "phase", ""),
            "created_at": mission.created_at,
            "updated_at": mission.updated_at,
            
            "runtime_metrics": mission.metrics,
            "execution_history": getattr(mission, "state_transitions", []),
            "checkpoints": getattr(mission, "checkpoints", []),
            "archived_at": datetime.now(timezone.utc).isoformat()
        }
        
        path = self._get_path(mission.id)
        with open(path, 'w') as f:
            json.dump(data, f, indent=2)
            
    def load(self, mission_id: str) -> dict:
        """Loads archived mission history."""
        path = self._get_path(mission_id)
        if not os.path.exists(path):
            raise FileNotFoundError(f"No history found for mission {mission_id}")
            
        with open(path, 'r') as f:
            return json.load(f)
