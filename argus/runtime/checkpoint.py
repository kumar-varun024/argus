import os
import pickle
from argus.runtime.mission import Mission

class MissionCheckpointer:
    """Handles serialization and recovery of Mission state."""
    
    def __init__(self, storage_dir: str = ".argus/checkpoints"):
        self.storage_dir = storage_dir
        if not os.path.exists(self.storage_dir):
            os.makedirs(self.storage_dir, exist_ok=True)
            
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
