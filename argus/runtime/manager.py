import logging
from argus.runtime.mission import Mission, MissionState
from argus.runtime.lifecycle import MissionLifecycle
from argus.runtime.checkpoint import MissionCheckpointer
from argus.runtime.scheduler import MissionScheduler
from argus.runtime.context import MissionContext
from argus.runtime.metrics import MissionMetrics

logger = logging.getLogger(__name__)

class MissionManager:
    """Central orchestrator for the Mission Runtime."""
    
    def __init__(self, checkpointer: MissionCheckpointer = None, scheduler: MissionScheduler = None):
        self.checkpointer = checkpointer or MissionCheckpointer()
        self.scheduler = scheduler or MissionScheduler()
        self._active_missions = {}
        
    def create_mission(self, target: str) -> Mission:
        mission = MissionLifecycle.create(target)
        self._active_missions[mission.id] = mission
        self.checkpointer.checkpoint(mission)
        
        from argus.runtime.events import get_event_bus, RuntimeEventType
        get_event_bus().publish(RuntimeEventType.MISSION_CREATED, mission.id, details={"target": target})
        
        return mission

    def get_mission(self, mission_id: str) -> Mission:
        if mission_id in self._active_missions:
            return self._active_missions[mission_id]
        
        # Try to recover
        try:
            mission = self.checkpointer.recover(mission_id)
            self._active_missions[mission.id] = mission
            return mission
        except FileNotFoundError:
            return None

    def start_mission(self, mission_id: str):
        mission = self.get_mission(mission_id)
        MissionLifecycle.start(mission)
        self.checkpointer.checkpoint(mission)
        
        # Setup context and start scheduler
        MissionContext.set_active_mission(mission)
        MissionMetrics.start_timer(mission, "total_execution_time")
        try:
            self.scheduler.run_until_paused(mission)
        finally:
            self.checkpointer.checkpoint(mission)
            MissionContext.clear()

    def pause_mission(self, mission_id: str):
        mission = self.get_mission(mission_id)
        MissionLifecycle.pause(mission)
        self.checkpointer.checkpoint(mission)

    def resume_mission(self, mission_id: str):
        mission = self.get_mission(mission_id)
        MissionLifecycle.resume(mission)
        self.checkpointer.checkpoint(mission)
        
        MissionContext.set_active_mission(mission)
        try:
            self.scheduler.run_until_paused(mission)
        finally:
            self.checkpointer.checkpoint(mission)
            MissionContext.clear()

    def cancel_mission(self, mission_id: str):
        mission = self.get_mission(mission_id)
        MissionLifecycle.cancel(mission)
        self.checkpointer.checkpoint(mission)
        
    def list_missions(self):
        # Extremely basic listing of loaded missions. 
        # In a real app, you'd scan the .argus/checkpoints directory.
        import os
        missions = []
        if os.path.exists(self.checkpointer.storage_dir):
            for f in os.listdir(self.checkpointer.storage_dir):
                if f.endswith(".ckpt"):
                    try:
                        m_id = f.replace(".ckpt", "")
                        missions.append(self.get_mission(m_id))
                    except Exception as e:
                        logger.error(f"Failed to load mission {f}: {e}")
        return missions

# Global singleton
mission_manager = MissionManager()
