import threading
from typing import Optional
from argus.runtime.mission import Mission

class MissionContext:
    """Thread-safe context for accessing the currently active Mission."""
    
    _local = threading.local()

    @classmethod
    def set_active_mission(cls, mission: Mission):
        cls._local.active_mission = mission

    @classmethod
    def get_active_mission(cls) -> Optional[Mission]:
        return getattr(cls._local, 'active_mission', None)

    @classmethod
    def clear(cls):
        if hasattr(cls._local, 'active_mission'):
            del cls._local.active_mission
