from datetime import datetime
from argus.runtime.mission import Mission, MissionState

class MissionLifecycle:
    """Manages strict state machine transitions for a Mission."""

    @staticmethod
    def create(target: str) -> Mission:
        return Mission(target=target, status=MissionState.CREATED)

    @staticmethod
    def start(mission: Mission):
        if mission.status not in (MissionState.CREATED, MissionState.READY):
            raise ValueError(f"Cannot start mission from state {mission.status}")
        mission.status = MissionState.RUNNING
        mission.updated_at = datetime.utcnow().isoformat()

    @staticmethod
    def pause(mission: Mission):
        if mission.status != MissionState.RUNNING:
            raise ValueError(f"Cannot pause mission from state {mission.status}")
        mission.status = MissionState.PAUSED
        mission.updated_at = datetime.utcnow().isoformat()

    @staticmethod
    def resume(mission: Mission):
        if mission.status != MissionState.PAUSED:
            raise ValueError(f"Cannot resume mission from state {mission.status}")
        mission.status = MissionState.RUNNING
        mission.updated_at = datetime.utcnow().isoformat()

    @staticmethod
    def cancel(mission: Mission):
        if mission.status in (MissionState.COMPLETED, MissionState.CANCELLED):
            raise ValueError(f"Cannot cancel a mission that is already {mission.status}")
        mission.status = MissionState.CANCELLED
        mission.updated_at = datetime.utcnow().isoformat()

    @staticmethod
    def complete(mission: Mission):
        if mission.status != MissionState.RUNNING:
            raise ValueError(f"Cannot complete mission from state {mission.status}")
        mission.status = MissionState.COMPLETED
        mission.phase = "finished"
        mission.updated_at = datetime.utcnow().isoformat()
