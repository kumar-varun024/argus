import time
from typing import Dict
from argus.runtime.mission import Mission

class MissionMetrics:
    """Tracks performance and operational metrics for a Mission."""

    @staticmethod
    def start_timer(mission: Mission, timer_name: str):
        if "timers" not in mission.metrics:
            mission.metrics["timers"] = {}
        mission.metrics["timers"][timer_name] = time.time()

    @staticmethod
    def stop_timer(mission: Mission, timer_name: str):
        if "timers" in mission.metrics and timer_name in mission.metrics["timers"]:
            start_time = mission.metrics["timers"].pop(timer_name)
            elapsed = time.time() - start_time
            
            if "durations" not in mission.metrics:
                mission.metrics["durations"] = {}
            mission.metrics["durations"][timer_name] = elapsed

    @staticmethod
    def increment_counter(mission: Mission, counter_name: str, amount: int = 1):
        if "counters" not in mission.metrics:
            mission.metrics["counters"] = {}
        
        current = mission.metrics["counters"].get(counter_name, 0)
        mission.metrics["counters"][counter_name] = current + amount

    @staticmethod
    def record_task_executed(mission: Mission):
        MissionMetrics.increment_counter(mission, "tasks_executed")

    @staticmethod
    def record_observation_produced(mission: Mission):
        MissionMetrics.increment_counter(mission, "observations_produced")

    @staticmethod
    def record_correlation_created(mission: Mission):
        MissionMetrics.increment_counter(mission, "correlations_created")
        
    @staticmethod
    def record_evidence_bundle(mission: Mission):
        MissionMetrics.increment_counter(mission, "evidence_bundles")

    @staticmethod
    def record_investigation(mission: Mission):
        MissionMetrics.increment_counter(mission, "investigations")

    @staticmethod
    def record_hypothesis(mission: Mission):
        MissionMetrics.increment_counter(mission, "hypotheses")
        
    @staticmethod
    def record_planner_update(mission: Mission):
        MissionMetrics.increment_counter(mission, "planner_updates")

    @staticmethod
    def record_checkpoint(mission: Mission):
        MissionMetrics.increment_counter(mission, "checkpoint_count")

    @staticmethod
    def record_recovery_event(mission: Mission):
        MissionMetrics.increment_counter(mission, "recovery_events")

    @staticmethod
    def get_summary(mission: Mission) -> Dict:
        return {
            "durations": mission.metrics.get("durations", {}),
            "counters": mission.metrics.get("counters", {})
        }
