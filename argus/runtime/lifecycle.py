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
    def complete(mission: Mission, output_dir: str | None = None):
        if mission.status != MissionState.RUNNING:
            raise ValueError(f"Cannot complete mission from state {mission.status}")
        mission.status = MissionState.COMPLETED
        mission.phase = "finished"
        mission.updated_at = datetime.utcnow().isoformat()

        # Trigger report generation upon completion
        try:
            from argus.reporting.generator import ReportGenerator
            generator = ReportGenerator(output_dir=output_dir)
            report_paths = generator.generate_and_save(mission, output_dir=output_dir)
            for path in report_paths:
                if path not in mission.reports:
                    mission.reports.append(path)
        except Exception as e:
            import logging
            logging.getLogger(__name__).warning(f"Report generation failed during mission completion: {e}")

        # Post-scan Vector RAG Indexing of Findings & Evidence
        try:
            from argus.reporting.vector_indexer import ScanEvidenceIndexer
            indexer = ScanEvidenceIndexer()
            indexer.index_mission(mission)
        except Exception as e:
            import logging
            logging.getLogger(__name__).debug(f"Post-scan vector indexing skipped: {e}")


class TaskLifecycle:
    """Manages strict state machine transitions for a ScheduledTask."""

    @staticmethod
    def ready(task) -> None:
        from argus.runtime.models import TaskState
        if task.state not in (TaskState.PENDING, TaskState.BLOCKED):
            raise ValueError(f"Cannot transition to READY from {task.state}")
        task.state = TaskState.READY

    @staticmethod
    def start(task) -> None:
        from argus.runtime.models import TaskState
        from datetime import datetime, timezone
        if task.state != TaskState.READY:
            raise ValueError(f"Cannot start task from state {task.state}")
        task.state = TaskState.RUNNING
        task.started_at = datetime.now(timezone.utc).isoformat()

    @staticmethod
    def complete(task) -> None:
        from argus.runtime.models import TaskState
        from datetime import datetime, timezone
        if task.state != TaskState.RUNNING:
            raise ValueError(f"Cannot complete task from state {task.state}")
        task.state = TaskState.COMPLETED
        task.completed_at = datetime.now(timezone.utc).isoformat()

    @staticmethod
    def fail(task, error: str = "") -> None:
        from argus.runtime.models import TaskState
        from datetime import datetime, timezone
        if task.state != TaskState.RUNNING:
            raise ValueError(f"Cannot fail task from state {task.state}")
        task.state = TaskState.FAILED
        task.error = error
        task.completed_at = datetime.now(timezone.utc).isoformat()

    @staticmethod
    def skip(task) -> None:
        from argus.runtime.models import TaskState
        from datetime import datetime, timezone
        if task.state not in (TaskState.PENDING, TaskState.READY, TaskState.BLOCKED):
            raise ValueError(f"Cannot skip task from state {task.state}")
        task.state = TaskState.SKIPPED
        task.completed_at = datetime.now(timezone.utc).isoformat()

    @staticmethod
    def cancel(task) -> None:
        from argus.runtime.models import TaskState
        from datetime import datetime, timezone
        if task.state in (TaskState.COMPLETED, TaskState.FAILED, TaskState.SKIPPED, TaskState.CANCELLED):
            raise ValueError(f"Cannot cancel task that is already {task.state}")
        task.state = TaskState.CANCELLED
        task.completed_at = datetime.now(timezone.utc).isoformat()

