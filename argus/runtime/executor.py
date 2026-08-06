"""
Task Scheduler.

Orchestrates Research Tasks, determining execution order, resolving dependencies,
and handling task lifecycle transitions. It does NOT execute tools directly, but
schedules them for the runtime.
"""
import logging
from typing import List, Any
from argus.planning.models import ResearchTask
from argus.runtime.models import ScheduledTask, TaskState, EventType
from argus.runtime.queue import ExecutionQueueManager
from argus.runtime.events import EventBus
from argus.runtime.lifecycle import TaskLifecycle
from argus.runtime.retry import RetryHandler

logger = logging.getLogger(__name__)


class TaskScheduler:
    """Schedules and coordinates the lifecycle of ResearchTasks."""

    def __init__(self, mission: Any, max_workers: int = 4):
        self.mission = mission
        self.queue_manager = ExecutionQueueManager(max_workers=max_workers)
        self.event_bus = EventBus()

        # Subscribe mission storage to events
        self.event_bus.subscribe(self._update_mission_storage)

    def schedule_tasks(self, research_tasks: List[ResearchTask]):
        """Convert ResearchTasks to ScheduledTasks and add them to the queue."""
        scheduled_tasks = []
        for rt in research_tasks:
            # Policy check could happen here, though Planner usually does it.
            # Convert to ScheduledTask
            st = ScheduledTask(
                task_id=rt.id,
                task_title=rt.title,
                priority=rt.priority,
                dependencies=rt.dependencies,
            )
            scheduled_tasks.append(st)

        self.queue_manager.add_tasks(scheduled_tasks)
        
        for st in scheduled_tasks:
            self.event_bus.publish(EventType.TASK_SCHEDULED, st)

    def get_executable_batch(self) -> List[ScheduledTask]:
        """
        Retrieves a batch of READY tasks that can be executed concurrently.
        Marks them as RUNNING and increments the active worker count.
        """
        ready_tasks = self.queue_manager.get_ready_tasks()
        
        for task in ready_tasks:
            TaskLifecycle.start(task)
            self.queue_manager.increment_workers()
            self.event_bus.publish(EventType.TASK_STARTED, task)
            logger.info("Started task: %s", task.task_title)
            
        return ready_tasks

    def report_success(self, task_id: str):
        """Report that a running task has completed successfully."""
        task = self.queue_manager.get_task(task_id)
        if not task:
            logger.error("report_success: Task %s not found", task_id)
            return

        TaskLifecycle.complete(task)
        self.queue_manager.decrement_workers()
        self.event_bus.publish(EventType.TASK_COMPLETED, task)
        logger.info("Completed task: %s", task.task_title)

    def report_failure(self, task_id: str, error: str, is_timeout: bool = False, is_plugin_failure: bool = False):
        """Report that a running task has failed, applying retry policy."""
        task = self.queue_manager.get_task(task_id)
        if not task:
            logger.error("report_failure: Task %s not found", task_id)
            return

        self.queue_manager.decrement_workers()
        
        will_retry = RetryHandler.handle_failure(
            task, error, is_timeout=is_timeout, is_plugin_failure=is_plugin_failure
        )
        
        if will_retry:
            self.event_bus.publish(EventType.TASK_RETRIED, task, details={"error": error})
        else:
            self.event_bus.publish(EventType.TASK_FAILED, task, details={"error": error})

    def cancel_task(self, task_id: str):
        """Cancel a pending or ready task."""
        task = self.queue_manager.get_task(task_id)
        if not task:
            return
            
        TaskLifecycle.cancel(task)
        self.event_bus.publish(EventType.TASK_CANCELLED, task)

    def _update_mission_storage(self, event):
        """Synchronize the execution queue state to the mission."""
        if hasattr(self.mission, 'execution_queue'):
            # Convert ExecutionQueue to dict for storage
            self.mission.execution_queue = self.queue_manager.queue.model_dump()
            
        if hasattr(self.mission, 'execution_history'):
            if not getattr(self.mission, 'execution_history'):
                self.mission.execution_history = []
            self.mission.execution_history.append(event.model_dump())
            
        if hasattr(self.mission, 'task_states'):
            if not getattr(self.mission, 'task_states'):
                self.mission.task_states = {}
            self.mission.task_states[event.task_id] = self.queue_manager.get_task(event.task_id).state.value

        if hasattr(self.mission, 'retry_history') and event.event_type == EventType.TASK_RETRIED:
            if not getattr(self.mission, 'retry_history'):
                self.mission.retry_history = []
            task = self.queue_manager.get_task(event.task_id)
            if task and task.retry_history:
                self.mission.retry_history.append({
                    "task_id": task.task_id,
                    "task_title": task.task_title,
                    "record": task.retry_history[-1].model_dump()
                })
