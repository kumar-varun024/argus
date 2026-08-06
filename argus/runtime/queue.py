"""
Execution Queue Manager.

Manages the queuing and retrieval of tasks for execution.
Ensures that concurrency limits are respected when dispensing READY tasks.
"""
import logging
from typing import List, Optional
from argus.runtime.models import ScheduledTask, TaskState, ExecutionQueue
from argus.runtime.dependencies import TaskDependencyResolver

logger = logging.getLogger(__name__)


class ExecutionQueueManager:
    """Manages the lifecycle of tasks within the execution queue."""

    def __init__(self, max_workers: int = 4):
        self.queue = ExecutionQueue(max_workers=max_workers)

    def add_tasks(self, tasks: List[ScheduledTask]):
        """Add a list of new tasks to the queue."""
        # Topologically sort to ensure sensible ordering
        ordered_tasks = TaskDependencyResolver.topological_order(tasks)
        
        # Determine which are immediately ready vs blocked
        for task in ordered_tasks:
            self.queue.tasks.append(task)
            
        # Run dependency resolution to update initial states
        TaskDependencyResolver.resolve(self.queue.tasks)

    def get_ready_tasks(self) -> List[ScheduledTask]:
        """
        Returns a list of READY tasks up to the available worker capacity.
        Does NOT change their state to RUNNING (that's the Executor's job).
        """
        # Resolve any newly unblocked dependencies before fetching
        TaskDependencyResolver.resolve(self.queue.tasks)

        available_capacity = self.queue.max_workers - self.queue.active_workers
        if available_capacity <= 0:
            return []

        ready_tasks = [t for t in self.queue.tasks if t.state == TaskState.READY]
        
        # Sort by priority descending
        ready_tasks.sort(key=lambda t: t.priority, reverse=True)
        
        return ready_tasks[:available_capacity]

    def increment_workers(self, count: int = 1):
        """Register that a worker has started executing a task."""
        self.queue.active_workers += count

    def decrement_workers(self, count: int = 1):
        """Register that a worker has finished executing a task."""
        self.queue.active_workers = max(0, self.queue.active_workers - count)

    def get_task(self, task_id: str) -> Optional[ScheduledTask]:
        """Retrieve a specific task by its ID."""
        for t in self.queue.tasks:
            if t.task_id == task_id or t.id == task_id:
                return t
        return None

    def is_complete(self) -> bool:
        """Returns True if all tasks have reached a terminal state (COMPLETED, FAILED, SKIPPED, CANCELLED)."""
        terminal_states = {TaskState.COMPLETED, TaskState.FAILED, TaskState.SKIPPED, TaskState.CANCELLED}
        return all(t.state in terminal_states for t in self.queue.tasks)
