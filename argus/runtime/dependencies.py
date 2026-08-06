"""
Task Dependency Resolver.

Determines which scheduled tasks are ready to run based on dependency
completion. Blocked tasks automatically transition to READY when all
their dependencies reach COMPLETED state.
"""
import logging
from typing import List, Dict, Set
from argus.runtime.models import ScheduledTask, TaskState

logger = logging.getLogger(__name__)


class TaskDependencyResolver:
    """Resolves task dependencies and unblocks ready tasks."""

    @staticmethod
    def resolve(tasks: List[ScheduledTask]) -> List[ScheduledTask]:
        """
        Evaluate all tasks and transition PENDING/BLOCKED tasks to READY
        if their dependencies are fully satisfied.
        Returns the list of tasks that transitioned to READY.
        """
        title_map: Dict[str, ScheduledTask] = {t.task_title: t for t in tasks}
        completed_titles: Set[str] = {
            t.task_title for t in tasks if t.state == TaskState.COMPLETED
        }
        newly_ready: List[ScheduledTask] = []

        for task in tasks:
            if task.state not in (TaskState.PENDING, TaskState.BLOCKED):
                continue

            if not task.dependencies:
                # No dependencies — immediately ready
                if task.state != TaskState.READY:
                    task.state = TaskState.READY
                    newly_ready.append(task)
                    logger.info("Task ready (no deps): %s", task.task_title)
            else:
                # Check if all named dependencies are completed
                all_met = all(dep in completed_titles for dep in task.dependencies)
                if all_met:
                    task.state = TaskState.READY
                    newly_ready.append(task)
                    logger.info("Dependency resolved, task ready: %s", task.task_title)
                elif task.state != TaskState.BLOCKED:
                    task.state = TaskState.BLOCKED
                    logger.info("Task blocked (unmet deps): %s", task.task_title)

        return newly_ready

    @staticmethod
    def topological_order(tasks: List[ScheduledTask]) -> List[ScheduledTask]:
        """Return tasks in a valid topological execution order."""
        graph: Dict[str, List[str]] = {t.task_title: [] for t in tasks}
        in_degree: Dict[str, int] = {t.task_title: 0 for t in tasks}
        title_set = set(graph.keys())

        for task in tasks:
            for dep in task.dependencies:
                if dep in title_set:
                    graph[dep].append(task.task_title)
                    in_degree[task.task_title] += 1

        queue = sorted(
            [name for name, deg in in_degree.items() if deg == 0]
        )
        ordered_names: List[str] = []

        while queue:
            node = queue.pop(0)
            ordered_names.append(node)
            for neighbour in sorted(graph[node]):
                in_degree[neighbour] -= 1
                if in_degree[neighbour] == 0:
                    queue.append(neighbour)

        if len(ordered_names) != len(tasks):
            raise ValueError("Cyclic dependency detected in scheduled tasks.")

        title_to_task = {t.task_title: t for t in tasks}
        return [title_to_task[name] for name in ordered_names]
