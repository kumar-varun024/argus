"""
Task Dependency Resolver.

Determines which scheduled tasks are ready to run based on dependency
completion. Blocked tasks automatically transition to READY when all
their dependencies reach COMPLETED state.
"""
import logging
from typing import List, Dict, Set
from argus.runtime.models import ScheduledTask, TaskState
from argus.runtime.lifecycle import TaskLifecycle

logger = logging.getLogger(__name__)


class TaskDependencyResolver:
    """Resolves task dependencies and unblocks ready tasks."""

    @staticmethod
    def resolve(tasks: List[ScheduledTask]) -> List[ScheduledTask]:
        """
        Evaluate all tasks and transition PENDING/BLOCKED tasks to READY
        if their dependencies are fully satisfied, or to SKIPPED if any dependency
        has reached FAILED, SKIPPED, or CANCELLED state.
        Returns the list of tasks that transitioned to READY.
        """
        newly_ready: List[ScheduledTask] = []
        changed = True

        while changed:
            changed = False
            title_map: Dict[str, ScheduledTask] = {}
            id_map: Dict[str, ScheduledTask] = {}
            for t in tasks:
                if t.task_title:
                    title_map[t.task_title] = t
                if t.task_id:
                    id_map[t.task_id] = t
                if getattr(t, 'id', None):
                    id_map[t.id] = t

            completed_identifiers: Set[str] = set()
            terminal_failure_identifiers: Set[str] = set()

            for t in tasks:
                if t.state == TaskState.COMPLETED:
                    if t.task_title:
                        completed_identifiers.add(t.task_title)
                    if t.task_id:
                        completed_identifiers.add(t.task_id)
                    if getattr(t, 'id', None):
                        completed_identifiers.add(t.id)
                elif t.state in (TaskState.FAILED, TaskState.SKIPPED, TaskState.CANCELLED):
                    if t.task_title:
                        terminal_failure_identifiers.add(t.task_title)
                    if t.task_id:
                        terminal_failure_identifiers.add(t.task_id)
                    if getattr(t, 'id', None):
                        terminal_failure_identifiers.add(t.id)

            for task in tasks:
                if task.state not in (TaskState.PENDING, TaskState.BLOCKED):
                    continue

                if not task.dependencies:
                    # No dependencies — immediately ready
                    if task.state != TaskState.READY:
                        TaskLifecycle.ready(task)
                        newly_ready.append(task)
                        changed = True
                        logger.info("Task ready (no deps): %s", task.task_title)
                else:
                    # Check if all named dependencies in the active queue are completed.
                    # External / non-queued prerequisites are treated as already satisfied.
                    active_deps = [
                        dep for dep in task.dependencies 
                        if dep in title_map or dep in id_map
                    ]

                    # If any dependency failed, was skipped, or was cancelled, skip this task
                    has_failed_dep = any(dep in terminal_failure_identifiers for dep in active_deps)
                    if has_failed_dep:
                        TaskLifecycle.skip(task)
                        changed = True
                        logger.info("Task skipped (dep failed/skipped/cancelled): %s", task.task_title)
                        continue

                    all_met = all(dep in completed_identifiers for dep in active_deps)
                    if all_met:
                        TaskLifecycle.ready(task)
                        newly_ready.append(task)
                        changed = True
                        logger.info("Dependency resolved, task ready: %s", task.task_title)
                    elif task.state != TaskState.BLOCKED:
                        task.state = TaskState.BLOCKED
                        changed = True
                        logger.info("Task blocked (unmet deps): %s", task.task_title)

        return newly_ready

    @staticmethod
    def topological_order(tasks: List[ScheduledTask]) -> List[ScheduledTask]:
        """Return tasks in a valid topological execution order."""
        id_to_task: Dict[str, ScheduledTask] = {}
        for t in tasks:
            if t.task_title:
                id_to_task[t.task_title] = t
            if t.task_id:
                id_to_task[t.task_id] = t
            if getattr(t, 'id', None):
                id_to_task[t.id] = t

        graph: Dict[str, List[str]] = {t.task_title: [] for t in tasks}
        in_degree: Dict[str, int] = {t.task_title: 0 for t in tasks}

        for task in tasks:
            for dep in task.dependencies:
                dep_task = id_to_task.get(dep)
                if dep_task and dep_task.task_title != task.task_title:
                    graph[dep_task.task_title].append(task.task_title)
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
