"""
Task Scheduler & Executors.

Orchestrates Research Tasks, determining execution order, resolving dependencies,
and handling task lifecycle transitions. Defines tool executors for executing
internal plugins, external command tools, and remote workers.
"""
import logging
import time
from abc import ABC, abstractmethod
from typing import List, Any, Optional
from datetime import datetime, timezone

from argus.planning.models import ResearchTask
from argus.runtime.models import ScheduledTask, TaskState, EventType, Tool, ToolExecutionResult, ToolExecutionStatus
from argus.runtime.queue import ExecutionQueueManager
from argus.runtime.events import EventBus
from argus.runtime.lifecycle import TaskLifecycle
from argus.runtime.retry import RetryHandler
from argus.runtime.sandbox import Sandbox
from argus.runtime.results import ResultCollector
from argus.evidence.model import Evidence

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
            task = self.queue_manager.get_task(event.task_id)
            if task:
                self.mission.task_states[event.task_id] = task.state.value

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


# =========================================================
# TOOL EXECUTORS (PR4 Sprint 11)
# =========================================================

class ToolExecutor(ABC):
    """Abstract Base Class for executing tools."""

    @abstractmethod
    def execute(self, tool: Tool, context: Any) -> ToolExecutionResult:
        """Executes the tool with the given context and returns a result."""
        pass


class InternalPluginExecutor(ToolExecutor):
    """Executes class-based internal plugins and specialist agents."""

    def execute(self, tool: Tool, context: Any) -> ToolExecutionResult:
        collector = ResultCollector(tool.id, context.task.id)
        collector.log(f"Executor: Launching internal specialist plugin '{tool.name}'")

        start_time = time.perf_counter()
        try:
            # Adapt and execute via PluginExecutorAdapter
            from argus.runtime.plugins import PluginExecutorAdapter
            adapter = PluginExecutorAdapter()
            exec_result = adapter.execute_plugin(tool.id, context.mission)
            
            execution_time_ms = (time.perf_counter() - start_time) * 1000.0
            
            # Post-execution output collection
            # Collect findings (observations/evidence) from the mission object
            mission = context.mission
            if hasattr(mission, "findings") and mission.findings:
                # Capture new observations appended during execution
                for finding in mission.findings:
                    collector.add_observation(finding)
            
            # Record plugin-specific metrics
            if hasattr(mission, "graphql") and mission.graphql:
                collector.add_metric("graphql_endpoints_discovered", len(mission.graphql.endpoints))
            if hasattr(mission, "subdomains") and mission.subdomains:
                collector.add_metric("subdomains_total", len(mission.subdomains))

            return collector.finalize(ToolExecutionStatus.SUCCEEDED, execution_time_ms)
        except Exception as e:
            execution_time_ms = (time.perf_counter() - start_time) * 1000.0
            logger.error(f"Executor: Internal plugin {tool.name} failed: {e}")
            return collector.finalize(ToolExecutionStatus.FAILED, execution_time_ms, error=str(e))


class ExternalToolExecutor(ToolExecutor):
    """Executes command-line binary tools within the sandbox."""

    def execute(self, tool: Tool, context: Any) -> ToolExecutionResult:
        collector = ResultCollector(tool.id, context.task.id)
        collector.log(f"Executor: Launching external tool command '{tool.command}'")

        # Resolve args based on the tool and target
        args = []
        target = getattr(context.mission, "target", "")
        if tool.id == "subfinder":
            args = ["-d", target, "-silent"]
        elif tool.id == "httpx":
            # Pass subdomains if already discovered, otherwise target
            subdomains = getattr(context.mission, "subdomains", [])
            if subdomains:
                args = ["-l", ",".join(subdomains)]
            else:
                args = ["-u", target]
        elif "katana" in tool.id:
            args = ["-u", target]
        else:
            args = [target]

        sandbox = Sandbox(context)
        start_time = time.perf_counter()
        try:
            # Run command inside Sandbox
            result = sandbox.execute_command(tool.command, args, timeout=tool.timeout)
            execution_time_ms = (time.perf_counter() - start_time) * 1000.0
            
            # Log standard output streams
            if result.get("stdout"):
                collector.log(result["stdout"])
            if result.get("stderr"):
                collector.log(result["stderr"])

            # Parse outputs into evidence store and mission attributes
            stdout = result.get("stdout", "")
            if tool.id == "subfinder":
                from argus.runtime.parser import ReconParser
                subdomains = ReconParser.parse_subfinder(stdout)
                
                # Update mission state
                context.mission.subdomains = subdomains
                collector.add_metric("subdomains_discovered", len(subdomains))

                # Store as evidence
                for sub in subdomains:
                    ev = Evidence(
                        category="subdomain",
                        value=sub,
                        source="subfinder",
                        description=f"Discovered subdomain {sub} for target {target}"
                    )
                    # Add to mission evidence store
                    if hasattr(context.mission, "evidence") and context.mission.evidence:
                        context.mission.evidence.add(ev)
                    collector.add_evidence(ev)

            return collector.finalize(ToolExecutionStatus.SUCCEEDED, execution_time_ms)
        except TimeoutError as e:
            execution_time_ms = (time.perf_counter() - start_time) * 1000.0
            logger.error(f"Executor: External tool {tool.name} execution timed out: {e}")
            return collector.finalize(ToolExecutionStatus.TIMED_OUT, execution_time_ms, error=str(e))
        except Exception as e:
            execution_time_ms = (time.perf_counter() - start_time) * 1000.0
            logger.error(f"Executor: External tool {tool.name} failed: {e}")
            return collector.finalize(ToolExecutionStatus.FAILED, execution_time_ms, error=str(e))


class RemoteWorkerExecutor(ToolExecutor):
    """Placeholder for executing tools on a remote worker node."""

    def execute(self, tool: Tool, context: Any) -> ToolExecutionResult:
        collector = ResultCollector(tool.id, context.task.id)
        collector.log(f"Executor: Simulating dispatch of tool '{tool.name}' to remote worker")
        
        start_time = time.perf_counter()
        # Mock remote latency
        time.sleep(0.05)
        execution_time_ms = (time.perf_counter() - start_time) * 1000.0

        collector.log(f"Executor: Remote worker returned successfully for tool '{tool.id}'")
        return collector.finalize(ToolExecutionStatus.SUCCEEDED, execution_time_ms)
