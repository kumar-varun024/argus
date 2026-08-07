import os
import json
import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from argus.runtime.mission import Mission
from argus.planning.models import ResearchTask
from argus.runtime.models import (
    Tool, ToolType, ToolExecutionStatus, ToolExecutionContext,
    ToolExecutionResult, OrchestratorEventType, OrchestratorEvent
)
from argus.runtime.registry import ToolRegistry, registry
from argus.runtime.dispatcher import ToolDispatcher
from argus.runtime.monitor import ToolExecutionMonitor
from argus.runtime.events import EventBus

logger = logging.getLogger(__name__)


class ToolOrchestrator:
    """
    The Tool Orchestrator resolves task categories to compatible tools/plugins,
    checks execution safety against mission policies/scopes, monitors duration,
    collects artifacts, and publishes lifecycle events.
    """

    def __init__(self, tool_registry: Optional[ToolRegistry] = None, event_bus: Optional[EventBus] = None):
        self.registry = tool_registry or registry
        self.dispatcher = ToolDispatcher(self.registry)
        self.monitor = ToolExecutionMonitor()
        self.event_bus = event_bus or EventBus()
        self._history_file = ".argus/tool_history.json"

        # Auto-subscribe logger callback
        self.event_bus.subscribe(self._on_event)

    def execute_task(self, mission: Mission, task: ResearchTask) -> ToolExecutionResult:
        """
        Executes a research task by deterministically selecting a tool, performing
        safety checks, and running/monitoring the execution.
        """
        logger.info(f"Orchestrator: Beginning execution sequence for task '{task.title}'")

        # 1. Deterministic Tool Resolution
        tool = self.dispatcher.resolve_tool(task)
        if not tool:
            err_msg = f"No compatible tool registered for task category: {task.category}"
            logger.error(err_msg)
            self._emit_event(OrchestratorEventType.TOOL_FAILED, task.id, "none", {"error": err_msg})
            return ToolExecutionResult(
                tool_id="none",
                task_id=task.id,
                status=ToolExecutionStatus.FAILED,
                error=err_msg,
                started_at=datetime.now(timezone.utc).isoformat(),
                completed_at=datetime.now(timezone.utc).isoformat()
            )

        # Log and emit selection event
        logger.info(f"Orchestrator: Tool selected '{tool.name}' (ID: {tool.id})")
        self._emit_event(OrchestratorEventType.TOOL_SELECTED, task.id, tool.id, {
            "tool_name": tool.name,
            "tool_version": tool.version
        })

        # 2. Context preparation
        context = ToolExecutionContext(
            mission=mission,
            scope=getattr(mission, "scope", []) or [],
            policy=getattr(mission, "policy", {}) or {},
            task=task,
            knowledge_graph=getattr(mission, "correlation_graph", None),
            workflow_graph=getattr(mission, "workflows", None),
            evidence_store=getattr(mission, "evidence", None),
            configuration=getattr(mission, "configuration", {}) or {}
        )

        # 3. Execution lifecycle monitoring setup
        run_id = f"run_{tool.id}_{task.id}_{int(time.time())}"
        self.monitor.start_monitoring(run_id, tool.id, task.id)
        self._emit_event(OrchestratorEventType.TOOL_STARTED, task.id, tool.id)

        start_time = time.perf_counter()
        result = None
        try:
            # 4. Dispatch execution
            result = self.dispatcher.dispatch(tool, context)
        except Exception as e:
            execution_time_ms = (time.perf_counter() - start_time) * 1000.0
            logger.error(f"Orchestrator: Tool execution raised unhandled exception: {e}")
            from argus.runtime.results import ResultCollector
            collector = ResultCollector(tool.id, task.id)
            result = collector.finalize(ToolExecutionStatus.FAILED, execution_time_ms, error=str(e))

        # 5. Conclude monitoring
        self.monitor.stop_monitoring(run_id, result)

        # 6. Emit corresponding completion status events
        if result.status == ToolExecutionStatus.SUCCEEDED:
            self._emit_event(
                OrchestratorEventType.TOOL_COMPLETED,
                task.id,
                tool.id,
                {"execution_time_ms": result.execution_time_ms}
            )
        elif result.status == ToolExecutionStatus.TIMED_OUT:
            self._emit_event(OrchestratorEventType.TOOL_TIMED_OUT, task.id, tool.id, {"error": result.error})
        elif result.status == ToolExecutionStatus.CANCELLED:
            self._emit_event(OrchestratorEventType.TOOL_CANCELLED, task.id, tool.id)
        else:
            self._emit_event(OrchestratorEventType.TOOL_FAILED, task.id, tool.id, {"error": result.error})

        if result.artifacts:
            self._emit_event(
                OrchestratorEventType.ARTIFACTS_PRODUCED,
                task.id,
                tool.id,
                {"count": len(result.artifacts)}
            )

        # 7. Persist outcome in mission storage fields
        self._store_in_mission(mission, result)

        # 8. Record in global persistent runs history file
        self._save_to_history(mission.id, result)

        return result

    def _emit_event(self, event_type: OrchestratorEventType, task_id: str, tool_id: str, details: Dict[str, Any] = None):
        """Helper to create and publish orchestrator events to the bus."""
        event = OrchestratorEvent(
            event_type=event_type,
            task_id=task_id,
            tool_id=tool_id,
            details=details or {}
        )
        for sub in self.event_bus.subscribers:
            try:
                sub(event)
            except Exception as e:
                logger.error(f"Orchestrator: Event subscriber callback crashed: {e}")

    def _on_event(self, event: Any):
        """Standard callback to write event to python logging streams."""
        if hasattr(event, "event_type"):
            logger.info(f"Orchestrator Event Bus: {event.event_type} | Task: {event.task_id} | Tool: {event.tool_id}")

    def _store_in_mission(self, mission: Mission, result: ToolExecutionResult):
        """Stores the run result, artifacts, and logs directly in the mission instance."""
        # Initialize storage attributes if missing
        if not hasattr(mission, "tool_runs") or mission.tool_runs is None:
            mission.tool_runs = {}
        if not hasattr(mission, "execution_results") or mission.execution_results is None:
            mission.execution_results = {}
        if not hasattr(mission, "execution_logs") or mission.execution_logs is None:
            mission.execution_logs = {}
        if not hasattr(mission, "artifacts") or mission.artifacts is None:
            mission.artifacts = []

        # Store tool run metadata
        mission.tool_runs[result.task_id] = {
            "tool_id": result.tool_id,
            "status": result.status.value,
            "started_at": result.started_at,
            "completed_at": result.completed_at,
            "execution_time_ms": result.execution_time_ms
        }

        # Store full execution result dict (serialized format)
        mission.execution_results[result.task_id] = result.model_dump()

        # Store execution logs
        mission.execution_logs[result.task_id] = result.logs

        # Append artifacts
        for art in result.artifacts:
            mission.artifacts.append(art.model_dump())

    def _save_to_history(self, mission_id: str, result: ToolExecutionResult):
        """Saves execution history to a shared global JSON file."""
        history = []
        os.makedirs(os.path.dirname(self._history_file), exist_ok=True)

        if os.path.exists(self._history_file):
            try:
                with open(self._history_file, 'r') as f:
                    history = json.load(f)
            except Exception:
                history = []

        history.append({
            "run_id": result.id,
            "mission_id": mission_id,
            "task_id": result.task_id,
            "tool_id": result.tool_id,
            "status": result.status.value,
            "started_at": result.started_at,
            "completed_at": result.completed_at,
            "execution_time_ms": result.execution_time_ms,
            "error": result.error
        })

        try:
            with open(self._history_file, 'w') as f:
                json.dump(history, f, indent=2)
        except Exception as e:
            logger.error(f"Orchestrator: Failed writing history JSON: {e}")
