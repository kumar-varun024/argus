import time
import logging
from typing import Dict, Any
from argus.runtime.models import ToolExecutionResult, ToolExecutionStatus

logger = logging.getLogger(__name__)


class ToolExecutionMonitor:
    """Monitors running tools, records execution duration and status, and logs lifecycle details."""

    def __init__(self):
        # Maps run_id to dict containing monitoring details
        self.active_runs: Dict[str, Dict[str, Any]] = {}

    def start_monitoring(self, run_id: str, tool_id: str, task_id: str):
        """Registers the start of a tool execution and begins duration tracking."""
        self.active_runs[run_id] = {
            "tool_id": tool_id,
            "task_id": task_id,
            "started_at": time.time(),
            "status": ToolExecutionStatus.RUNNING
        }
        logger.info(f"Monitor: Execution started for Tool: {tool_id}, Task: {task_id} (Run ID: {run_id})")

    def stop_monitoring(self, run_id: str, result: ToolExecutionResult):
        """Concludes monitoring for a run, logging durations, errors, and artifact summary."""
        if run_id not in self.active_runs:
            return

        run_info = self.active_runs[run_id]
        started_at = run_info["started_at"]
        duration_sec = time.time() - started_at
        
        # Update run info
        run_info["status"] = result.status
        run_info["completed_at"] = time.time()
        run_info["duration_seconds"] = duration_sec

        # Standard logging requirements:
        # Tool selected, Execution started, Execution completed, Execution failed, Artifacts stored, Execution duration
        if result.status == ToolExecutionStatus.SUCCEEDED:
            logger.info(
                f"Monitor: Execution completed successfully | Tool: {result.tool_id} | "
                f"Duration: {result.execution_time_ms:.2f}ms ({duration_sec:.2f}s)"
            )
            if result.artifacts:
                logger.info(f"Monitor: Artifacts stored successfully | Count: {len(result.artifacts)}")
        elif result.status == ToolExecutionStatus.TIMED_OUT:
            logger.warning(
                f"Monitor: Execution timed out | Tool: {result.tool_id} | "
                f"Duration limit exceeded after {duration_sec:.2f}s | Error: {result.error}"
            )
        elif result.status == ToolExecutionStatus.CANCELLED:
            logger.info(f"Monitor: Execution cancelled | Tool: {result.tool_id} | Task: {result.task_id}")
        else:
            logger.error(
                f"Monitor: Execution failed | Tool: {result.tool_id} | "
                f"Duration: {result.execution_time_ms:.2f}ms | Error: {result.error}"
            )

        # Remove from active list
        del self.active_runs[run_id]
