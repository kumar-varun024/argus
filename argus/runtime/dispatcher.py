import logging
from typing import Any, Optional
from argus.runtime.models import Tool, ToolType, ToolExecutionResult
from argus.runtime.registry import ToolRegistry, registry
from argus.runtime.sandbox import SafetyValidator

logger = logging.getLogger(__name__)


class ToolDispatcher:
    """Selects and routes tool executions to internal, external, or remote execution engines."""

    def __init__(self, tool_registry: ToolRegistry = None):
        self.registry = tool_registry or registry

    def resolve_tool(self, task: Any) -> Optional[Tool]:
        """
        Determines the best compatible tool for the given task.
        Sorts multiple compatible candidates deterministically.
        """
        # Resolve task category string
        category = getattr(task, "category", None)
        category_name = category.value if hasattr(category, "value") else str(category)
        # Explicit tool requested by the planner.
        metadata = getattr(task, "metadata", {}) or {}
        requested_tool_id = metadata.get("tool_id") if isinstance(metadata, dict) else None
        
        if requested_tool_id:
            tool = self.registry.get(requested_tool_id)
            
            if tool:
                logger.info(
                    f"Dispatcher: Task explicitly requested "
                    f"tool '{requested_tool_id}'"
                )
                return tool
                
            logger.warning(
                f"Dispatcher: Requested tool '{requested_tool_id}' "
                f"was not found in registry"
            )

        # Check required specialists in task metadata/specialists list
        required_specialists = getattr(task, "required_specialists", []) or []
        for spec in required_specialists:
            tool = self.registry.get(spec)
            if tool:
                logger.info(f"Dispatcher: Matched required specialist '{spec}' to tool '{tool.id}'")
                return tool

        # Find compatible candidates sorted by priority descending and id alphabetically
        candidates = self.registry.find_compatible_tools(category_name)
        if not candidates:
            logger.warning(f"Dispatcher: No compatible tools registered for category '{category_name}'")
            return None

        # Return the top candidate (highest priority, deterministic fallback)
        selected = candidates[0]
        logger.info(
            f"Dispatcher: Resolved task '{task.title}' ({category_name}) "
            f"to tool '{selected.name}' (ID: {selected.id})"
        )
        return selected

    def dispatch(self, tool: Tool, context: Any) -> ToolExecutionResult:
        """
        Validates safety requirements and routes the execution to the appropriate executor.
        """
        # 1. Pre-execution safety validation
        SafetyValidator.validate(tool, context)

        # 2. Determine execution routing
        tool_type = tool.safety_requirements.get("type", ToolType.EXTERNAL)

        # Import executors here to avoid circular dependencies
        from argus.runtime.executor import (
            InternalPluginExecutor,
            ExternalToolExecutor,
            RemoteWorkerExecutor
        )

        logger.info(f"Dispatcher: Routing tool '{tool.id}' to {tool_type} executor")

        if tool_type == ToolType.INTERNAL or tool.id.endswith("specialist"):
            executor = InternalPluginExecutor()
        elif tool_type == ToolType.REMOTE:
            executor = RemoteWorkerExecutor()
        else:
            executor = ExternalToolExecutor()

        return executor.execute(tool, context)
