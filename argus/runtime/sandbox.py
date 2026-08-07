import subprocess
import logging
from typing import List, Dict, Any
from argus.runtime.models import Tool, ToolExecutionContext

logger = logging.getLogger(__name__)


class SafetyViolationError(ValueError):
    """Exception raised when a tool execution violates scope or policy safety constraints."""
    pass


class SafetyValidator:
    """Validates targets, capabilities, permissions, and operations against Mission Scope and Policy."""

    @staticmethod
    def validate(tool: Tool, context: ToolExecutionContext):
        """
        Runs safety checks before tool execution.
        Raises SafetyViolationError if check fails.
        """
        mission = context.mission
        policy = context.policy or {}
        scope = context.scope or []

        # 1. Mission Scope Validation
        # Check target domain/IP. If scope list is empty, we permit it,
        # otherwise it must match or be a subdomain of one of the items in scope.
        target = getattr(mission, "target", "")
        if not target:
            target = getattr(context.task, "metadata", {}).get("target", "")

        if scope and target:
            is_in_scope = False
            for allowed in scope:
                if target == allowed or target.endswith(f".{allowed}"):
                    is_in_scope = True
                    break
            if not is_in_scope:
                raise SafetyViolationError(
                    f"Safety Violation: Target '{target}' is outside the mission scope: {scope}"
                )

        # 2. Blocked Operations (Mission Policy)
        # Check if the tool capability is blocked by policy
        blocked_ops = policy.get("blocked_operations", [])
        for cap in tool.capabilities:
            if cap in blocked_ops:
                raise SafetyViolationError(
                    f"Safety Violation: Tool capability '{cap}' is blocked by mission policy"
                )

        # Check if the task category is blocked
        blocked_categories = policy.get("blocked_categories", [])
        task_category = getattr(context.task, "category", None)
        task_category_str = task_category.value if hasattr(task_category, "value") else str(task_category)
        if task_category_str in blocked_categories:
            raise SafetyViolationError(
                f"Safety Violation: Task category '{task_category_str}' is blocked by mission policy"
            )

        # Check if the task name/title is explicitly blocked
        blocked_tasks = policy.get("blocked_tasks", [])
        task_title = getattr(context.task, "title", "")
        if task_title in blocked_tasks:
            raise SafetyViolationError(
                f"Safety Violation: Task '{task_title}' is explicitly blocked by mission policy"
            )

        # 3. Required capabilities
        # If the task requires specific capabilities, make sure the tool offers them
        task_metadata = getattr(context.task, "metadata", {}) or {}
        required_caps = task_metadata.get("required_capabilities", [])
        for cap in required_caps:
            if cap not in tool.capabilities:
                raise SafetyViolationError(
                    f"Safety Violation: Tool '{tool.name}' lacks required capability '{cap}' for this task"
                )

        # 4. Plugin permissions
        # If the tool declares permissions, check them against the allowed policy permissions
        allowed_permissions = policy.get("allowed_permissions", ["network", "filesystem", "db_read", "db_write"])
        tool_perms = tool.safety_requirements.get("permissions", [])
        for perm in tool_perms:
            if perm not in allowed_permissions:
                raise SafetyViolationError(
                    f"Safety Violation: Tool '{tool.name}' requests permission '{perm}' which is not allowed by policy"
                )

        logger.info(f"Safety checks passed for tool '{tool.name}' on task '{task_title}'")


class Sandbox:
    """Executes external commands inside a restricted sandbox environment."""

    def __init__(self, context: ToolExecutionContext = None):
        self.context = context

    def execute_command(self, executable: str, args: List[str], timeout: float = 300.0) -> Dict[str, Any]:
        """
        Runs the command using subprocess, enforcing the timeout.
        Raises TimeoutError if execution exceeds the timeout limit.
        """
        logger.info(f"Sandbox: Executing command '{executable}' with args {args} (timeout={timeout}s)")
        
        try:
            result = subprocess.run(
                [executable, *args],
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return {
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode
            }
        except subprocess.TimeoutExpired as e:
            logger.error(f"Sandbox Timeout: Command '{executable}' timed out after {timeout} seconds")
            raise TimeoutError(f"Command execution timed out after {timeout} seconds") from e
        except Exception as e:
            logger.error(f"Sandbox Error executing command: {e}")
            raise RuntimeError(f"Sandbox execution failed: {e}") from e
