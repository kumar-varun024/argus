"""
Task Retry Handler.

Manages task failure recovery by applying the retry policy.
Determines whether a task should be retried or transitioned to a terminal FAILED state.
"""
import logging
from argus.runtime.models import ScheduledTask, TaskState, RetryRecord
from argus.runtime.lifecycle import TaskLifecycle

logger = logging.getLogger(__name__)


class RetryHandler:
    """Handles task failure logic according to its RetryPolicy."""

    @staticmethod
    def handle_failure(task: ScheduledTask, error: str, is_timeout: bool = False, is_plugin_failure: bool = False) -> bool:
        """
        Process a failure for the given task.
        Returns True if the task will be retried, False if it has terminally failed.
        """
        policy = task.retry_policy

        # Check conditions for retry based on error type
        if is_timeout and not policy.retry_on_timeout:
            logger.warning("Task %s failed due to timeout, policy disallows retry.", task.task_title)
            TaskLifecycle.fail(task, error)
            return False

        if is_plugin_failure and not policy.retry_on_plugin_failure:
            logger.warning("Task %s failed due to plugin error, policy disallows retry.", task.task_title)
            TaskLifecycle.fail(task, error)
            return False

        # Check max retries
        if task.retry_count >= policy.max_retries:
            logger.warning("Task %s reached max retries (%d). Marking as FAILED.", task.task_title, policy.max_retries)
            TaskLifecycle.fail(task, error)
            return False

        # Apply retry
        task.retry_count += 1
        record = RetryRecord(attempt=task.retry_count, error=error)
        task.retry_history.append(record)

        # Transition state back to READY
        # In a real async system we might delay this by `policy.backoff_seconds * (policy.backoff_multiplier ** (task.retry_count - 1))`
        # but for the scheduler state machine, READY means it is eligible to be picked up again.
        task.state = TaskState.READY
        # Reset started_at / completed_at for the next attempt
        task.started_at = None
        task.completed_at = None
        task.error = None
        
        logger.info("Task %s scheduled for retry %d/%d.", task.task_title, task.retry_count, policy.max_retries)
        return True
