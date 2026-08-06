"""
Task Scheduler Event Bus.

Emits and records events related to the execution lifecycle of tasks.
"""
import logging
from typing import List, Callable, Any
from argus.runtime.models import SchedulerEvent, EventType, ScheduledTask

logger = logging.getLogger(__name__)


class EventBus:
    """Publishes and subscribes to scheduler events."""

    def __init__(self):
        self.subscribers: List[Callable[[SchedulerEvent], None]] = []
        self.history: List[SchedulerEvent] = []

    def subscribe(self, callback: Callable[[SchedulerEvent], None]):
        """Register a callback for all events."""
        self.subscribers.append(callback)

    def publish(self, event_type: EventType, task: ScheduledTask, details: Any = None):
        """Create and publish an event to all subscribers."""
        event = SchedulerEvent(
            event_type=event_type,
            task_id=task.task_id,
            task_title=task.task_title,
            details=details or {}
        )
        self.history.append(event)
        
        for callback in self.subscribers:
            try:
                callback(event)
            except Exception as e:
                logger.error("Error in event subscriber: %s", e)
                
    def get_history(self) -> List[SchedulerEvent]:
        """Return the event history."""
        return self.history
