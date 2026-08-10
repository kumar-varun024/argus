"""
Mission Runtime Event Bus.

Emits and records events related to the full execution lifecycle of a mission,
including planning, scheduling, orchestration, correlation, and hypotheses.
"""
import logging
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import List, Callable, Any, Dict
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

class RuntimeEventType(str, Enum):
    """Events emitted by the autonomous mission runtime."""
    MISSION_STARTED = "MissionStarted"
    MISSION_PAUSED = "MissionPaused"
    MISSION_RESUMED = "MissionResumed"
    MISSION_COMPLETED = "MissionCompleted"
    MISSION_CANCELLED = "MissionCancelled"
    MISSION_FAILED = "MissionFailed"
    CHECKPOINT_REACHED = "CheckpointReached"
    PLAN_UPDATED = "PlanUpdated"
    TASK_SCHEDULED = "TaskScheduled"
    TASK_STARTED = "TaskStarted"
    TASK_COMPLETED = "TaskCompleted"
    TASK_FAILED = "TaskFailed"
    TASK_RETRIED = "TaskRetried"
    TASK_CANCELLED = "TaskCancelled"
    OBSERVATION_ADDED = "ObservationAdded"
    CORRELATION_CREATED = "CorrelationCreated"
    EVIDENCE_BUNDLE_CREATED = "EvidenceBundleCreated"
    INVESTIGATION_CREATED = "InvestigationCreated"
    HYPOTHESIS_UPDATED = "HypothesisUpdated"

class RuntimeEvent(BaseModel):
    """An event emitted across the Argus platform."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_type: RuntimeEventType
    mission_id: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    details: Dict[str, Any] = Field(default_factory=dict)

class EventBus:
    """Publishes and subscribes to runtime events."""

    def __init__(self):
        self.subscribers: List[Callable[[RuntimeEvent], None]] = []
        self.history: List[RuntimeEvent] = []

    def subscribe(self, callback: Callable[[RuntimeEvent], None]):
        """Register a callback for all events."""
        self.subscribers.append(callback)

    def publish(self, event_type: RuntimeEventType, mission_id: str, details: Any = None):
        """Create and publish an event to all subscribers."""
        event = RuntimeEvent(
            event_type=event_type,
            mission_id=mission_id,
            details=details or {}
        )
        self.history.append(event)
        
        for callback in self.subscribers:
            try:
                callback(event)
            except Exception as e:
                logger.error("Error in event subscriber: %s", e)
                
    def get_history(self) -> List[RuntimeEvent]:
        """Return the event history."""
        return self.history
