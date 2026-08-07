"""
Task Scheduler Models.

Defines the task lifecycle states, scheduled task wrappers, retry policies,
execution events, and the execution queue used by the Task Scheduler.
"""
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from enum import Enum
from pydantic import BaseModel, Field


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class TaskState(str, Enum):
    """Lifecycle states for a scheduled task."""
    PENDING = "PENDING"
    READY = "READY"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"
    SKIPPED = "SKIPPED"
    CANCELLED = "CANCELLED"


class EventType(str, Enum):
    """Types of events emitted by the scheduler."""
    TASK_SCHEDULED = "TaskScheduled"
    TASK_STARTED = "TaskStarted"
    TASK_COMPLETED = "TaskCompleted"
    TASK_FAILED = "TaskFailed"
    TASK_RETRIED = "TaskRetried"
    TASK_CANCELLED = "TaskCancelled"


class RetryPolicy(BaseModel):
    """Configurable retry policy for a task."""
    max_retries: int = 3
    backoff_seconds: float = 1.0
    backoff_multiplier: float = 2.0
    retry_on_timeout: bool = True
    retry_on_plugin_failure: bool = True


class RetryRecord(BaseModel):
    """Record of a single retry attempt."""
    attempt: int
    timestamp: str = Field(default_factory=_utc_now)
    error: str = ""


class ScheduledTask(BaseModel):
    """A ResearchTask wrapped with scheduling metadata."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    task_id: str
    task_title: str
    state: TaskState = TaskState.PENDING
    priority: float = 0.5
    dependencies: List[str] = Field(default_factory=list)
    retry_policy: RetryPolicy = Field(default_factory=RetryPolicy)
    retry_history: List[RetryRecord] = Field(default_factory=list)
    retry_count: int = 0
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    error: Optional[str] = None
    execution_time_ms: float = 0.0
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: str = Field(default_factory=_utc_now)


class SchedulerEvent(BaseModel):
    """An event emitted by the scheduler."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_type: EventType
    task_id: str
    task_title: str
    timestamp: str = Field(default_factory=_utc_now)
    details: Dict[str, Any] = Field(default_factory=dict)


class ExecutionQueue(BaseModel):
    """The ordered execution queue for the scheduler."""
    tasks: List[ScheduledTask] = Field(default_factory=list)
    events: List[SchedulerEvent] = Field(default_factory=list)
    active_workers: int = 0
    max_workers: int = 4

    @property
    def pending_count(self) -> int:
        return sum(1 for t in self.tasks if t.state == TaskState.PENDING)

    @property
    def ready_count(self) -> int:
        return sum(1 for t in self.tasks if t.state == TaskState.READY)

    @property
    def running_count(self) -> int:
        return sum(1 for t in self.tasks if t.state == TaskState.RUNNING)

    @property
    def completed_count(self) -> int:
        return sum(1 for t in self.tasks if t.state == TaskState.COMPLETED)

    @property
    def failed_count(self) -> int:
        return sum(1 for t in self.tasks if t.state == TaskState.FAILED)


class ToolType(str, Enum):
    """Supported types of tools."""
    INTERNAL = "internal"
    EXTERNAL = "external"
    REMOTE = "remote"


class ToolExecutionStatus(str, Enum):
    """Execution lifecycle status for a tool."""
    PREPARING = "Preparing"
    RUNNING = "Running"
    SUCCEEDED = "Succeeded"
    FAILED = "Failed"
    CANCELLED = "Cancelled"
    TIMED_OUT = "Timed Out"


class OrchestratorEventType(str, Enum):
    """Event types emitted by the Tool Orchestrator."""
    TOOL_SELECTED = "ToolSelected"
    TOOL_STARTED = "ToolStarted"
    TOOL_COMPLETED = "ToolCompleted"
    TOOL_FAILED = "ToolFailed"
    TOOL_TIMED_OUT = "ToolTimedOut"
    TOOL_CANCELLED = "ToolCancelled"
    ARTIFACTS_PRODUCED = "ArtifactsProduced"


class Tool(BaseModel):
    """Metadata representing an executable tool or capability."""
    id: str = ""
    name: str
    version: str = "1.0.0"
    description: str = ""
    supported_tasks: List[str] = Field(default_factory=list)
    required_inputs: List[str] = Field(default_factory=list)
    produced_outputs: List[str] = Field(default_factory=list)
    capabilities: List[str] = Field(default_factory=list)
    safety_requirements: Dict[str, Any] = Field(default_factory=dict)
    timeout: float = 300.0
    priority: int = 100

    # Backwards compatibility
    command: Optional[str] = None
    capability: Optional[str] = None

    def __init__(self, **data):
        super().__init__(**data)
        if not self.id:
            self.id = self.name.lower().replace(" ", "_")
        if self.capability and self.capability not in self.capabilities:
            self.capabilities.append(self.capability)


class ToolExecutionContext(BaseModel):
    """The context injected into tools for execution."""
    mission: Any
    scope: List[str] = Field(default_factory=list)
    policy: Dict[str, Any] = Field(default_factory=dict)
    task: Any
    knowledge_graph: Optional[Any] = None
    workflow_graph: Optional[Any] = None
    evidence_store: Optional[Any] = None
    configuration: Dict[str, Any] = Field(default_factory=dict)

    class Config:
        arbitrary_types_allowed = True


class ToolArtifact(BaseModel):
    """Artifact produced by a tool, stored with provenance."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    type: str  # e.g., "observation", "evidence", "knowledge_graph_update", "workflow_update", "file", "log", "metric"
    data: Any
    provenance: Dict[str, Any] = Field(default_factory=dict)
    created_at: str = Field(default_factory=_utc_now)


class ToolExecutionResult(BaseModel):
    """Standardized result wrapper for all tool execution types."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tool_id: str
    task_id: str
    status: ToolExecutionStatus
    observations: List[Any] = Field(default_factory=list)
    evidence: List[Any] = Field(default_factory=list)
    knowledge_graph_updates: List[Any] = Field(default_factory=list)
    workflow_updates: List[Any] = Field(default_factory=list)
    files: List[Dict[str, Any]] = Field(default_factory=list)
    logs: List[str] = Field(default_factory=list)
    metrics: Dict[str, Any] = Field(default_factory=dict)
    artifacts: List[ToolArtifact] = Field(default_factory=list)
    error: Optional[str] = None
    execution_time_ms: float = 0.0
    started_at: str = Field(default_factory=_utc_now)
    completed_at: Optional[str] = None


class OrchestratorEvent(BaseModel):
    """An event emitted by the Tool Orchestrator."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_type: OrchestratorEventType
    task_id: str
    tool_id: str
    timestamp: str = Field(default_factory=_utc_now)
    details: Dict[str, Any] = Field(default_factory=dict)

