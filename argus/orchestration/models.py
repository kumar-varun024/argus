import uuid
from enum import Enum
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone

def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()

class ResearchStepState(str, Enum):
    NOT_STARTED = "NOT_STARTED"
    PLANNING = "PLANNING"
    INVESTIGATING = "INVESTIGATING"
    WAITING_FOR_USER = "WAITING_FOR_USER"
    WAITING_FOR_EVIDENCE = "WAITING_FOR_EVIDENCE"
    ANALYZING = "ANALYZING"
    VERIFYING = "VERIFYING"
    CONFIRMED = "CONFIRMED"
    REJECTED = "REJECTED"
    BLOCKED = "BLOCKED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"

class ResearchStepType(str, Enum):
    OBSERVE = "OBSERVE"
    ANALYZE = "ANALYZE"
    CORRELATE = "CORRELATE"
    QUERY = "QUERY"
    VERIFY = "VERIFY"
    COLLECT_EVIDENCE = "COLLECT_EVIDENCE"
    USER_INPUT = "USER_INPUT"
    TOOL_EXECUTION = "TOOL_EXECUTION"
    DECISION = "DECISION"
    CREATE_FINDING = "CREATE_FINDING"
    REVIEW_FINDING = "REVIEW_FINDING"

class ToolExecution(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tool_id: str
    target: str
    inputs: Dict[str, Any] = Field(default_factory=dict)
    status: str = "PENDING"
    result: Optional[Any] = None
    error_message: Optional[str] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None

class WorkflowEvent(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str
    description: str
    timestamp: str = Field(default_factory=_utc_now)
    metadata: Dict[str, Any] = Field(default_factory=dict)

class ResearchStep(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    description: str
    step_type: ResearchStepType
    state: ResearchStepState = ResearchStepState.NOT_STARTED
    target: Optional[str] = None
    rationale: str = ""
    expected_evidence: str = ""
    tool_execution: Optional[ToolExecution] = None
    produced_evidence_ids: List[str] = Field(default_factory=list)
    created_at: str = Field(default_factory=_utc_now)
    updated_at: str = Field(default_factory=_utc_now)
    metadata: Dict[str, Any] = Field(default_factory=dict)

class ResearchWorkflow(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    investigation_id: str
    mission_id: str
    current_step_id: Optional[str] = None
    steps: List[ResearchStep] = Field(default_factory=list)
    events: List[WorkflowEvent] = Field(default_factory=list)
    is_paused: bool = False
    created_at: str = Field(default_factory=_utc_now)
    updated_at: str = Field(default_factory=_utc_now)
