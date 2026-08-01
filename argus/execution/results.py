from dataclasses import dataclass, field
from typing import Dict, Any, List
from datetime import datetime

@dataclass
class ExecutionStepResult:
    step_order: int
    agent: str
    status: str
    outputs: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    execution_time_ms: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

@dataclass
class ExecutionPlanResult:
    plan_id: str
    status: str
    step_results: List[ExecutionStepResult] = field(default_factory=list)
    collected_evidence: Dict[str, Any] = field(default_factory=dict)
    total_execution_time_ms: float = 0.0
    start_time: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    end_time: str = ""
