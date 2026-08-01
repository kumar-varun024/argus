from dataclasses import dataclass, field
from typing import List, Dict, Any
from uuid import uuid4
from argus.execution.state import ExecutionStatus

@dataclass
class ExecutionStep:
    order: int
    agent: str
    action: str
    required_inputs: List[str] = field(default_factory=list)
    expected_outputs: List[str] = field(default_factory=list)
    validation_checks: List[str] = field(default_factory=list)

@dataclass
class ExecutionPlan:
    title: str
    objective: str
    id: str = field(default_factory=lambda: str(uuid4()))
    required_agents: List[str] = field(default_factory=list)
    required_evidence: List[str] = field(default_factory=list)
    steps: List[ExecutionStep] = field(default_factory=list)
    status: ExecutionStatus = ExecutionStatus.PENDING
    confidence: float = 1.0
    expected_outputs: List[str] = field(default_factory=list)
