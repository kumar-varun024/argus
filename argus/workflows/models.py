from dataclasses import dataclass, field
from uuid import uuid4
from typing import List, Set


@dataclass
class WorkflowStep:
    title: str
    endpoint: str
    http_method: str
    id: str = field(default_factory=lambda: str(uuid4()))
    order: int = 0
    business_object: str = ""
    authentication: str = ""
    required_role: str = ""
    expected_state: str = ""
    next_steps: List[str] = field(default_factory=list)
    previous_steps: List[str] = field(default_factory=list)
    graph_node: str = ""
    evidence: List[str] = field(default_factory=list)


@dataclass
class Workflow:
    name: str
    description: str
    id: str = field(default_factory=lambda: str(uuid4()))
    confidence: float = 0.0
    business_objects: Set[str] = field(default_factory=set)
    authentication: Set[str] = field(default_factory=set)
    roles: Set[str] = field(default_factory=set)
    steps: List[WorkflowStep] = field(default_factory=list)
    entry_points: List[str] = field(default_factory=list)
    exit_points: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    risk_score: str = "LOW"
    graph_nodes: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
