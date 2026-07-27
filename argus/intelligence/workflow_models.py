from dataclasses import dataclass, field
from uuid import uuid4
from typing import List, Set


@dataclass
class WorkflowStep:
    name: str
    endpoint: str
    method: str
    business_object: str = ""
    authentication: str = ""
    required_role: str = ""
    expected_state: str = ""
    next_steps: List[str] = field(default_factory=list)
    previous_steps: List[str] = field(default_factory=list)


@dataclass
class Workflow:
    name: str
    description: str
    id: str = field(default_factory=lambda: str(uuid4()))
    steps: List[WorkflowStep] = field(default_factory=list)
    
    business_objects: Set[str] = field(default_factory=set)
    related_endpoints: Set[str] = field(default_factory=set)
    authentication: Set[str] = field(default_factory=set)
    roles: Set[str] = field(default_factory=set)
    
    evidence: List[str] = field(default_factory=list)
    confidence: float = 0.0
    
    entry_points: List[str] = field(default_factory=list)
    exit_points: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    
    risk_level: str = "LOW"
    status: str = "IDENTIFIED"
