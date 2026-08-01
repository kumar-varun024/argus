from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from argus.intelligence.models import Investigation
from argus.workflows.models import Workflow

@dataclass
class State:
    name: str
    description: str = ""

@dataclass
class StateMachine:
    workflow_id: str
    name: str
    states: List[State] = field(default_factory=list)
    transitions: List[dict] = field(default_factory=list) # e.g., {"from": "Draft", "to": "Submitted", "action": "submit"}

@dataclass
class BusinessLogicContext:
    mission_id: str
    target: str
    workflows: List[Workflow] = field(default_factory=list)
    business_objects: List[Any] = field(default_factory=list)
    state_machines: Dict[str, StateMachine] = field(default_factory=dict)
    rules: List[dict] = field(default_factory=list)

@dataclass
class BusinessHeuristicResult:
    investigation: Investigation
    matched_nodes: List[str] = field(default_factory=list)
    heuristic_id: str = ""
