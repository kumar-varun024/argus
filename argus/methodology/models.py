from dataclasses import dataclass, field
from typing import List, Dict, Optional

@dataclass
class PlaybookStep:
    id: str
    title: str
    description: str
    required_evidence: List[str] = field(default_factory=list)
    required_graph_nodes: List[str] = field(default_factory=list)
    required_workflows: List[str] = field(default_factory=list)
    actions: List[str] = field(default_factory=list)
    expected_results: List[str] = field(default_factory=list)
    completion_criteria: str = ""

@dataclass
class Playbook:
    id: str
    name: str
    category: str
    description: str
    steps: List[PlaybookStep] = field(default_factory=list)
    required_inputs: List[str] = field(default_factory=list)
    supported_technologies: List[str] = field(default_factory=list)
    supported_business_objects: List[str] = field(default_factory=list)
    expected_outputs: List[str] = field(default_factory=list)
    priority: int = 50

@dataclass
class PlaybookResult:
    playbook_id: str
    status: str = "pending"  # pending, running, completed, failed
    completed_steps: List[str] = field(default_factory=list)
    findings: List[dict] = field(default_factory=list)
