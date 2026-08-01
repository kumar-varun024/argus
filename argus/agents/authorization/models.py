from dataclasses import dataclass, field
from typing import List, Dict, Optional
from argus.intelligence.models import Investigation

@dataclass
class AuthzHeuristicResult:
    """Wrapper for hypotheses returned by an authz heuristic."""
    investigation: Investigation
    matched_nodes: List[str] = field(default_factory=list)
    heuristic_id: str = ""

@dataclass
class AuthzContext:
    """Context object passed to authorization heuristics."""
    mission_id: str
    target: str
    roles: List[str] = field(default_factory=list)
    hierarchy: Dict[str, List[str]] = field(default_factory=dict)
    ownership_chains: List[List[str]] = field(default_factory=list)
    endpoints: List[dict] = field(default_factory=list)
    workflows: List[dict] = field(default_factory=list)
    
    # The full graph is available if heuristics need deep traversal
    graph: Optional['AuthorizationGraph'] = None
