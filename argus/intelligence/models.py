from dataclasses import dataclass, field
from typing import List, Optional
from uuid import uuid4

@dataclass(slots=True)
class APIEndpoint:
    method: str
    path: str
    resource: str
    operation: str
    object_identifier: bool = False
    business_object: str = ""
    risk_score: int = 0
    priority: str = "LOW"
    confidence: float = 0.0
    tags: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)
    reasoning: List[str] = field(default_factory=list)
    manual_checks: List[str] = field(default_factory=list)


@dataclass
class Investigation:
    id: str = field(default_factory=lambda: str(uuid4()))
    title: str = ""
    category: str = "Uncategorized"
    
    # Context
    affected_objects: List[str] = field(default_factory=list)
    affected_endpoints: List[str] = field(default_factory=list)
    workflow: Optional[str] = None
    
    # Intelligence
    reasoning: str = ""
    supporting_evidence: List[str] = field(default_factory=list)
    confidence: float = 0.0
    priority: str = "Informational"
    
    # Actionable output
    manual_validation_steps: List[str] = field(default_factory=list)
    
    # Metadata
    related_cwe: List[str] = field(default_factory=list)
    related_owasp: List[str] = field(default_factory=list)
    status: str = "Pending"

