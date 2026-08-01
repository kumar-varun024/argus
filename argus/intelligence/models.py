from dataclasses import dataclass, field
from typing import List, Optional
from uuid import uuid4

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
