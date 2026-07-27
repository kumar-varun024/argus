from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
from uuid import uuid4


class KnowledgeCategory(str, Enum):
    METHODOLOGY = "Methodology"
    HEURISTIC = "Heuristic"
    FINDING_PATTERN = "Finding Pattern"
    TECHNOLOGY = "Technology"
    BUSINESS_OBJECT = "Business Object"
    AUTHENTICATION_PATTERN = "Authentication Pattern"
    AUTHORIZATION_PATTERN = "Authorization Pattern"
    WORKFLOW_PATTERN = "Workflow Pattern"
    RECON_TECHNIQUE = "Recon Technique"
    EVIDENCE_PATTERN = "Evidence Pattern"
    INVESTIGATION_TECHNIQUE = "Investigation Technique"


@dataclass(slots=True)
class KnowledgeEntry:
    title: str
    category: KnowledgeCategory
    description: str
    
    id: str = field(default_factory=lambda: str(uuid4()))
    tags: list[str] = field(default_factory=list)
    source: str = ""
    references: list[str] = field(default_factory=list)
    confidence: float = 1.0
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    version: int = 1
    
    related_business_objects: list[str] = field(default_factory=list)
    related_technologies: list[str] = field(default_factory=list)
    related_authentication: list[str] = field(default_factory=list)
    related_cwes: list[str] = field(default_factory=list)
    related_capecs: list[str] = field(default_factory=list)
    related_owasp: list[str] = field(default_factory=list)
    related_entries: list[str] = field(default_factory=list)
    
    examples: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
