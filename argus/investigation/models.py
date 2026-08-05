import uuid
from enum import Enum
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field, ConfigDict

def _generate_utc_now() -> datetime:
    return datetime.now(timezone.utc)

class InvestigationCategory(str, Enum):
    AUTHORIZATION = "Authorization"
    BUSINESS_LOGIC = "Business Logic"
    AUTHENTICATION = "Authentication"
    SESSION_MANAGEMENT = "Session Management"
    API = "API"
    GRAPHQL = "GraphQL"
    WORKFLOW = "Workflow"
    FILE_HANDLING = "File Handling"
    CLIENT_SIDE = "Client-side"
    CONFIGURATION = "Configuration"
    INFRASTRUCTURE = "Infrastructure"
    TECHNOLOGY = "Technology"

class InvestigationPriority(str, Enum):
    INFORMATIONAL = "Informational"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

class InvestigationStatus(str, Enum):
    OPEN = "Open"
    IN_PROGRESS = "In Progress"
    CLOSED = "Closed"

class Investigation(BaseModel):
    """
    Represents an evidence-backed area for human review.
    Does NOT assert vulnerabilities or exploits.
    """
    model_config = ConfigDict(
        validate_assignment=True,
        arbitrary_types_allowed=True
    )
    
    id: uuid.UUID = Field(default_factory=uuid.uuid4, frozen=True)
    title: str
    summary: str
    description: str
    category: InvestigationCategory
    priority: InvestigationPriority = InvestigationPriority.LOW
    priority_score: float = Field(0.0, ge=0.0, le=100.0)
    priority_explanation: List[str] = Field(default_factory=list)
    confidence: float = Field(0.0, ge=0.0, le=1.0)
    status: InvestigationStatus = InvestigationStatus.OPEN
    created_at: datetime = Field(default_factory=_generate_utc_now)
    updated_at: datetime = Field(default_factory=_generate_utc_now)
    
    business_objects: List[str] = Field(default_factory=list)
    workflows: List[str] = Field(default_factory=list)
    related_endpoints: List[str] = Field(default_factory=list)
    related_graph_nodes: List[str] = Field(default_factory=list)
    related_graph_edges: List[str] = Field(default_factory=list)
    
    observations: List[uuid.UUID] = Field(default_factory=list)
    correlations: List[uuid.UUID] = Field(default_factory=list)
    evidence_bundles: List[uuid.UUID] = Field(default_factory=list)
    
    manual_validation: str = ""
    reasoning: str = ""
    supporting_evidence: List[Any] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    technologies: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
