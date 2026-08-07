import uuid
from enum import Enum
from datetime import datetime, timezone
from typing import List, Dict, Any
from pydantic import BaseModel, Field, ConfigDict

def _generate_utc_now() -> datetime:
    return datetime.now(timezone.utc)

class HypothesisCategory(str, Enum):
    AUTHORIZATION = "Authorization"
    BUSINESS_LOGIC = "Business Logic"
    AUTHENTICATION = "Authentication"
    API = "API"
    GRAPHQL = "GraphQL"
    JAVASCRIPT = "JavaScript"
    INFRASTRUCTURE = "Infrastructure"
    CONFIGURATION = "Configuration"
    WORKFLOW = "Workflow"
    TECHNOLOGY = "Technology"
    GENERAL_RESEARCH = "General Research"

class HypothesisStatus(str, Enum):
    DRAFT = "Draft"
    PROPOSED = "Proposed"
    UNDER_REVIEW = "Under Review"
    VALIDATED = "Validated"
    REJECTED = "Rejected"
    ARCHIVED = "Archived"

class HypothesisPriority(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

class HypothesisHistoryEntry(BaseModel):
    status: HypothesisStatus
    reason: str
    confidence: float
    timestamp: datetime = Field(default_factory=_generate_utc_now)

class Hypothesis(BaseModel):
    """
    Represents an evidence-backed research question.
    A hypothesis is NOT a vulnerability.
    It proposes structured areas that should be investigated further based on evidence.
    """
    model_config = ConfigDict(
        validate_assignment=True,
        arbitrary_types_allowed=True
    )
    
    id: uuid.UUID = Field(default_factory=uuid.uuid4, frozen=True)
    title: str
    summary: str
    description: str
    category: HypothesisCategory
    status: HypothesisStatus = HypothesisStatus.DRAFT
    priority: HypothesisPriority = HypothesisPriority.LOW
    priority_score: float = Field(0.0, ge=0.0, le=100.0)
    confidence: float = Field(0.0, ge=0.0, le=1.0)
    reason: str = ""
    
    business_objects: List[str] = Field(default_factory=list)
    workflows: List[str] = Field(default_factory=list)
    related_endpoints: List[str] = Field(default_factory=list)
    
    related_observations: List[uuid.UUID] = Field(default_factory=list)
    related_correlations: List[uuid.UUID] = Field(default_factory=list)
    related_evidence: List[uuid.UUID] = Field(default_factory=list)
    related_investigations: List[uuid.UUID] = Field(default_factory=list)
    
    supporting_graph_nodes: List[str] = Field(default_factory=list)
    supporting_graph_edges: List[str] = Field(default_factory=list)
    
    manual_validation: str = ""
    created_at: datetime = Field(default_factory=_generate_utc_now)
    updated_at: datetime = Field(default_factory=_generate_utc_now)
    
    history: List[HypothesisHistoryEntry] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
