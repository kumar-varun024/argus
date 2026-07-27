from dataclasses import dataclass, field

from enum import Enum
from datetime import datetime
from uuid import uuid4

class ResearchCardCategory(str, Enum):
    AUTHORIZATION = "Authorization"
    AUTHENTICATION = "Authentication"
    BUSINESS_LOGIC = "Business Logic"
    WORKFLOW = "Workflow"
    GRAPHQL = "GraphQL"
    REST_API = "REST API"
    JAVASCRIPT = "JavaScript"
    FILE_UPLOAD = "File Upload"
    SENSITIVE_DATA = "Sensitive Data"
    CONFIGURATION = "Configuration"
    RECON = "Recon"
    CUSTOM = "Custom"

class ResearchCardPriority(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"

class ResearchCardStatus(str, Enum):
    PENDING = "Pending"
    COMPLETED = "Completed"
    DISMISSED = "Dismissed"

@dataclass
class ResearchCard:
    title: str
    summary: str
    category: ResearchCardCategory
    
    id: str = field(default_factory=lambda: str(uuid4()))
    priority: ResearchCardPriority = ResearchCardPriority.LOW
    confidence: float = 1.0
    status: ResearchCardStatus = ResearchCardStatus.PENDING
    
    business_object: str = ""
    authentication: str = ""
    technology: str = ""
    
    related_endpoints: list[str] = field(default_factory=list)
    related_evidence: list[str] = field(default_factory=list)
    related_graph_nodes: list[str] = field(default_factory=list)
    
    reasoning: list[str] = field(default_factory=list)
    recommended_manual_steps: list[str] = field(default_factory=list)
    expected_observations: list[str] = field(default_factory=list)
    
    risk_if_confirmed: str = ""
    references: list[str] = field(default_factory=list)
    related_workflows: list[str] = field(default_factory=list)
    authorization_context: str = ""
    
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())


@dataclass
class AIResponse:

    executive_summary: str = ""
    business_objects: list[str] = field(default_factory=list)
    business_workflows: list[str] = field(default_factory=list)
    authorization_boundaries: list[str] = field(default_factory=list)
    sensitive_operations: list[str] = field(default_factory=list)
    high_value_assets: list[str] = field(default_factory=list)
    research_questions: list[str] = field(default_factory=list)
    missing_evidence: list[str] = field(default_factory=list)
    recommended_next_steps: list[str] = field(default_factory=list)
    confidence: str = ""
    unknown_areas: list[str] = field(default_factory=list)