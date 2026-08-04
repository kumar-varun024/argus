import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field, validator, ConfigDict

from argus.correlation.models import ObservationCategory, ObservationPriority

def _generate_utc_now() -> datetime:
    return datetime.now(timezone.utc)

class Observation(BaseModel):
    """Universal Observation model produced by all Argus specialists."""
    
    id: uuid.UUID = Field(default_factory=uuid.uuid4, frozen=True)
    source: str = Field(..., description="The specialist or module that generated this observation.")
    category: ObservationCategory
    subcategory: Optional[str] = None
    title: str
    description: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    priority: ObservationPriority
    timestamp: datetime = Field(default_factory=_generate_utc_now)
    
    # Contextual metadata
    business_objects: List[str] = Field(default_factory=list)
    workflows: List[str] = Field(default_factory=list)
    graph_nodes: List[str] = Field(default_factory=list)
    graph_edges: List[str] = Field(default_factory=list)
    api_operations: List[str] = Field(default_factory=list)
    graphql_types: List[str] = Field(default_factory=list)
    endpoints: List[str] = Field(default_factory=list)
    urls: List[str] = Field(default_factory=list)
    authentication_context: List[str] = Field(default_factory=list)
    authorization_context: List[str] = Field(default_factory=list)
    technology: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    evidence: List[Any] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    model_config = ConfigDict(
        validate_assignment=True,
        arbitrary_types_allowed=True
    )
