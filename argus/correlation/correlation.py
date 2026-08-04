import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field, ConfigDict

def _generate_utc_now() -> datetime:
    return datetime.now(timezone.utc)

class Correlation(BaseModel):
    """
    Represents multiple related observations that appear to describe the same 
    application behavior or security context.
    """
    model_config = ConfigDict(
        validate_assignment=True,
        arbitrary_types_allowed=True
    )
    
    id: uuid.UUID = Field(default_factory=uuid.uuid4, frozen=True)
    title: str
    description: str
    confidence: float = Field(0.0, ge=0.0, le=1.0)
    score: int = Field(0, ge=0, le=100)
    created_at: datetime = Field(default_factory=_generate_utc_now)
    updated_at: datetime = Field(default_factory=_generate_utc_now)
    
    # Links to standard observations
    observations: List[uuid.UUID] = Field(default_factory=list)
    
    # Aggregated contexts from underlying observations
    business_objects: List[str] = Field(default_factory=list)
    workflows: List[str] = Field(default_factory=list)
    technologies: List[str] = Field(default_factory=list)
    graph_nodes: List[str] = Field(default_factory=list)
    graph_edges: List[str] = Field(default_factory=list)
    authentication_context: List[str] = Field(default_factory=list)
    authorization_context: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
