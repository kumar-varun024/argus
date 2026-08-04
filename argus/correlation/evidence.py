import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any
from pydantic import BaseModel, Field, ConfigDict

def _generate_utc_now() -> datetime:
    return datetime.now(timezone.utc)

class EvidenceBundle(BaseModel):
    """
    Represents multiple pieces of evidence supporting the same application behavior
    or investigation area. Fuses observations and correlations together.
    """
    model_config = ConfigDict(
        validate_assignment=True,
        arbitrary_types_allowed=True
    )
    
    id: uuid.UUID = Field(default_factory=uuid.uuid4, frozen=True)
    title: str
    description: str
    confidence: float = Field(0.0, ge=0.0, le=1.0)
    strength: int = Field(0, ge=0, le=100)
    created_at: datetime = Field(default_factory=_generate_utc_now)
    updated_at: datetime = Field(default_factory=_generate_utc_now)
    
    business_objects: List[str] = Field(default_factory=list)
    workflows: List[str] = Field(default_factory=list)
    technologies: List[str] = Field(default_factory=list)
    
    observations: List[uuid.UUID] = Field(default_factory=list)
    correlations: List[uuid.UUID] = Field(default_factory=list)
    
    evidence: List[Any] = Field(default_factory=list)
    graph_nodes: List[str] = Field(default_factory=list)
    graph_edges: List[str] = Field(default_factory=list)
    authentication_context: List[str] = Field(default_factory=list)
    authorization_context: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
