import uuid
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime

@dataclass
class EvidenceRelationship:
    """Represents a relationship between evidence and other entities."""
    relationship_type: str  # DERIVED_FROM, SUPPORTS, CONTRADICTS, SUPERSEDED_BY
    target_id: str
    target_type: str  # e.g., 'hypothesis', 'evidence', 'observation'

@dataclass
class ProvenanceData:
    """Tracks the origin of an evidence item."""
    conversation_id: str = ""
    message_id: str = ""
    image_id: str = ""
    observation_id: str = ""
    original_ai_description: str = ""
    corrected_by_user: bool = False
    
@dataclass(slots=True)
class Evidence:
    """Represents confirmed or reviewed research evidence."""
    evidence_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    project_id: str = ""
    mission_id: str = ""
    investigation_id: str = ""
    
    source_type: str = "SYSTEM" # e.g., SCREENSHOT, LOG, OBSERVATION
    source_id: str = ""
    created_by: str = "SYSTEM_GENERATED" # USER_PROVIDED, AI_DERIVED, SYSTEM_GENERATED
    
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    
    title: str = ""
    description: str = ""
    content_reference: str = ""
    
    category: str = "Other"
    value: str = "" # Original field maintained for compatibility
    source: str = "" # Original field maintained for compatibility
    
    status: str = "UNVERIFIED" # UNVERIFIED, USER_REVIEWED, CORROBORATED, CONFIRMED, REJECTED, SUPERSEDED
    confidence: float = 1.0 # Semantic state could be mapped if needed, keeping float for compat
    severity: str = "info"
    
    provenance: ProvenanceData = field(default_factory=ProvenanceData)
    relationships: List[EvidenceRelationship] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

