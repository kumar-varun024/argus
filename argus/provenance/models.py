from dataclasses import dataclass, field
from typing import List, Dict, Optional
from datetime import datetime
import uuid

@dataclass
class ProvenanceRecord:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    artifact_type: str = "Unknown"
    created_by: str = "System"
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    confidence: float = 1.0
    
    # Source nodes these findings are based on
    source_evidence: List[str] = field(default_factory=list)
    supporting_nodes: List[str] = field(default_factory=list)
    supporting_workflows: List[str] = field(default_factory=list)
    supporting_research_cards: List[str] = field(default_factory=list)
    
    # Graph traversal links
    parent_artifacts: List[str] = field(default_factory=list)
    child_artifacts: List[str] = field(default_factory=list)
