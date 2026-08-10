from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

@dataclass
class ContextQuery:
    """Represents a request for research context."""
    conversation_id: str
    query: str
    user_id: str = ""
    project_id: str = ""
    mission_id: str = ""
    investigation_id: str = ""
    message_id: str = ""
    current_entity: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ContextSource:
    """Represents a single retrieved item of research context."""
    source_id: str
    source_type: str  # e.g., 'observation', 'evidence', 'hypothesis', 'finding', 'knowledge_graph'
    title: str
    content: str
    
    semantic_status: str  # 'OBSERVATION', 'EVIDENCE', 'INFERENCE', 'HYPOTHESIS', 'FINDING', 'UNKNOWN'
    relevance_score: str = "Low"  # 'Critical', 'High', 'Medium', 'Low'
    relevance_reason: str = ""
    
    mission_id: str = ""
    investigation_id: str = ""
    project_id: str = ""
    
    timestamp: str = ""
    confidence: str = ""
    authorization_scope: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ContextResult:
    """The final structured context returned by the engine."""
    sources: List[ContextSource] = field(default_factory=list)
    context_status: str = "OK"  # 'INSUFFICIENT_CONTEXT', 'CONTRADICTORY_EVIDENCE', 'OK'
    status_reason: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
