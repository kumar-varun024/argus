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

# Semantic Status Constants
SEMANTIC_STATUS_OBSERVATION = "OBSERVATION"
SEMANTIC_STATUS_EVIDENCE = "EVIDENCE"
SEMANTIC_STATUS_INFERENCE = "INFERENCE"
SEMANTIC_STATUS_HYPOTHESIS = "HYPOTHESIS"
SEMANTIC_STATUS_FINDING = "FINDING"
SEMANTIC_STATUS_MISSION_STATE = "MISSION_STATE"
SEMANTIC_STATUS_SCOPE = "SCOPE"
SEMANTIC_STATUS_INVESTIGATION_STATE = "INVESTIGATION_STATE"
SEMANTIC_STATUS_KNOWLEDGE_GRAPH = "KNOWLEDGE_GRAPH"
SEMANTIC_STATUS_CVE_KNOWLEDGE = "CVE_KNOWLEDGE"
SEMANTIC_STATUS_HISTORICAL_MEMORY = "HISTORICAL_MEMORY"
SEMANTIC_STATUS_VECTOR_FINDING = "VECTOR_FINDING"
SEMANTIC_STATUS_VECTOR_EVIDENCE = "VECTOR_EVIDENCE"
SEMANTIC_STATUS_UNKNOWN = "UNKNOWN"

# Source Type Constants
SOURCE_TYPE_OBSERVATION = "observation"
SOURCE_TYPE_EVIDENCE = "evidence"
SOURCE_TYPE_HYPOTHESIS = "hypothesis"
SOURCE_TYPE_FINDING = "finding"
SOURCE_TYPE_KNOWLEDGE_GRAPH = "knowledge_graph"
SOURCE_TYPE_CVE_KNOWLEDGE = "cve_knowledge"
SOURCE_TYPE_HISTORICAL_MEMORY = "historical_memory"
SOURCE_TYPE_VECTOR_FINDING = "vector_finding"
SOURCE_TYPE_VECTOR_EVIDENCE = "vector_evidence"

@dataclass
class ContextSource:
    """Represents a single retrieved item of research context."""
    source_id: str
    source_type: str  # e.g., 'observation', 'evidence', 'hypothesis', 'finding', 'knowledge_graph', 'cve_knowledge', 'historical_memory', 'vector_finding', 'vector_evidence'
    title: str
    content: str
    
    semantic_status: str  # 'OBSERVATION', 'EVIDENCE', 'INFERENCE', 'HYPOTHESIS', 'FINDING', 'CVE_KNOWLEDGE', 'HISTORICAL_MEMORY', 'VECTOR_FINDING', 'VECTOR_EVIDENCE', 'UNKNOWN'
    relevance_score: str = "Low"  # 'Critical', 'High', 'Medium', 'Low'
    relevance_reason: str = ""
    
    mission_id: str = ""
    investigation_id: str = ""
    project_id: str = ""
    
    timestamp: str = ""
    confidence: str = ""
    authorization_scope: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    vector_score: Optional[float] = None

    def __post_init__(self):
        if self.vector_score is None and "vector_score" in self.metadata:
            try:
                self.vector_score = float(self.metadata["vector_score"])
            except (ValueError, TypeError):
                pass
        elif self.vector_score is not None and "vector_score" not in self.metadata:
            self.metadata["vector_score"] = self.vector_score

@dataclass
class ContextResult:
    """The final structured context returned by the engine."""
    sources: List[ContextSource] = field(default_factory=list)
    context_status: str = "OK"  # 'INSUFFICIENT_CONTEXT', 'CONTRADICTORY_EVIDENCE', 'OK'
    status_reason: str = ""
    user_permission_state: str = ""
    authorization_scope: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
