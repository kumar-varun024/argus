from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from uuid import UUID, uuid4
from datetime import datetime

class ReasoningStep(BaseModel):
    """A deterministic step in the reasoning chain."""
    step_id: str
    description: str
    source_type: str  # e.g., 'Observation', 'Correlation', 'EvidenceBundle', 'Priority'
    source_id: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

class TimelineEvent(BaseModel):
    """A chronological event related to the investigation."""
    timestamp: datetime
    event_type: str  # e.g., 'Observation Created', 'Correlation Formed', 'Evidence Fused'
    description: str
    source_id: str

class GraphNode(BaseModel):
    """A node in the explanation graph."""
    id: str
    label: str
    node_type: str  # e.g., 'Observation', 'EvidenceBundle', 'BusinessObject', 'Investigation'
    properties: Dict[str, Any] = Field(default_factory=dict)

class GraphEdge(BaseModel):
    """An edge in the explanation graph."""
    source: str
    target: str
    relationship: str  # e.g., 'SUPPORTS', 'PART_OF', 'INVOLVES'
    properties: Dict[str, Any] = Field(default_factory=dict)

class ExplanationGraph(BaseModel):
    """The full graph structure explaining the investigation's provenance."""
    nodes: List[GraphNode] = Field(default_factory=list)
    edges: List[GraphEdge] = Field(default_factory=list)

class Explanation(BaseModel):
    """
    A comprehensive explanation object detailing why an investigation exists
    and how its attributes (priority, confidence) were determined.
    """
    id: UUID = Field(default_factory=uuid4)
    investigation_id: UUID
    title: str
    summary: str
    
    # Reasoning & Provenance
    reasoning_chain: List[ReasoningStep] = Field(default_factory=list)
    timeline: List[TimelineEvent] = Field(default_factory=list)
    explanation_graph: ExplanationGraph = Field(default_factory=ExplanationGraph)
    
    # Breakdowns
    priority_breakdown: Dict[str, float] = Field(default_factory=dict)
    confidence_breakdown: Dict[str, float] = Field(default_factory=dict)
    
    # Context summary
    observations: List[UUID] = Field(default_factory=list)
    correlations: List[UUID] = Field(default_factory=list)
    evidence_bundles: List[UUID] = Field(default_factory=list)
    knowledge_graph_nodes: List[str] = Field(default_factory=list)
    workflow_nodes: List[str] = Field(default_factory=list)
    
    manual_validation: str = ""
    metadata: Dict[str, Any] = Field(default_factory=dict)
