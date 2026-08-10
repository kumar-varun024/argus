import uuid
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime

@dataclass
class ContextReference:
    """Represents a reference to research context (observation, evidence, workflow, etc.)"""
    ref_id: str
    ref_type: str # 'observation', 'evidence', 'workflow', 'hypothesis', 'finding'
    title: str
    snippet: str = ""

@dataclass
class VisualObservation:
    """Represents a structured technical fact extracted from an image."""
    observation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    image_id: str = ""
    description: str = ""
    category: str = "Other" # e.g. Browser UI, HTTP response, Error message
    confidence: str = "UNKNOWN" # CONFIRMED, LIKELY, POSSIBLE, UNCERTAIN
    semantic_status: str = "OBSERVATION" # OBSERVATION, EVIDENCE, INFERENCE
    technical_significance: str = ""

@dataclass
class ImageAttachment:
    """Represents an uploaded screenshot/image evidence."""
    image_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    filename: str = ""
    mime_type: str = "application/octet-stream"
    size: int = 0
    width: int = 0
    height: int = 0
    storage_reference: str = ""
    
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    user_description: str = ""
    
    # Research context IDs
    conversation_id: str = ""
    project_id: str = ""
    mission_id: str = ""
    investigation_id: str = ""
    
    # Analysis fields
    analysis_status: str = "PENDING" # PENDING, PROCESSING, COMPLETED, FAILED
    analysis_result: str = ""
    model: str = ""
    model_provider: str = ""
    analysis_version: str = "1.0"
    
    visual_observations: List[VisualObservation] = field(default_factory=list)
    references: List[ContextReference] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class Message:
    """Represents a single chat interaction."""
    message_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    role: str = "user" # system, user, assistant
    text: str = ""
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    
    sequence_number: int = 0
    model: str = ""
    model_provider: str = ""
    token_usage: Dict[str, int] = field(default_factory=dict)
    
    attachments: List[ImageAttachment] = field(default_factory=list)
    references: List[ContextReference] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    # For internal reasoning steps not shown directly to user, or shown as dropdown
    reasoning_chain: List[str] = field(default_factory=list)

@dataclass
class Conversation:
    """Represents a full conversation session in the workspace."""
    conversation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    title: str = "New Conversation"
    
    user_id: str = "local_user"
    project_id: str = ""
    mission_id: str = ""
    investigation_id: str = ""
    
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    last_message_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    
    status: str = "active"
    archived_at: Optional[str] = None
    
    messages: List[Message] = field(default_factory=list)
    
    # Abstraction representing active state (scope, current investigation)
    current_context: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
