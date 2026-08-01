from dataclasses import dataclass, field
from typing import List, Optional, Any
from datetime import datetime
from uuid import uuid4

@dataclass
class Observation:
    description: str
    confidence: float = 1.0
    evidence: List[Any] = field(default_factory=list)

@dataclass
class GraphQLEndpoint:
    url: str
    method: str = "POST"
    source: str = "Unknown"
    confidence: float = 0.0
    evidence: List[Any] = field(default_factory=list)
    id: str = field(default_factory=lambda: str(uuid4()))
    framework_hint: Optional[str] = None
    supports_get: bool = False
    supports_post: bool = False
    first_seen: Optional[str] = field(default_factory=lambda: datetime.utcnow().isoformat())
    last_seen: Optional[str] = field(default_factory=lambda: datetime.utcnow().isoformat())

@dataclass
class GraphQLType:
    name: str

@dataclass
class GraphQLOperation:
    name: str
    operation_type: str

@dataclass
class GraphQLRelationship:
    parent: str
    child: str
