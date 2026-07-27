from dataclasses import dataclass, field
from enum import Enum
from uuid import uuid4
from typing import Dict, Any, List

class AuthNodeType(str, Enum):
    IDENTITY = "Identity"
    ROLE = "Role"
    PERMISSION = "Permission"
    BUSINESS_OBJECT = "BusinessObject"
    PROTECTED_RESOURCE = "ProtectedResource"
    ORGANIZATION = "Organization"
    PROJECT = "Project"
    REPOSITORY = "Repository"
    WORKSPACE = "Workspace"
    MEMBERSHIP = "Membership"
    OWNERSHIP = "Ownership"
    POLICY = "Policy"

class AuthEdgeType(str, Enum):
    OWNS = "OWNS"
    CAN_READ = "CAN_READ"
    CAN_CREATE = "CAN_CREATE"
    CAN_UPDATE = "CAN_UPDATE"
    CAN_DELETE = "CAN_DELETE"
    CAN_INVITE = "CAN_INVITE"
    MEMBER_OF = "MEMBER_OF"
    ADMIN_OF = "ADMIN_OF"
    BELONGS_TO = "BELONGS_TO"
    PROTECTED_BY = "PROTECTED_BY"
    INHERITS = "INHERITS"
    ASSIGNS = "ASSIGNS"
    USES_POLICY = "USES_POLICY"

@dataclass
class AuthNode:
    name: str
    node_type: AuthNodeType
    id: str = field(default_factory=lambda: str(uuid4()))
    properties: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0
    inferred: bool = False
    evidence: List[str] = field(default_factory=list)

@dataclass
class AuthEdge:
    source_id: str
    target_id: str
    edge_type: AuthEdgeType
    id: str = field(default_factory=lambda: str(uuid4()))
    properties: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0
    inferred: bool = False
    evidence: List[str] = field(default_factory=list)
