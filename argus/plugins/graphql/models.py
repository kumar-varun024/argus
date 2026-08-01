from dataclasses import dataclass, field
from typing import List, Optional, Any, Dict
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
class GraphQLArgument:
    name: str
    type: str
    default_value: Optional[str] = None
    is_required: bool = False

@dataclass
class GraphQLField:
    name: str
    type: str
    description: Optional[str] = None
    arguments: List[GraphQLArgument] = field(default_factory=list)
    is_list: bool = False
    is_required: bool = False
    custom_scalars: List[str] = field(default_factory=list)

@dataclass
class GraphQLType:
    name: str
    kind: str  # OBJECT, INPUT_OBJECT, SCALAR, etc.
    description: Optional[str] = None
    fields: Dict[str, GraphQLField] = field(default_factory=dict)
    relationships: List[str] = field(default_factory=list)
    field_types: List[str] = field(default_factory=list)
    nullability: bool = True
    lists: bool = False
    custom_scalars: List[str] = field(default_factory=list)
    id: str = field(default_factory=lambda: str(uuid4()))
    source: str = "Unknown"
    evidence: List[Any] = field(default_factory=list)
    confidence: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class GraphQLOperation:
    name: str
    operation_type: str  # Query, Mutation, Subscription
    return_type: str
    arguments: List[GraphQLArgument] = field(default_factory=list)
    input_types: List[str] = field(default_factory=list)
    observed_variables: List[str] = field(default_factory=list)
    authentication_metadata: Dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: str(uuid4()))
    source: str = "Unknown"
    evidence: List[Any] = field(default_factory=list)
    confidence: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class GraphQLEnum:
    name: str
    values: List[str] = field(default_factory=list)
    id: str = field(default_factory=lambda: str(uuid4()))
    source: str = "Unknown"
    evidence: List[Any] = field(default_factory=list)
    confidence: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class GraphQLUnion:
    name: str
    possible_types: List[str] = field(default_factory=list)
    id: str = field(default_factory=lambda: str(uuid4()))
    source: str = "Unknown"
    evidence: List[Any] = field(default_factory=list)
    confidence: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class GraphQLInterface:
    name: str
    fields: Dict[str, GraphQLField] = field(default_factory=dict)
    implemented_by: List[str] = field(default_factory=list)
    id: str = field(default_factory=lambda: str(uuid4()))
    source: str = "Unknown"
    evidence: List[Any] = field(default_factory=list)
    confidence: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class GraphQLSchema:
    types: Dict[str, GraphQLType] = field(default_factory=dict)
    queries: Dict[str, GraphQLOperation] = field(default_factory=dict)
    mutations: Dict[str, GraphQLOperation] = field(default_factory=dict)
    subscriptions: Dict[str, GraphQLOperation] = field(default_factory=dict)
    enums: Dict[str, GraphQLEnum] = field(default_factory=dict)
    unions: Dict[str, GraphQLUnion] = field(default_factory=dict)
    interfaces: Dict[str, GraphQLInterface] = field(default_factory=dict)
    id: str = field(default_factory=lambda: str(uuid4()))
    source: str = "Unknown"
    evidence: List[Any] = field(default_factory=list)
    confidence: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class GraphQLRelationship:
    parent: str
    child: str
    type: str = "RELATED_TO"
    source: str = "Unknown"
    evidence: List[Any] = field(default_factory=list)
    confidence: float = 1.0

@dataclass
class GraphQLBusinessObject:
    name: str
    object_type: str
    relationships: List[GraphQLRelationship] = field(default_factory=list)
    evidence: List[Any] = field(default_factory=list)
    confidence: float = 1.0

@dataclass
class GraphQLCRUD:
    operation_name: str
    action: str  # CREATE, READ, UPDATE, DELETE, LIST, SEARCH
    object_type: str
    evidence: List[Any] = field(default_factory=list)

@dataclass
class GraphQLWorkflowNode:
    name: str
    state: str
    evidence: List[Any] = field(default_factory=list)

@dataclass
class GraphQLWorkflow:
    name: str
    states: List[GraphQLWorkflowNode] = field(default_factory=list)
    transitions: List[Dict[str, str]] = field(default_factory=list)
    business_objects: List[str] = field(default_factory=list)
    evidence: List[Any] = field(default_factory=list)
    confidence: float = 1.0

@dataclass
class GraphQLInvestigation:
    title: str
    description: str
    category: str
    reasoning: str
    evidence: List[Any] = field(default_factory=list)
    confidence: float = 0.0
    priority: str = "Informational"
    business_objects: List[str] = field(default_factory=list)
    related_operations: List[str] = field(default_factory=list)
    related_workflow: Optional[str] = None
    related_nodes: List[str] = field(default_factory=list)
    manual_validation_guidance: str = ""
    status: str = "Pending"
    tags: List[str] = field(default_factory=list)
    id: str = field(default_factory=lambda: str(uuid4()))
