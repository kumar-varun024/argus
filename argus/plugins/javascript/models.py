from dataclasses import dataclass, field
from typing import List, Optional, Any, Dict
from datetime import datetime
from uuid import uuid4

@dataclass
class JavaScriptObservation:
    description: str
    confidence: float = 1.0
    evidence: List[Any] = field(default_factory=list)

@dataclass
class JavaScriptInvestigation:
    title: str
    description: str
    category: str
    reasoning: str
    evidence: List[Any] = field(default_factory=list)
    confidence: float = 0.0
    priority: str = "Informational"
    status: str = "Pending"
    tags: List[str] = field(default_factory=list)
    id: str = field(default_factory=lambda: str(uuid4()))

@dataclass
class JavaScriptSymbol:
    name: str
    symbol_type: str # Function, Class, Constant, EnvVar, FeatureFlag, Import, Export
    value: Optional[str] = None
    source: str = "Unknown"
    confidence: float = 1.0

@dataclass
class JavaScriptModule:
    name: str
    module_type: str # ESM, CommonJS
    exports: List[str] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    source: str = "Unknown"

@dataclass
class JavaScriptASTNode:
    node_type: str
    value: Any = None
    children: List['JavaScriptASTNode'] = field(default_factory=list)
    source: str = "Unknown"

@dataclass
class JavaScriptRoute:
    path: str
    route_type: str
    source: str = "Unknown"

@dataclass
class JavaScriptFramework:
    name: str
    source: str = "Unknown"

@dataclass
class JavaScriptWebSocket:
    url: str
    source: str = "Unknown"
