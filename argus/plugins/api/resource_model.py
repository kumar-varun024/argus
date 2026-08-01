from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any

@dataclass
class APIResource:
    name: str
    path: str
    is_collection: bool = False
    properties: Dict[str, Any] = field(default_factory=dict)
    
@dataclass
class APICollection(APIResource):
    is_collection: bool = True
    member_path: Optional[str] = None
    
@dataclass
class APISingleton(APIResource):
    is_collection: bool = False
