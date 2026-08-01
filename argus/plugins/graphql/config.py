from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

@dataclass
class GraphQLConfig:
    enabled: bool = True
    introspection_attempts: int = 3
    timeout_ms: int = 5000
