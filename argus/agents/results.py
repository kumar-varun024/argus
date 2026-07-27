from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Any
from datetime import datetime

class AgentHealth(str, Enum):
    HEALTHY = "Healthy"
    DEGRADED = "Degraded"
    FAILED = "Failed"
    UNKNOWN = "Unknown"

@dataclass
class AgentMetric:
    execution_time_ms: float = 0.0
    items_processed: int = 0
    items_produced: int = 0
    errors: int = 0

@dataclass
class AgentResult:
    agent_name: str
    recommendations: List[str] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    confidence: float = 1.0
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
