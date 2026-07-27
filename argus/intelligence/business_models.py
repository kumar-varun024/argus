from dataclasses import dataclass, field
from argus.intelligence.models import APIEndpoint

@dataclass
class BusinessObject:
    name: str
    operations: set[str] = field(default_factory=set)
    endpoints: list[APIEndpoint] = field(default_factory=list)
    children: list[str] = field(default_factory=list)
    parents: list[str] = field(default_factory=list)
    risk_score: int = 0
    priority: str = "LOW"
    reasoning: list[str] = field(default_factory=list)
