from dataclasses import dataclass, field
from typing import Dict, List, Any

@dataclass
class BenchmarkDataset:
    """Represents a loaded benchmark dataset with all its configurations."""
    id: str
    name: str
    description: str
    version: str
    category: str
    target: str
    mission: Dict[str, Any] = field(default_factory=dict)
    ground_truth: Dict[str, Any] = field(default_factory=dict)
    
    expected_technologies: List[str] = field(default_factory=list)
    expected_business_objects: List[str] = field(default_factory=list)
    expected_workflows: List[str] = field(default_factory=list)
    expected_investigation_areas: List[str] = field(default_factory=list)
    expected_routes: List[str] = field(default_factory=list)
    expected_api_endpoints: List[str] = field(default_factory=list)
    expected_graphql_types: List[str] = field(default_factory=list)
    
    metadata: Dict[str, Any] = field(default_factory=dict)
