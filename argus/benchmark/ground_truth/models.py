from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional
from enum import Enum

class MatchStatus(str, Enum):
    """The classification of an expected finding against actual output."""
    MATCHED = "Matched"
    PARTIALLY_MATCHED = "Partially Matched"
    NOT_MATCHED = "Not Matched"
    UNEXPECTED_FINDING = "Unexpected Finding"

@dataclass
class GroundTruth:
    """Comprehensive definition of expected analysis outcomes for a benchmark."""
    id: str
    dataset: str
    version: str
    
    # Expectations
    expected_technologies: List[str] = field(default_factory=list)
    expected_frameworks: List[str] = field(default_factory=list)
    expected_endpoints: List[str] = field(default_factory=list)
    expected_graphql_types: List[str] = field(default_factory=list)
    expected_business_objects: List[str] = field(default_factory=list)
    expected_relationships: List[str] = field(default_factory=list)
    expected_workflows: List[str] = field(default_factory=list)
    expected_authentication_flows: List[str] = field(default_factory=list)
    expected_authorization_boundaries: List[str] = field(default_factory=list)
    expected_investigation_areas: List[str] = field(default_factory=list)
    expected_observations: List[str] = field(default_factory=list)
    expected_correlations: List[str] = field(default_factory=list)
    expected_evidence_bundles: List[str] = field(default_factory=list)
    
    notes: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class MatchResult:
    """The result of comparing a single expectation against actual output."""
    category: str
    expected: Optional[str]
    actual: Optional[str]
    status: MatchStatus
    explanation: str
    confidence: float

@dataclass
class ComparisonResult:
    """The aggregated result of all ground truth comparisons for a mission."""
    dataset_id: str
    mission_id: str
    matches: List[MatchResult] = field(default_factory=list)
    misses: List[MatchResult] = field(default_factory=list)
    unexpected_findings: List[MatchResult] = field(default_factory=list)
    
    total_expected: int = 0
    total_matched: int = 0
    total_partially_matched: int = 0
