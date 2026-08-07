from dataclasses import dataclass, field
from typing import Dict, Any, List

@dataclass
class Metric:
    id: str
    name: str
    category: str
    score: float
    maximum_score: float
    weight: float
    description: str
    details: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class CoverageReport:
    technology_coverage: float = 0.0
    framework_coverage: float = 0.0
    api_coverage: float = 0.0
    graphql_coverage: float = 0.0
    business_object_coverage: float = 0.0
    workflow_coverage: float = 0.0
    relationship_coverage: float = 0.0
    authentication_coverage: float = 0.0
    authorization_coverage: float = 0.0
    investigation_coverage: float = 0.0

@dataclass
class QualityReport:
    observation_quality: float = 0.0
    correlation_quality: float = 0.0
    evidence_quality: float = 0.0
    investigation_quality: float = 0.0
    hypothesis_quality: float = 0.0
    explainability_quality: float = 0.0

@dataclass
class PerformanceReport:
    mission_duration_ms: float = 0.0
    memory_usage_mb: float = 0.0
    cpu_usage_percent: float = 0.0
    graph_size: int = 0
    execution_time_ms: float = 0.0
    planner_time_ms: float = 0.0
    correlation_time_ms: float = 0.0
    investigation_time_ms: float = 0.0

@dataclass
class BenchmarkScore:
    overall_score: float = 0.0
    technology_score: float = 0.0
    framework_score: float = 0.0
    endpoint_score: float = 0.0
    business_object_score: float = 0.0
    relationship_score: float = 0.0
    workflow_score: float = 0.0
    authentication_score: float = 0.0
    authorization_score: float = 0.0
    graphql_score: float = 0.0
    javascript_score: float = 0.0
    observation_score: float = 0.0
    correlation_score: float = 0.0
    evidence_score: float = 0.0
    investigation_score: float = 0.0
    hypothesis_score: float = 0.0
    explainability_score: float = 0.0
    runtime_score: float = 0.0
    false_positive_score: float = 0.0
    false_negative_score: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)
