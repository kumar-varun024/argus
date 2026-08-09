import enum
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional
from datetime import datetime

class Classification(str, enum.Enum):
    IMPROVED = "Improved"
    STABLE = "Stable"
    REGRESSED = "Regressed"
    SIGNIFICANTLY_REGRESSED = "Significantly Regressed"
    INCOMPATIBLE = "Incompatible"

@dataclass
class LeaderboardEntry:
    id: str
    benchmark_id: str
    dataset_id: str
    dataset_version: str
    argus_version: str
    commit_sha: str
    timestamp: str
    
    overall_score: float
    category_scores: Dict[str, float] = field(default_factory=dict)
    
    # Granular scores mapping to category_scores, kept for explicit typed access
    coverage_score: float = 0.0
    investigation_score: float = 0.0
    explainability_score: float = 0.0
    false_positive_score: float = 0.0
    false_negative_score: float = 0.0
    runtime_score: float = 0.0
    
    status: str = "completed"
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class MetricComparison:
    metric_name: str
    baseline_value: float
    current_value: float
    absolute_difference: float
    percentage_difference: float
    classification: Classification

@dataclass
class RegressionReport:
    overall_status: Classification
    baseline_id: str
    current_id: str
    
    regressions: List[MetricComparison]
    improvements: List[MetricComparison]
    stable_metrics: List[MetricComparison]
    incompatible_metrics: List[str]
    
    affected_benchmarks: List[str]
    affected_categories: List[str]
    
    recommendations: List[str]
