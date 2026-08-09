from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional

@dataclass
class ExecutiveSummary:
    overall_score: float
    strongest_categories: List[str]
    weakest_categories: List[str]
    important_coverage_gaps: List[str]
    investigation_quality: float
    false_positive_rate: float
    false_negative_rate: float
    runtime_performance_ms: float
    comparison_summary: str = ""

@dataclass
class BenchmarkReport:
    """The full report generated from an EvaluationResult."""
    id: str
    benchmark_id: str
    dataset: str
    dataset_version: str
    argus_version: str
    timestamp: str
    
    summary: ExecutiveSummary
    
    overall_score: float
    category_scores: Dict[str, float]
    coverage: Dict[str, float]
    quality: Dict[str, float]
    performance: Dict[str, float]
    
    false_positives: List[Dict[str, Any]]
    false_negatives: List[Dict[str, Any]]
    
    ground_truth_comparison: Dict[str, Any]
    investigation_results: Dict[str, Any]
    explainability_results: Dict[str, Any]
    historical_comparison: Dict[str, Any]
    recommendations: List[str]
    
    artifacts: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
