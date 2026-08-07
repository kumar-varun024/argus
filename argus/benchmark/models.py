from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional

@dataclass
class BenchmarkGroundTruth:
    """Defines the expected outcomes for a benchmark mission."""
    expected_investigations: List[str] = field(default_factory=list)
    expected_hypotheses: List[str] = field(default_factory=list)
    expected_correlations: List[str] = field(default_factory=list)
    expected_evidence: List[str] = field(default_factory=list)
    expected_technologies: List[str] = field(default_factory=list)
    expected_business_objects: List[str] = field(default_factory=list)
    expected_workflows: List[str] = field(default_factory=list)
    expected_investigation_areas: List[str] = field(default_factory=list)
    expected_routes: List[str] = field(default_factory=list)
    expected_api_endpoints: List[str] = field(default_factory=list)
    expected_graphql_types: List[str] = field(default_factory=list)

@dataclass
class Benchmark:
    """Definition of a benchmark test."""
    id: str
    name: str
    description: str
    category: str
    target: str
    mission_config: Dict[str, Any] = field(default_factory=dict)
    ground_truth: BenchmarkGroundTruth = field(default_factory=BenchmarkGroundTruth)
    metadata: Dict[str, Any] = field(default_factory=dict)
    dataset_path: Optional[str] = None

@dataclass
class BenchmarkMetrics:
    """Quantitative metrics describing benchmark performance."""
    investigation_recall: float = 0.0
    hypothesis_recall: float = 0.0
    correlation_recall: float = 0.0
    evidence_recall: float = 0.0
    technology_recall: float = 0.0
    business_object_recall: float = 0.0
    total_execution_time_ms: float = 0.0

from argus.benchmark.ground_truth.models import ComparisonResult
from argus.benchmark.metrics.models import BenchmarkScore, CoverageReport, PerformanceReport

@dataclass
class BenchmarkResult:
    """The result of executing a benchmark mission."""
    benchmark_id: str
    mission_id: str
    metrics: BenchmarkMetrics
    scores: Optional[BenchmarkScore] = None
    coverage: Optional[CoverageReport] = None
    performance: Optional[PerformanceReport] = None
    runtime_history: List[Dict[str, Any]] = field(default_factory=list)
    raw_outputs: Dict[str, Any] = field(default_factory=dict)
    ground_truth_comparison: Optional[ComparisonResult] = None
