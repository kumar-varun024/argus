from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional

from argus.benchmark.metrics.models import BenchmarkScore, CoverageReport, QualityReport, PerformanceReport
from argus.benchmark.ground_truth.models import ComparisonResult

@dataclass
class BenchmarkArtifacts:
    """Structured storage for artifacts collected during a benchmark mission."""
    mission_results: Dict[str, Any] = field(default_factory=dict)
    execution_metrics: Dict[str, Any] = field(default_factory=dict)
    knowledge_graph: Any = None
    workflow_graph: Any = None
    observations: List[Any] = field(default_factory=list)
    correlations: List[Any] = field(default_factory=list)
    evidence_bundles: List[Any] = field(default_factory=list)
    investigations: List[Any] = field(default_factory=list)
    hypotheses: List[Any] = field(default_factory=list)
    logs: List[str] = field(default_factory=list)
    runtime_statistics: Dict[str, Any] = field(default_factory=dict)

@dataclass
class EvaluationResult:
    """The final structured evaluation result produced by the Evaluation Runner."""
    id: str
    benchmark_id: str
    dataset: str
    runtime: float
    score: Optional[BenchmarkScore] = None
    coverage: Optional[CoverageReport] = None
    quality: Optional[QualityReport] = None
    performance: Optional[PerformanceReport] = None
    comparison: Optional[ComparisonResult] = None
    summary: str = ""
    artifacts: BenchmarkArtifacts = field(default_factory=BenchmarkArtifacts)
    metadata: Dict[str, Any] = field(default_factory=dict)
