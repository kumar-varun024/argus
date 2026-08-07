from typing import Dict, Any, Tuple
from argus.runtime.mission import Mission
from argus.benchmark.ground_truth.models import ComparisonResult
from argus.benchmark.metrics.registry import MetricsRegistry
from argus.benchmark.metrics.models import BenchmarkScore, CoverageReport, QualityReport, PerformanceReport
from argus.benchmark.metrics.coverage import CoverageCalculator
from argus.benchmark.metrics.quality import QualityCalculator
from argus.benchmark.metrics.performance import PerformanceCalculator
from argus.benchmark.metrics.scoring import ScoringEngine

class MetricsEngine:
    """Facade for the Metrics and Scoring subsystem."""
    
    def __init__(self):
        self.registry = MetricsRegistry()
        
    def evaluate(self, mission: Mission, comparison: ComparisonResult, execution_time_ms: float = 0.0) -> Tuple[BenchmarkScore, CoverageReport, QualityReport, PerformanceReport]:
        """Evaluates all metrics for a mission and generates a scorecard."""
        
        # 1. Compute Coverage
        coverage = CoverageCalculator.calculate(comparison)
        self.registry.register_coverage(mission.id, coverage)
        
        # 2. Compute Quality
        quality = QualityCalculator.calculate(comparison)
        self.registry.register_quality(mission.id, quality)
        
        # 3. Compute Performance
        performance = PerformanceCalculator.calculate(mission, execution_time_ms)
        self.registry.register_performance(mission.id, performance)
        
        # 4. Generate Overall Score
        score = ScoringEngine.calculate(coverage, quality, performance, comparison)
        self.registry.register_score(mission.id, score)
        
        return score, coverage, quality, performance
