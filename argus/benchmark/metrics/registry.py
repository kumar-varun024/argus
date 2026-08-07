from typing import Dict, Optional
from argus.benchmark.metrics.models import BenchmarkScore, CoverageReport, QualityReport, PerformanceReport

class MetricsRegistry:
    """Stores generated metrics, reports, and scores."""
    
    def __init__(self):
        self.scores: Dict[str, BenchmarkScore] = {}
        self.coverage_reports: Dict[str, CoverageReport] = {}
        self.quality_reports: Dict[str, QualityReport] = {}
        self.performance_reports: Dict[str, PerformanceReport] = {}
        
    def register_score(self, mission_id: str, score: BenchmarkScore):
        self.scores[mission_id] = score
        
    def get_score(self, mission_id: str) -> Optional[BenchmarkScore]:
        return self.scores.get(mission_id)
        
    def register_coverage(self, mission_id: str, coverage: CoverageReport):
        self.coverage_reports[mission_id] = coverage
        
    def get_coverage(self, mission_id: str) -> Optional[CoverageReport]:
        return self.coverage_reports.get(mission_id)
        
    def register_quality(self, mission_id: str, quality: QualityReport):
        self.quality_reports[mission_id] = quality
        
    def get_quality(self, mission_id: str) -> Optional[QualityReport]:
        return self.quality_reports.get(mission_id)
        
    def register_performance(self, mission_id: str, performance: PerformanceReport):
        self.performance_reports[mission_id] = performance
        
    def get_performance(self, mission_id: str) -> Optional[PerformanceReport]:
        return self.performance_reports.get(mission_id)
