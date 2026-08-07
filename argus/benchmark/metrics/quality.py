from argus.benchmark.ground_truth.models import ComparisonResult, MatchStatus
from argus.benchmark.metrics.models import QualityReport
from typing import List

class QualityCalculator:
    """Calculates quality scores from ground truth comparisons."""
    
    @staticmethod
    def _calculate_quality(result: ComparisonResult, category: str) -> float:
        expected = sum(1 for m in result.matches if m.category == category) + \
                   sum(1 for m in result.misses if m.category == category)
                   
        if expected == 0:
            return 100.0
            
        score = 0.0
        for m in result.matches:
            if m.category == category:
                if m.status == MatchStatus.MATCHED:
                    score += 1.0
                elif m.status == MatchStatus.PARTIALLY_MATCHED:
                    score += 0.5
                    
        return (score / expected) * 100.0

    @classmethod
    def calculate(cls, comparison: ComparisonResult) -> QualityReport:
        """Calculates quality metrics normalized to 0-100."""
        
        # Note: Depending on where "Explainability" is tracked, it might not be in comparison categories
        # Let's map available categories. The engine will supply any missing pieces later or default to 0
        return QualityReport(
            observation_quality=cls._calculate_quality(comparison, "Observations"),
            correlation_quality=cls._calculate_quality(comparison, "Correlations"),
            evidence_quality=cls._calculate_quality(comparison, "Evidence Bundles"),
            investigation_quality=cls._calculate_quality(comparison, "Investigation Areas"),
            hypothesis_quality=100.0, # Placeholder until hypothesis tracking is added to MatchResult properly
            explainability_quality=100.0 # Placeholder
        )
