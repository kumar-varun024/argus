from argus.benchmark.metrics.models import CoverageReport, QualityReport, PerformanceReport, BenchmarkScore
from argus.benchmark.metrics.weights import ScoringWeights
from argus.benchmark.ground_truth.models import ComparisonResult

class ScoringEngine:
    """Computes the final deterministic benchmark scorecard."""
    
    @staticmethod
    def _calculate_weighted_average(metrics: dict, weights: dict) -> float:
        total_weight = 0.0
        weighted_sum = 0.0
        
        for key, value in metrics.items():
            weight = weights.get(key, 1.0)
            weighted_sum += value * weight
            total_weight += weight
            
        if total_weight == 0:
            return 0.0
            
        return weighted_sum / total_weight

    @classmethod
    def calculate(cls, 
                  coverage: CoverageReport, 
                  quality: QualityReport, 
                  performance: PerformanceReport, 
                  comparison: ComparisonResult) -> BenchmarkScore:
        """Calculates the final benchmark score."""
        
        # Calculate coverage scores
        coverage_metrics = {
            "technology": coverage.technology_coverage,
            "framework": coverage.framework_coverage,
            "api": coverage.api_coverage,
            "graphql": coverage.graphql_coverage,
            "business_object": coverage.business_object_coverage,
            "workflow": coverage.workflow_coverage,
            "relationship": coverage.relationship_coverage,
            "authentication": coverage.authentication_coverage,
            "authorization": coverage.authorization_coverage,
            "investigation": coverage.investigation_coverage
        }
        overall_coverage = cls._calculate_weighted_average(coverage_metrics, ScoringWeights.COVERAGE)
        
        # Calculate quality scores
        quality_metrics = {
            "observation": quality.observation_quality,
            "correlation": quality.correlation_quality,
            "evidence": quality.evidence_quality,
            "investigation": quality.investigation_quality,
            "hypothesis": quality.hypothesis_quality,
            "explainability": quality.explainability_quality
        }
        overall_quality = cls._calculate_weighted_average(quality_metrics, ScoringWeights.QUALITY)
        
        # Calculate performance score (simplified: 100 for now, could be dynamic based on SLAs)
        overall_performance = 100.0
        
        # False Positives / False Negatives (Penalty system)
        fp_count = len(comparison.unexpected_findings)
        fn_count = len(comparison.misses)
        total_expected = comparison.total_expected if comparison.total_expected > 0 else 1
        
        # Normalize FP/FN to 0-100 scale penalty
        fp_score = min(100.0, (fp_count / total_expected) * 100.0 * ScoringWeights.FALSE_POSITIVE_PENALTY_FACTOR)
        fn_score = min(100.0, (fn_count / total_expected) * 100.0 * ScoringWeights.FALSE_NEGATIVE_PENALTY_FACTOR)
        
        # Combine categories
        categories = {
            "coverage": overall_coverage,
            "quality": overall_quality,
            "performance": overall_performance,
            "explainability": quality.explainability_quality  # Track explainability explicitly in categories
        }
        base_score = cls._calculate_weighted_average(categories, ScoringWeights.CATEGORIES)
        
        # Apply penalties
        overall_score = max(0.0, base_score - (fp_score * 0.2) - (fn_score * 0.2)) # Arbitrary penalty scaling
        
        return BenchmarkScore(
            overall_score=overall_score,
            technology_score=coverage.technology_coverage,
            framework_score=coverage.framework_coverage,
            endpoint_score=coverage.api_coverage,
            business_object_score=coverage.business_object_coverage,
            relationship_score=coverage.relationship_coverage,
            workflow_score=coverage.workflow_coverage,
            authentication_score=coverage.authentication_coverage,
            authorization_score=coverage.authorization_coverage,
            graphql_score=coverage.graphql_coverage,
            javascript_score=100.0, # Placeholder
            observation_score=quality.observation_quality,
            correlation_score=quality.correlation_quality,
            evidence_score=quality.evidence_quality,
            investigation_score=quality.investigation_quality,
            hypothesis_score=quality.hypothesis_quality,
            explainability_score=quality.explainability_quality,
            runtime_score=overall_performance,
            false_positive_score=fp_score,
            false_negative_score=fn_score
        )
