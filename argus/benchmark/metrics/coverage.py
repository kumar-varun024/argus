from typing import List
from argus.benchmark.ground_truth.models import ComparisonResult, MatchStatus
from argus.benchmark.metrics.models import CoverageReport

class CoverageCalculator:
    """Calculates coverage scores from ground truth comparisons."""
    
    @staticmethod
    def _calculate_ratio(matched: int, expected: int) -> float:
        if expected == 0:
            return 100.0
        return (matched / expected) * 100.0

    @staticmethod
    def _count_matches_by_category(result: ComparisonResult, category: str) -> int:
        return sum(1 for m in result.matches if m.category == category)

    @staticmethod
    def _count_expected_by_category(result: ComparisonResult, category: str) -> int:
        matched = sum(1 for m in result.matches if m.category == category)
        missed = sum(1 for m in result.misses if m.category == category)
        return matched + missed

    @classmethod
    def calculate(cls, comparison: ComparisonResult) -> CoverageReport:
        """Calculates coverage metrics normalized to 0-100."""
        
        def get_coverage(category_name: str) -> float:
            expected = cls._count_expected_by_category(comparison, category_name)
            matched = cls._count_matches_by_category(comparison, category_name)
            return cls._calculate_ratio(matched, expected)

        return CoverageReport(
            technology_coverage=get_coverage("Technologies"),
            framework_coverage=get_coverage("Frameworks"),
            api_coverage=get_coverage("Endpoints"),
            graphql_coverage=get_coverage("GraphQL Types"),
            business_object_coverage=get_coverage("Business Objects"),
            workflow_coverage=get_coverage("Workflows"),
            relationship_coverage=get_coverage("Relationships"),
            authentication_coverage=get_coverage("Authentication Flows"),
            authorization_coverage=get_coverage("Authorization Boundaries"),
            investigation_coverage=get_coverage("Investigation Areas")
        )
