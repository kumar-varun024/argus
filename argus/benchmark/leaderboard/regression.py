from argus.benchmark.leaderboard.models import LeaderboardEntry, RegressionReport, Classification, MetricComparison
from argus.benchmark.leaderboard.comparison import MetricComparator

class RegressionDetector:
    
    @staticmethod
    def detect(baseline: LeaderboardEntry, current: LeaderboardEntry) -> RegressionReport:
        if not MetricComparator.check_compatibility(baseline, current):
            return RegressionReport(
                overall_status=Classification.INCOMPATIBLE,
                baseline_id=baseline.id,
                current_id=current.id,
                regressions=[],
                improvements=[],
                stable_metrics=[],
                incompatible_metrics=["dataset_id", "dataset_version"],
                affected_benchmarks=[],
                affected_categories=[],
                recommendations=["Cannot compare incompatible benchmark runs."]
            )
            
        comparisons = []
        
        # Compare Overall
        comparisons.append(MetricComparator.compare_metric("Overall Score", baseline.overall_score, current.overall_score))
        
        # Compare granular explicit scores
        comparisons.append(MetricComparator.compare_metric("Coverage Score", baseline.coverage_score, current.coverage_score))
        comparisons.append(MetricComparator.compare_metric("Investigation Score", baseline.investigation_score, current.investigation_score))
        comparisons.append(MetricComparator.compare_metric("Explainability Score", baseline.explainability_score, current.explainability_score))
        
        # Lower is better for False Positives/Negatives and Runtime
        comparisons.append(MetricComparator.compare_metric("False Positive Rate", baseline.false_positive_score, current.false_positive_score, is_lower_better=True))
        comparisons.append(MetricComparator.compare_metric("False Negative Rate", baseline.false_negative_score, current.false_negative_score, is_lower_better=True))
        comparisons.append(MetricComparator.compare_metric("Runtime Performance", baseline.runtime_score, current.runtime_score, is_lower_better=True))
        
        # Compare Categories
        for cat_name, base_val in baseline.category_scores.items():
            curr_val = current.category_scores.get(cat_name)
            if curr_val is not None:
                # Assuming category scores are "higher is better" unless named otherwise
                is_lower = "runtime" in cat_name.lower() or "memory" in cat_name.lower()
                comparisons.append(MetricComparator.compare_metric(f"Category: {cat_name}", base_val, curr_val, is_lower_better=is_lower))

        regressions = []
        improvements = []
        stable = []
        
        has_significant_regression = False
        affected_categories = set()
        recommendations = []
        
        for comp in comparisons:
            if comp.classification in (Classification.REGRESSED, Classification.SIGNIFICANTLY_REGRESSED):
                regressions.append(comp)
                if comp.classification == Classification.SIGNIFICANTLY_REGRESSED:
                    has_significant_regression = True
                
                # Extract category names for grouping
                if "Category:" in comp.metric_name:
                    affected_categories.add(comp.metric_name.split(":")[1].strip())
                    
                recommendations.append(f"{comp.metric_name} regressed by {abs(comp.percentage_difference):.2f}%.")
            elif comp.classification == Classification.IMPROVED:
                improvements.append(comp)
                recommendations.append(f"{comp.metric_name} improved by {abs(comp.percentage_difference):.2f}%.")
            else:
                stable.append(comp)

        overall_status = Classification.STABLE
        if has_significant_regression:
            overall_status = Classification.SIGNIFICANTLY_REGRESSED
        elif regressions:
            overall_status = Classification.REGRESSED
        elif improvements:
            overall_status = Classification.IMPROVED
            
        return RegressionReport(
            overall_status=overall_status,
            baseline_id=baseline.id,
            current_id=current.id,
            regressions=regressions,
            improvements=improvements,
            stable_metrics=stable,
            incompatible_metrics=[],
            affected_benchmarks=[current.benchmark_id] if current.benchmark_id else [],
            affected_categories=list(affected_categories),
            recommendations=recommendations
        )
