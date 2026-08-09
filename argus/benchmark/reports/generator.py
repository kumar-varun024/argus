import uuid
from datetime import datetime
from typing import List, Dict, Any, Tuple

from argus.benchmark.runner.models import EvaluationResult
from argus.benchmark.reports.models import BenchmarkReport, ExecutiveSummary
from argus.benchmark.ground_truth.models import MatchStatus

class ReportGenerator:
    """Converts EvaluationResults into BenchmarkReports."""
    
    @classmethod
    def generate(cls, eval_result: EvaluationResult, previous_results: List[EvaluationResult] = None) -> BenchmarkReport:
        if previous_results is None:
            previous_results = []
            
        summary = cls._generate_summary(eval_result, previous_results)
        historical_comparison = cls._compare_historical(eval_result, previous_results)
        recommendations = cls._generate_recommendations(summary, historical_comparison)
        
        # Safe extraction for FP/FN
        fps = []
        fns = []
        if eval_result.comparison:
            for unexpected in eval_result.comparison.unexpected_findings:
                fps.append({"category": unexpected.category, "actual": unexpected.actual})
            for miss in eval_result.comparison.misses:
                fns.append({"category": miss.category, "expected": miss.expected})

        # Base category mapping
        category_scores = {}
        coverage_dict = {}
        quality_dict = {}
        performance_dict = {}
        
        if eval_result.coverage:
            coverage_dict = {
                "technology_coverage": eval_result.coverage.technology_coverage,
                "framework_coverage": eval_result.coverage.framework_coverage,
                "api_coverage": eval_result.coverage.api_coverage,
                "graphql_coverage": eval_result.coverage.graphql_coverage,
                "business_object_coverage": eval_result.coverage.business_object_coverage,
                "workflow_coverage": eval_result.coverage.workflow_coverage,
                "relationship_coverage": eval_result.coverage.relationship_coverage,
                "authentication_coverage": eval_result.coverage.authentication_coverage,
                "authorization_coverage": eval_result.coverage.authorization_coverage,
                "investigation_coverage": eval_result.coverage.investigation_coverage
            }
            category_scores.update(coverage_dict)
            
        if eval_result.quality:
            quality_dict = {
                "observation_quality": eval_result.quality.observation_quality,
                "correlation_quality": eval_result.quality.correlation_quality,
                "evidence_quality": eval_result.quality.evidence_quality,
                "investigation_quality": eval_result.quality.investigation_quality,
                "hypothesis_quality": eval_result.quality.hypothesis_quality,
                "explainability_quality": eval_result.quality.explainability_quality
            }
            category_scores.update(quality_dict)
            
        if eval_result.performance:
            performance_dict = {
                "mission_duration_ms": eval_result.performance.mission_duration_ms,
                "execution_time_ms": eval_result.performance.execution_time_ms,
                "memory_usage_mb": eval_result.performance.memory_usage_mb,
                "cpu_usage_percent": eval_result.performance.cpu_usage_percent,
                "graph_size": eval_result.performance.graph_size
            }
            category_scores["runtime_score"] = 100.0 # From scoring logic

        return BenchmarkReport(
            id=str(uuid.uuid4()),
            benchmark_id=eval_result.benchmark_id,
            dataset=eval_result.dataset,
            dataset_version="1.0", # Hardcoded or fetched from metadata
            argus_version="12.0",
            timestamp=datetime.utcnow().isoformat(),
            summary=summary,
            overall_score=eval_result.score.overall_score if eval_result.score else 0.0,
            category_scores=category_scores,
            coverage=coverage_dict,
            quality=quality_dict,
            performance=performance_dict,
            false_positives=fps,
            false_negatives=fns,
            ground_truth_comparison={"total_expected": eval_result.comparison.total_expected} if eval_result.comparison else {},
            investigation_results={}, # Could be populated with specifics
            explainability_results={},
            historical_comparison=historical_comparison,
            recommendations=recommendations,
            artifacts={"has_artifacts": bool(eval_result.artifacts)},
            metadata=eval_result.metadata
        )

    @classmethod
    def _generate_summary(cls, eval_result: EvaluationResult, previous_results: List[EvaluationResult]) -> ExecutiveSummary:
        cov = eval_result.coverage
        qual = eval_result.quality
        perf = eval_result.performance
        score = eval_result.score
        
        # Calculate strongest/weakest categories
        categories = {}
        if cov:
            categories.update(cov.__dict__)
        if qual:
            categories.update(qual.__dict__)
            
        sorted_cats = sorted(categories.items(), key=lambda x: x[1])
        weakest = [k for k, v in sorted_cats[:3]] if sorted_cats else []
        strongest = [k for k, v in reversed(sorted_cats[-3:])] if sorted_cats else []
        
        gaps = [k for k, v in categories.items() if v < 50.0]
        
        comp_summary = ""
        if previous_results:
            last = previous_results[-1]
            diff = (score.overall_score if score else 0.0) - (last.score.overall_score if last.score else 0.0)
            comp_summary = f"Overall score {'improved' if diff >= 0 else 'regressed'} by {abs(diff):.2f} points."

        return ExecutiveSummary(
            overall_score=score.overall_score if score else 0.0,
            strongest_categories=strongest,
            weakest_categories=weakest,
            important_coverage_gaps=gaps,
            investigation_quality=qual.investigation_quality if qual else 0.0,
            false_positive_rate=score.false_positive_score if score else 0.0,
            false_negative_rate=score.false_negative_score if score else 0.0,
            runtime_performance_ms=perf.execution_time_ms if perf else 0.0,
            comparison_summary=comp_summary
        )

    @classmethod
    def _compare_historical(cls, eval_result: EvaluationResult, previous_results: List[EvaluationResult]) -> Dict[str, Any]:
        if not previous_results:
            return {"status": "No historical data available"}
            
        last = previous_results[-1]
        
        def get_trend(current: float, previous: float) -> str:
            if current > previous: return "Improved"
            if current < previous: return "Regressed"
            return "Unchanged"
            
        current_score = eval_result.score.overall_score if eval_result.score else 0.0
        last_score = last.score.overall_score if last.score else 0.0
        
        return {
            "overall_score_trend": get_trend(current_score, last_score),
            "previous_score": last_score,
            "current_score": current_score,
            "difference": current_score - last_score
        }

    @classmethod
    def _generate_recommendations(cls, summary: ExecutiveSummary, historical: Dict[str, Any]) -> List[str]:
        recs = []
        
        for gap in summary.important_coverage_gaps:
            recs.append(f"{gap.replace('_', ' ').title()} is below acceptable threshold. Review detection rules.")
            
        if summary.false_positive_rate > 20.0:
            recs.append("False positive rate is high. Consider tuning correlation confidence thresholds.")
            
        if summary.false_negative_rate > 20.0:
            recs.append("False negative rate is high. Argus is missing expected observations.")
            
        if historical.get("overall_score_trend") == "Regressed":
            recs.append(f"Overall score regressed by {abs(historical.get('difference', 0)):.2f} points compared to the last run.")
            
        return recs
