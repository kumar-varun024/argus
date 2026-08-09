from argus.benchmark.leaderboard.models import LeaderboardEntry, MetricComparison, Classification
from argus.benchmark.leaderboard.thresholds import RegressionThresholds

class MetricComparator:
    
    @staticmethod
    def compare_metric(name: str, baseline: float, current: float, is_lower_better: bool = False) -> MetricComparison:
        diff = current - baseline
        
        # Avoid division by zero
        if baseline == 0:
            pct_diff = 100.0 if current > 0 else 0.0
        else:
            pct_diff = (diff / baseline) * 100.0
            
        threshold = RegressionThresholds.get_threshold(name)
        
        # Determine improvement vs regression based on is_lower_better
        if is_lower_better:
            if diff < 0 and abs(pct_diff) >= 1.0:
                classification = Classification.IMPROVED
            elif diff > 0 and pct_diff > threshold:
                classification = Classification.SIGNIFICANTLY_REGRESSED
            elif diff > 0 and pct_diff > 0:
                classification = Classification.REGRESSED
            else:
                classification = Classification.STABLE
        else:
            if diff > 0 and pct_diff >= 1.0:
                classification = Classification.IMPROVED
            elif diff < 0 and abs(pct_diff) > threshold:
                classification = Classification.SIGNIFICANTLY_REGRESSED
            elif diff < 0 and abs(pct_diff) > 0:
                classification = Classification.REGRESSED
            else:
                classification = Classification.STABLE
                
        return MetricComparison(
            metric_name=name,
            baseline_value=baseline,
            current_value=current,
            absolute_difference=diff,
            percentage_difference=pct_diff,
            classification=classification
        )
        
    @staticmethod
    def check_compatibility(baseline: LeaderboardEntry, current: LeaderboardEntry) -> bool:
        """Returns True if the entries are compatible for comparison."""
        # Must compare the same dataset and version
        if baseline.dataset_id != current.dataset_id or baseline.dataset_version != current.dataset_version:
            return False
            
        return True
