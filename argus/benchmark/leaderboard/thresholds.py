import os

class RegressionThresholds:
    """Configurable thresholds for detecting regressions."""
    
    # Defaults in percentages (e.g. 2.0 = 2%)
    DEFAULT_OVERALL_SCORE = 2.0
    DEFAULT_INVESTIGATION_QUALITY = 3.0
    DEFAULT_COVERAGE = 2.0
    DEFAULT_FALSE_POSITIVE_INCREASE = 5.0
    DEFAULT_RUNTIME_INCREASE = 10.0
    
    @classmethod
    def get_threshold(cls, metric_name: str) -> float:
        """Retrieves the threshold for a given metric, allowing ENV overrides."""
        env_key = f"ARGUS_THRESHOLD_{metric_name.upper()}"
        if env_key in os.environ:
            return float(os.environ[env_key])
            
        if "overall" in metric_name.lower():
            return cls.DEFAULT_OVERALL_SCORE
        elif "investigation" in metric_name.lower():
            return cls.DEFAULT_INVESTIGATION_QUALITY
        elif "coverage" in metric_name.lower():
            return cls.DEFAULT_COVERAGE
        elif "false_positive" in metric_name.lower() or "fp_" in metric_name.lower():
            return cls.DEFAULT_FALSE_POSITIVE_INCREASE
        elif "runtime" in metric_name.lower() or "memory" in metric_name.lower():
            return cls.DEFAULT_RUNTIME_INCREASE
            
        return 2.0 # Fallback generic threshold
