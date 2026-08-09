from typing import Dict, List, Any
from argus.benchmark.runner.models import EvaluationResult

class HistoryManager:
    """Manages evaluation history and provides trend analysis."""
    
    def __init__(self):
        # In-memory storage for history. Could be backed by DB/File in future.
        self.history: Dict[str, List[EvaluationResult]] = {}

    def append(self, result: EvaluationResult):
        """Appends a new evaluation result to the benchmark's history."""
        if result.benchmark_id not in self.history:
            self.history[result.benchmark_id] = []
        self.history[result.benchmark_id].append(result)

    def get_history(self, benchmark_id: str) -> List[EvaluationResult]:
        """Returns the history of evaluations for a benchmark."""
        return self.history.get(benchmark_id, [])

    def get_trend(self, benchmark_id: str) -> Dict[str, Any]:
        """Calculates trend analysis over historical runs."""
        runs = self.get_history(benchmark_id)
        if not runs:
            return {"status": "No history available"}

        scores = [r.score.overall_score for r in runs if r.score]
        return {
            "total_runs": len(runs),
            "latest_score": scores[-1] if scores else 0.0,
            "average_score": sum(scores) / len(scores) if scores else 0.0,
            "highest_score": max(scores) if scores else 0.0,
            "lowest_score": min(scores) if scores else 0.0,
            "trend": "improving" if len(scores) > 1 and scores[-1] >= scores[-2] else "declining"
        }
