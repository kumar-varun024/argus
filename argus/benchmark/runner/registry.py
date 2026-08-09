from typing import Dict, List, Optional
from argus.benchmark.runner.models import EvaluationResult

class EvaluationRegistry:
    """Registry to store and retrieve active and completed evaluations."""
    
    def __init__(self):
        self._evaluations: Dict[str, EvaluationResult] = {}
        
    def register(self, result: EvaluationResult):
        self._evaluations[result.id] = result
        
    def get(self, eval_id: str) -> Optional[EvaluationResult]:
        return self._evaluations.get(eval_id)
        
    def get_by_benchmark(self, benchmark_id: str) -> List[EvaluationResult]:
        return [r for r in self._evaluations.values() if r.benchmark_id == benchmark_id]
        
    def list_all(self) -> List[EvaluationResult]:
        return list(self._evaluations.values())
