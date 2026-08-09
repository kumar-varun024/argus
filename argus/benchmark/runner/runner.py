import logging
from typing import List, Optional
from argus.benchmark.runner.executor import BenchmarkExecutor
from argus.benchmark.runner.history import HistoryManager
from argus.benchmark.runner.registry import EvaluationRegistry
from argus.benchmark.runner.models import EvaluationResult

logger = logging.getLogger(__name__)

class EvaluationRunner:
    """Facade for the Evaluation Runner subsystem."""
    
    def __init__(self, framework_registry):
        self.executor = BenchmarkExecutor(framework_registry)
        self.history = HistoryManager()
        self.registry = EvaluationRegistry()
        self._framework_registry = framework_registry

    def run(self, benchmark_id: str, dry_run: bool = False) -> EvaluationResult:
        """Runs a single benchmark."""
        result = self.executor.run_single(benchmark_id, dry_run=dry_run)
        self._store_result(result)
        return result

    def run_suite(self, parallel: bool = False, dry_run: bool = False) -> List[EvaluationResult]:
        """Runs the full benchmark suite."""
        results = self.executor.run_suite(parallel=parallel, dry_run=dry_run)
        for r in results:
            self._store_result(r)
        return results

    def _store_result(self, result: EvaluationResult):
        self.registry.register(result)
        self.history.append(result)
        
        # Persist into the benchmark's mission storage lists
        benchmark = self._framework_registry.get(result.benchmark_id)
        if benchmark:
            benchmark.evaluations.append(result)
            benchmark.history.append(result)
            benchmark.artifacts.append(result.artifacts)
            benchmark.runtime["latest_execution_ms"] = result.runtime

    def get_status(self) -> dict:
        """Returns the status of the evaluation registry."""
        evals = self.registry.list_all()
        return {
            "total_evaluations": len(evals),
            "latest": evals[-1].id if evals else None
        }

    def get_history(self, benchmark_id: str) -> List[EvaluationResult]:
        return self.history.get_history(benchmark_id)

    def get_trend(self, benchmark_id: str) -> dict:
        return self.history.get_trend(benchmark_id)
