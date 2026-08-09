import concurrent.futures
from typing import List, Optional
from argus.benchmark.models import Benchmark
from argus.benchmark.runner.pipeline import EvaluationPipeline
from argus.benchmark.runner.models import EvaluationResult

class BenchmarkExecutor:
    """Executes benchmarks in various modes (Single, Multiple, Suite, Parallel)."""
    
    def __init__(self, framework_registry):
        self.registry = framework_registry
        self.pipeline = EvaluationPipeline()
        
    def run_single(self, benchmark_id: str, dry_run: bool = False) -> EvaluationResult:
        benchmark = self.registry.get(benchmark_id)
        if not benchmark:
            raise ValueError(f"Benchmark {benchmark_id} not found in registry.")
        return self.pipeline.run(benchmark, dry_run=dry_run)
        
    def run_multiple(self, benchmark_ids: List[str], parallel: bool = False, dry_run: bool = False) -> List[EvaluationResult]:
        results = []
        if parallel:
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
                futures = {executor.submit(self.run_single, bid, dry_run): bid for bid in benchmark_ids}
                for future in concurrent.futures.as_completed(futures):
                    try:
                        results.append(future.result())
                    except Exception as e:
                        print(f"Benchmark failed: {e}")
        else:
            for bid in benchmark_ids:
                results.append(self.run_single(bid, dry_run))
        return results
        
    def run_category(self, category: str, parallel: bool = False, dry_run: bool = False) -> List[EvaluationResult]:
        benchmarks = [b for b in self.registry.list_all() if b.category == category]
        return self.run_multiple([b.id for b in benchmarks], parallel, dry_run)
        
    def run_suite(self, parallel: bool = False, dry_run: bool = False) -> List[EvaluationResult]:
        benchmarks = self.registry.list_all()
        return self.run_multiple([b.id for b in benchmarks], parallel, dry_run)
