import pytest
from argus.benchmark.runner.executor import BenchmarkExecutor
from argus.benchmark.registry import BenchmarkRegistry
from argus.benchmark.models import Benchmark, BenchmarkGroundTruth

def test_executor_run_single():
    registry = BenchmarkRegistry()
    registry.register(Benchmark(id="b1", name="Test", description="", category="cat1", target="", ground_truth=BenchmarkGroundTruth()))
    
    executor = BenchmarkExecutor(registry)
    result = executor.run_single("b1", dry_run=True)
    
    assert result.benchmark_id == "b1"

def test_executor_run_multiple():
    registry = BenchmarkRegistry()
    registry.register(Benchmark(id="b1", name="Test", description="", category="cat1", target="", ground_truth=BenchmarkGroundTruth()))
    registry.register(Benchmark(id="b2", name="Test", description="", category="cat1", target="", ground_truth=BenchmarkGroundTruth()))
    
    executor = BenchmarkExecutor(registry)
    
    # Sequential
    results = executor.run_multiple(["b1", "b2"], parallel=False, dry_run=True)
    assert len(results) == 2
    
    # Parallel
    results_parallel = executor.run_multiple(["b1", "b2"], parallel=True, dry_run=True)
    assert len(results_parallel) == 2
