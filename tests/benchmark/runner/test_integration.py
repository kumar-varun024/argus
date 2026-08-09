import pytest
from argus.benchmark.framework import BenchmarkFramework
from argus.benchmark.models import Benchmark, BenchmarkGroundTruth

def test_evaluation_runner_integration():
    framework = BenchmarkFramework()
    
    benchmark = Benchmark(
        id="test-bench-integration",
        name="Test",
        description="",
        category="cat",
        target="",
        ground_truth=BenchmarkGroundTruth()
    )
    
    framework.register_benchmark(benchmark)
    
    # Run the benchmark via the facade
    result = framework.run_benchmark("test-bench-integration", dry_run=True)
    
    assert result is not None
    assert result.benchmark_id == "test-bench-integration"
    
    # Check if history and storage were updated
    assert len(benchmark.history) == 1
    assert len(benchmark.evaluations) == 1
    assert len(benchmark.artifacts) == 1
    assert "latest_execution_ms" in benchmark.runtime
    
    # Check runner registry
    assert framework.runner.get_status()["total_evaluations"] == 1
