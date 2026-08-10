import pytest
from unittest.mock import MagicMock
from argus.benchmark.models import Benchmark, BenchmarkGroundTruth
from argus.benchmark.framework import BenchmarkFramework
from argus.runtime.mission import Mission, MissionState

def test_benchmark_registry():
    framework = BenchmarkFramework()
    
    benchmark = Benchmark(
        id="test-bench-1",
        name="Test Benchmark",
        description="Testing the registry",
        category="auth",
        target="http://example.com"
    )
    
    framework.register_benchmark(benchmark)
    
    retrieved = framework.registry.get("test-bench-1")
    assert retrieved is not None
    assert retrieved.name == "Test Benchmark"
    
    all_b = framework.list_benchmarks()
    assert len(all_b) == 1

def test_benchmark_run_mocked():
    framework = BenchmarkFramework()
    
    benchmark = Benchmark(
        id="test-bench-mock",
        name="Mock Benchmark",
        description="Testing the runner",
        category="auth",
        target="http://example.com",
        ground_truth=BenchmarkGroundTruth(
            expected_technologies=["React", "Node"]
        )
    )
    
    framework.register_benchmark(benchmark)
    
    # We use dry_run to bypass execution while still testing the pipeline assembly
    result = framework.run_benchmark(benchmark.id, dry_run=True)
    
    assert result.benchmark_id == "test-bench-mock"
    assert result.metadata["status"] == MissionState.COMPLETED.value
    assert result.metadata["dry_run"] is True
