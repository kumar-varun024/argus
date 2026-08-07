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

def test_benchmark_runner_recall_logic():
    framework = BenchmarkFramework()
    runner = framework.runner
    
    expected = ["vuln-1", "vuln-2", "vuln-3"]
    actual = ["vuln-1", "vuln-3", "vuln-4"]
    
    recall = runner._calculate_recall(expected, actual)
    assert recall == 2 / 3
    
    # Test perfect recall when nothing is expected
    assert runner._calculate_recall([], ["something"]) == 1.0

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
    
    # We mock the controller start to immediately complete the mission
    original_start = framework.runner.controller.start
    def mock_start(mission):
        mission.status = MissionState.COMPLETED
        mission.technologies = ["React", "Express"]
        
    framework.runner.controller.start = mock_start
    
    framework.register_benchmark(benchmark)
    result = framework.run_benchmark(benchmark.id)
    
    # Expected: React, Node
    # Actual: React, Express
    # Recall for tech should be 0.5 (1/2)
    assert result.metrics.technology_recall == 0.5
    assert result.raw_outputs["status"] == MissionState.COMPLETED.value
    
    # Restore original just in case
    framework.runner.controller.start = original_start
