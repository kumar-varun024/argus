import pytest
from argus.benchmark.runner.pipeline import EvaluationPipeline
from argus.benchmark.models import Benchmark, BenchmarkGroundTruth

def test_pipeline_dry_run():
    pipeline = EvaluationPipeline()
    benchmark = Benchmark(id="bench-1", name="Test", description="", category="", target="", ground_truth=BenchmarkGroundTruth())
    
    # Run the pipeline in dry-run mode
    result = pipeline.run(benchmark, dry_run=True)
    
    assert result.benchmark_id == "bench-1"
    assert result.runtime == 0.0
    assert result.metadata["dry_run"] is True
    assert result.metadata["status"] == "COMPLETED"
