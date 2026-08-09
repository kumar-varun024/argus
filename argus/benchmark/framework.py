from typing import List, Optional
from argus.benchmark.models import Benchmark, BenchmarkGroundTruth
from argus.benchmark.registry import BenchmarkRegistry
from argus.benchmark.runner.runner import EvaluationRunner
from argus.benchmark.datasets.manager import DatasetManager
from argus.benchmark.datasets.models import BenchmarkDataset

class BenchmarkFramework:
    """Facade for the Argus Benchmark subsystem."""
    
    def __init__(self):
        self.registry = BenchmarkRegistry()
        self.runner = EvaluationRunner(self.registry)
        self.dataset_manager = DatasetManager()
        
    def register_benchmark(self, benchmark: Benchmark):
        self.registry.register(benchmark)

    def register_dataset_as_benchmark(self, dataset: BenchmarkDataset) -> Benchmark:
        """Converts a Dataset into an executable Benchmark."""
        gt = BenchmarkGroundTruth(
            expected_technologies=dataset.expected_technologies,
            expected_business_objects=dataset.expected_business_objects,
            expected_workflows=dataset.expected_workflows,
            expected_investigation_areas=dataset.expected_investigation_areas,
            expected_routes=dataset.expected_routes,
            expected_api_endpoints=dataset.expected_api_endpoints,
            expected_graphql_types=dataset.expected_graphql_types,
            expected_investigations=dataset.ground_truth.get("expected_investigations", []),
            expected_hypotheses=dataset.ground_truth.get("expected_hypotheses", []),
            expected_correlations=dataset.ground_truth.get("expected_correlations", []),
            expected_evidence=dataset.ground_truth.get("expected_evidence", [])
        )
        
        benchmark = Benchmark(
            id=dataset.id,
            name=dataset.name,
            description=dataset.description,
            category=dataset.category,
            target=dataset.target,
            mission_config=dataset.mission,
            ground_truth=gt,
            metadata=dataset.metadata
        )
        self.registry.register(benchmark)
        return benchmark
        
    def load_datasets(self, directory_path: str):
        """Discovers and registers all datasets in a directory as benchmarks."""
        datasets = self.dataset_manager.load_all_from_directory(directory_path)
        for ds in datasets:
            self.register_dataset_as_benchmark(ds)
            
    def list_benchmarks(self) -> List[Benchmark]:
        return self.registry.list_all()
        
    def run_benchmark(self, benchmark_id: str, dry_run: bool = False) -> 'EvaluationResult':
        """Runs a single benchmark via the new EvaluationRunner."""
        benchmark = self.registry.get(benchmark_id)
        if not benchmark:
            raise ValueError(f"Benchmark {benchmark_id} not found in registry.")
            
        return self.runner.run(benchmark_id, dry_run=dry_run)

# Global instance for CLI usage
benchmark_framework = BenchmarkFramework()
