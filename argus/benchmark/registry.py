from typing import Dict, List, Optional
from argus.benchmark.models import Benchmark

class BenchmarkRegistry:
    """Registry of all available benchmarks."""
    
    def __init__(self):
        self._benchmarks: Dict[str, Benchmark] = {}
        
    def register(self, benchmark: Benchmark):
        """Registers a new benchmark."""
        self._benchmarks[benchmark.id] = benchmark
        
    def get(self, benchmark_id: str) -> Optional[Benchmark]:
        """Retrieves a benchmark by ID."""
        return self._benchmarks.get(benchmark_id)
        
    def list_all(self) -> List[Benchmark]:
        """Returns all registered benchmarks."""
        return list(self._benchmarks.values())
        
    def list_by_category(self, category: str) -> List[Benchmark]:
        """Returns benchmarks filtered by category."""
        return [b for b in self._benchmarks.values() if b.category == category]
