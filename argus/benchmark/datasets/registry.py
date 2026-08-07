from typing import Dict, List, Optional
from argus.benchmark.datasets.models import BenchmarkDataset

class DatasetRegistry:
    """In-memory registry of loaded datasets."""
    
    def __init__(self):
        self._datasets: Dict[str, BenchmarkDataset] = {}
        
    def register(self, dataset: BenchmarkDataset):
        self._datasets[dataset.id] = dataset
        
    def remove(self, dataset_id: str):
        if dataset_id in self._datasets:
            del self._datasets[dataset_id]
            
    def find(self, dataset_id: str) -> Optional[BenchmarkDataset]:
        return self._datasets.get(dataset_id)
        
    def search(self, query: str) -> List[BenchmarkDataset]:
        query = query.lower()
        return [
            ds for ds in self._datasets.values() 
            if query in ds.id.lower() or query in ds.name.lower() or query in ds.description.lower()
        ]
        
    def list(self) -> List[BenchmarkDataset]:
        return list(self._datasets.values())
        
    def filter(self, category: str) -> List[BenchmarkDataset]:
        return [ds for ds in self._datasets.values() if ds.category == category]
