import os
import logging
from typing import List, Optional
from argus.benchmark.datasets.registry import DatasetRegistry
from argus.benchmark.datasets.loader import DatasetLoader
from argus.benchmark.datasets.models import BenchmarkDataset

logger = logging.getLogger(__name__)

class DatasetManager:
    """Facade for managing benchmark datasets."""
    
    def __init__(self):
        self.registry = DatasetRegistry()
        
    def import_dataset(self, directory_path: str) -> BenchmarkDataset:
        """Loads, validates, and registers a dataset from a directory."""
        dataset = DatasetLoader.load(directory_path)
        self.registry.register(dataset)
        return dataset
        
    def load_all_from_directory(self, base_dir: str) -> List[BenchmarkDataset]:
        """Discovers and imports all valid datasets within a base directory."""
        loaded = []
        if not os.path.exists(base_dir):
            return loaded
            
        for root, dirs, files in os.walk(base_dir):
            if "dataset.yaml" in files:
                try:
                    ds = self.import_dataset(root)
                    loaded.append(ds)
                except Exception as e:
                    logger.warning(f"Failed to load dataset at {root}: {e}")
        return loaded
        
    def get_dataset(self, dataset_id: str) -> Optional[BenchmarkDataset]:
        return self.registry.find(dataset_id)

    def list_datasets(self) -> List[BenchmarkDataset]:
        return self.registry.list()
