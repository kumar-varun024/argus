from typing import Dict, List, Optional
from argus.benchmark.ground_truth.models import GroundTruth

class GroundTruthRegistry:
    """In-memory storage for loaded Ground Truth definitions."""
    
    def __init__(self):
        self._registry: Dict[str, GroundTruth] = {}
        
    def register(self, gt: GroundTruth):
        """Stores a ground truth definition."""
        self._registry[gt.id] = gt
        
    def get(self, gt_id: str) -> Optional[GroundTruth]:
        """Retrieves ground truth by its ID."""
        return self._registry.get(gt_id)
        
    def get_by_dataset(self, dataset_id: str) -> Optional[GroundTruth]:
        """Retrieves ground truth associated with a specific dataset."""
        for gt in self._registry.values():
            if gt.dataset == dataset_id:
                return gt
        return None
        
    def list_all(self) -> List[GroundTruth]:
        """Lists all registered ground truth definitions."""
        return list(self._registry.values())
