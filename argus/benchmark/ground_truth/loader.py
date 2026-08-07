import yaml
from typing import Dict, Any
from argus.benchmark.ground_truth.models import GroundTruth
from argus.benchmark.ground_truth.validator import GroundTruthValidator

class GroundTruthLoader:
    """Loads and instantiates Ground Truth definitions."""
    
    @classmethod
    def load_from_dict(cls, data: Dict[str, Any]) -> GroundTruth:
        """Parses a dictionary into a validated GroundTruth object."""
        valid, msg = GroundTruthValidator.validate(data)
        if not valid:
            raise ValueError(msg)
            
        return GroundTruth(**data)
        
    @classmethod
    def load_from_file(cls, filepath: str) -> GroundTruth:
        """Loads a ground truth from a YAML file."""
        with open(filepath, 'r') as f:
            data = yaml.safe_load(f)
            if not data:
                data = {}
        return cls.load_from_dict(data)
