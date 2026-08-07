import os
import yaml
from typing import Optional

from argus.benchmark.datasets.models import BenchmarkDataset
from argus.benchmark.datasets.validator import DatasetValidator
from argus.benchmark.datasets.schema import DatasetManifestSchema, MissionConfigSchema, GroundTruthSchema

class DatasetLoader:
    """Parses a dataset directory and builds a BenchmarkDataset object."""
    
    @classmethod
    def load(cls, path: str) -> BenchmarkDataset:
        """Loads a dataset from the specified directory path."""
        valid, msg = DatasetValidator.validate_directory(path)
        if not valid:
            raise ValueError(f"Invalid dataset directory at {path}: {msg}")
            
        # Parse YAML files
        manifest_data = cls._read_yaml(os.path.join(path, "dataset.yaml"))
        mission_data = cls._read_yaml(os.path.join(path, "mission.yaml"))
        gt_data = cls._read_yaml(os.path.join(path, "ground_truth.yaml"))
        
        # Validate schemas
        valid, msg = DatasetValidator.validate_manifest(manifest_data)
        if not valid: raise ValueError(f"Manifest Validation Error: {msg}")
            
        valid, msg = DatasetValidator.validate_mission_config(mission_data)
        if not valid: raise ValueError(f"Mission Config Validation Error: {msg}")
            
        valid, msg = DatasetValidator.validate_ground_truth(gt_data)
        if not valid: raise ValueError(f"Ground Truth Validation Error: {msg}")
            
        manifest = DatasetManifestSchema(**manifest_data)
        gt = GroundTruthSchema(**gt_data)
        
        return BenchmarkDataset(
            id=manifest.id,
            name=manifest.name,
            description=manifest.description,
            version=manifest.version,
            category=manifest.category,
            target=manifest.target,
            mission=mission_data,
            ground_truth=gt_data,
            
            # Extract lists directly from validated schema
            expected_technologies=gt.expected_technologies,
            expected_business_objects=gt.expected_business_objects,
            expected_workflows=gt.expected_workflows,
            expected_investigation_areas=gt.expected_investigation_areas,
            expected_routes=gt.expected_routes,
            expected_api_endpoints=gt.expected_api_endpoints,
            expected_graphql_types=gt.expected_graphql_types,
            
            metadata=manifest.metadata
        )

    @classmethod
    def _read_yaml(cls, filepath: str) -> dict:
        with open(filepath, 'r') as f:
            data = yaml.safe_load(f)
            return data if data else {}
