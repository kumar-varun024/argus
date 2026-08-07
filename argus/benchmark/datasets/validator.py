import os
from typing import Dict, Any, Tuple
from pydantic import ValidationError

from argus.benchmark.datasets.schema import DatasetManifestSchema, MissionConfigSchema, GroundTruthSchema
from argus.benchmark.datasets.versioning import VersioningManager

class DatasetValidator:
    """Validates the structure and content of a benchmark dataset directory."""
    
    REQUIRED_FILES = ["dataset.yaml", "mission.yaml", "ground_truth.yaml"]
    
    @classmethod
    def validate_directory(cls, path: str) -> Tuple[bool, str]:
        """Checks if a directory is a valid benchmark dataset."""
        if not os.path.isdir(path):
            return False, f"Path {path} is not a directory."
            
        for file in cls.REQUIRED_FILES:
            if not os.path.exists(os.path.join(path, file)):
                return False, f"Missing required file: {file}"
                
        return True, "Valid directory structure"
        
    @classmethod
    def validate_manifest(cls, data: Dict[str, Any]) -> Tuple[bool, str]:
        """Validates dataset.yaml content."""
        try:
            manifest = DatasetManifestSchema(**data)
            if not VersioningManager.is_compatible(manifest.schema_version):
                return False, f"Unsupported schema version: {manifest.schema_version}"
            return True, ""
        except ValidationError as e:
            return False, f"Invalid manifest schema: {e}"

    @classmethod
    def validate_mission_config(cls, data: Dict[str, Any]) -> Tuple[bool, str]:
        try:
            MissionConfigSchema(**data)
            return True, ""
        except ValidationError as e:
            return False, f"Invalid mission config schema: {e}"
            
    @classmethod
    def validate_ground_truth(cls, data: Dict[str, Any]) -> Tuple[bool, str]:
        try:
            GroundTruthSchema(**data)
            return True, ""
        except ValidationError as e:
            return False, f"Invalid ground truth schema: {e}"
