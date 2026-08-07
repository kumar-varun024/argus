import os
import yaml
import pytest
from argus.benchmark.datasets.manager import DatasetManager
from argus.benchmark.datasets.validator import DatasetValidator
from argus.benchmark.framework import BenchmarkFramework

def test_dataset_validator_invalid_dir():
    valid, msg = DatasetValidator.validate_directory("/does/not/exist")
    assert not valid
    assert "not a directory" in msg

def test_manager_load_valid_dataset(tmp_path):
    # Setup mock dataset dir
    ds_dir = tmp_path / "mock_ds"
    ds_dir.mkdir()
    
    with open(ds_dir / "dataset.yaml", "w") as f:
        yaml.dump({
            "id": "mock-1",
            "name": "Mock Test",
            "description": "desc",
            "version": "1.0",
            "category": "auth",
            "target": "http://example.com"
        }, f)
        
    with open(ds_dir / "mission.yaml", "w") as f:
        yaml.dump({
            "scope": {"domains": ["example.com"]}
        }, f)
        
    with open(ds_dir / "ground_truth.yaml", "w") as f:
        yaml.dump({
            "expected_technologies": ["React"]
        }, f)
        
    manager = DatasetManager()
    ds = manager.import_dataset(str(ds_dir))
    
    assert ds.id == "mock-1"
    assert ds.target == "http://example.com"
    assert ds.expected_technologies == ["React"]
    
def test_framework_integration(tmp_path):
    ds_dir = tmp_path / "mock_ds_2"
    ds_dir.mkdir()
    
    with open(ds_dir / "dataset.yaml", "w") as f:
        yaml.dump({
            "id": "mock-2",
            "name": "Mock Framework Test",
            "description": "desc",
            "version": "1.0",
            "category": "auth",
            "target": "http://example.com"
        }, f)
        
    with open(ds_dir / "mission.yaml", "w") as f:
        yaml.dump({}, f)
        
    with open(ds_dir / "ground_truth.yaml", "w") as f:
        yaml.dump({}, f)
        
    framework = BenchmarkFramework()
    framework.load_datasets(str(tmp_path))
    
    # Verify it was loaded into the runner registry
    assert len(framework.list_benchmarks()) == 1
    assert framework.registry.get("mock-2") is not None
