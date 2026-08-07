from pydantic import BaseModel, Field
from typing import List, Dict, Any

class DatasetManifestSchema(BaseModel):
    """Schema for validating dataset.yaml"""
    id: str
    name: str
    description: str
    version: str
    schema_version: str = "1.0"
    category: str
    target: str
    metadata: Dict[str, Any] = Field(default_factory=dict)

class MissionConfigSchema(BaseModel):
    """Schema for validating mission.yaml"""
    scope: Dict[str, Any] = Field(default_factory=dict)
    policy: Dict[str, Any] = Field(default_factory=dict)
    configuration: Dict[str, Any] = Field(default_factory=dict)
    
class GroundTruthSchema(BaseModel):
    """Schema for validating ground_truth.yaml"""
    expected_technologies: List[str] = Field(default_factory=list)
    expected_business_objects: List[str] = Field(default_factory=list)
    expected_workflows: List[str] = Field(default_factory=list)
    expected_investigation_areas: List[str] = Field(default_factory=list)
    expected_routes: List[str] = Field(default_factory=list)
    expected_api_endpoints: List[str] = Field(default_factory=list)
    expected_graphql_types: List[str] = Field(default_factory=list)
    expected_investigations: List[str] = Field(default_factory=list)
    expected_hypotheses: List[str] = Field(default_factory=list)
    expected_correlations: List[str] = Field(default_factory=list)
    expected_evidence: List[str] = Field(default_factory=list)
