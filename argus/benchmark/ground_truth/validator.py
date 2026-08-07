from typing import Dict, Any, Tuple
from pydantic import BaseModel, Field, ValidationError

class GroundTruthSchema(BaseModel):
    """Pydantic schema for validating ground truth definitions."""
    id: str
    dataset: str
    version: str
    expected_technologies: list[str] = Field(default_factory=list)
    expected_frameworks: list[str] = Field(default_factory=list)
    expected_endpoints: list[str] = Field(default_factory=list)
    expected_graphql_types: list[str] = Field(default_factory=list)
    expected_business_objects: list[str] = Field(default_factory=list)
    expected_relationships: list[str] = Field(default_factory=list)
    expected_workflows: list[str] = Field(default_factory=list)
    expected_authentication_flows: list[str] = Field(default_factory=list)
    expected_authorization_boundaries: list[str] = Field(default_factory=list)
    expected_investigation_areas: list[str] = Field(default_factory=list)
    expected_observations: list[str] = Field(default_factory=list)
    expected_correlations: list[str] = Field(default_factory=list)
    expected_evidence_bundles: list[str] = Field(default_factory=list)
    notes: str = ""
    metadata: Dict[str, Any] = Field(default_factory=dict)

class GroundTruthValidator:
    """Validates ground truth definitions against the schema."""
    
    @classmethod
    def validate(cls, data: Dict[str, Any]) -> Tuple[bool, str]:
        """Checks if a raw dictionary conforms to the Ground Truth schema."""
        try:
            GroundTruthSchema(**data)
            return True, ""
        except ValidationError as e:
            return False, f"Invalid Ground Truth schema: {e}"
