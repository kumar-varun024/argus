import logging
from pydantic import BaseModel, Field, model_validator

logger = logging.getLogger(__name__)

class WeightConfig(BaseModel):
    """
    Configurable weights for prioritizing investigations.
    Default distribution reflects core priority model out of 1.0 (or 100%).
    """
    evidence_strength: float = Field(0.25, description="Weight for evidence strength (0.0-1.0)")
    workflow_importance: float = Field(0.20, description="Weight for related workflow importance (0.0-1.0)")
    business_object_importance: float = Field(0.20, description="Weight for business object importance (0.0-1.0)")
    observation_confidence: float = Field(0.15, description="Weight for observation confidence (0.0-1.0)")
    correlation_confidence: float = Field(0.10, description="Weight for correlation confidence (0.0-1.0)")
    reachability: float = Field(0.10, description="Weight for reachability/exposure (0.0-1.0)")

    # Optional adjusters and sub-factor multipliers
    administrative_context_bonus: float = Field(1.2, description="Multiplier if admin context is detected")
    authorization_context_bonus: float = Field(1.1, description="Multiplier if authorization context is detected")
    authentication_context_bonus: float = Field(1.1, description="Multiplier if authentication context is detected")
    mission_policy_bonus: float = Field(1.15, description="Multiplier if matches mission policy priorities")
    mission_scope_bonus: float = Field(1.1, description="Multiplier if in mission scope focus")
    graph_completeness_weight: float = Field(0.05, description="Weight for graph completeness bonus")
    technology_confidence_weight: float = Field(0.05, description="Weight for technology confidence bonus")

    @model_validator(mode='after')
    def validate_weights_on_init(self) -> 'WeightConfig':
        self.validate_weights()
        return self

    def validate_weights(self) -> None:
        """Ensure base weights sum to ~1.0"""
        total = (self.evidence_strength + self.workflow_importance + 
                 self.business_object_importance + self.observation_confidence + 
                 self.correlation_confidence + self.reachability)
        if abs(total - 1.0) > 0.01:
            raise ValueError(f"Base weights must sum to 1.0, got {total:.4f}")

    def log_weights(self) -> None:
        logger.info(
            f"Weight applied: evidence_strength={self.evidence_strength}, "
            f"workflow_importance={self.workflow_importance}, "
            f"business_object_importance={self.business_object_importance}, "
            f"observation_confidence={self.observation_confidence}, "
            f"correlation_confidence={self.correlation_confidence}, "
            f"reachability={self.reachability}"
        )
