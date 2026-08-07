from typing import Dict

class ScoringWeights:
    """Configurable weights for the scoring engine."""
    
    # Category weights for the overall score
    CATEGORIES: Dict[str, float] = {
        "coverage": 0.3,
        "quality": 0.4,
        "performance": 0.1,
        "explainability": 0.2
    }
    
    # Weights for individual coverage metrics
    COVERAGE: Dict[str, float] = {
        "technology": 1.0,
        "framework": 1.0,
        "api": 1.5,
        "graphql": 1.0,
        "business_object": 1.5,
        "workflow": 2.0,
        "relationship": 1.0,
        "authentication": 2.0,
        "authorization": 2.0,
        "investigation": 1.5
    }
    
    # Weights for individual quality metrics
    QUALITY: Dict[str, float] = {
        "observation": 1.0,
        "correlation": 1.5,
        "evidence": 1.0,
        "investigation": 2.0,
        "hypothesis": 1.5,
        "explainability": 1.0
    }
    
    # Modifiers
    FALSE_POSITIVE_PENALTY_FACTOR: float = 0.5  # Max penalty 50%
    FALSE_NEGATIVE_PENALTY_FACTOR: float = 1.0  # Missing expected items hits harder
