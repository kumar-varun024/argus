import pytest
from argus.correlation.strength import EvidenceStrengthScorer
from argus.correlation.confidence import ConfidenceCalculator
from argus.correlation.evidence import EvidenceBundle
from argus.correlation.registry import ObservationRegistry, CorrelationRegistry
from argus.correlation.observation import Observation
from argus.correlation.models import ObservationCategory, ObservationPriority

def test_evidence_strength_and_confidence():
    obs_reg = ObservationRegistry()
    corr_reg = CorrelationRegistry()
    
    obs1 = Observation(source="t1", category=ObservationCategory.API, title="t", description="t", confidence=0.8, priority=ObservationPriority.LOW)
    obs2 = Observation(source="t2", category=ObservationCategory.API, title="t", description="t", confidence=1.0, priority=ObservationPriority.LOW)
    obs_reg.add(obs1)
    obs_reg.add(obs2)
    
    scorer = EvidenceStrengthScorer(obs_reg, corr_reg)
    conf_calc = ConfidenceCalculator()
    
    bundle = EvidenceBundle(title="T", description="T")
    bundle.observations = [obs1.id, obs2.id]
    bundle.business_objects = ["A", "B"]
    bundle.technologies = ["React"]
    
    strength = scorer.calculate_strength(bundle)
    assert strength > 0
    
    bundle.strength = strength
    confidence = conf_calc.calculate_confidence(bundle)
    assert confidence > 0
