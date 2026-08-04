import pytest
from argus.correlation.fusion import EvidenceFusionEngine
from argus.correlation.registry import ObservationRegistry, CorrelationRegistry, EvidenceBundleRegistry
from argus.correlation.observation import Observation
from argus.correlation.models import ObservationCategory, ObservationPriority

def test_evidence_fusion_engine_creation():
    obs_reg = ObservationRegistry()
    corr_reg = CorrelationRegistry()
    bundle_reg = EvidenceBundleRegistry()
    
    engine = EvidenceFusionEngine(obs_reg, corr_reg, bundle_reg)
    
    obs1 = Observation(source="t", category=ObservationCategory.API, title="t", description="t", confidence=1.0, priority=ObservationPriority.LOW, business_objects=["A"])
    obs2 = Observation(source="t", category=ObservationCategory.API, title="t", description="t", confidence=1.0, priority=ObservationPriority.LOW, business_objects=["A"])
    
    obs_reg.add(obs1)
    obs_reg.add(obs2)
    
    engine.process_mission_state()
    
    bundles = bundle_reg.get_all()
    assert len(bundles) == 1
    
    bundle = bundles[0]
    assert len(bundle.observations) == 2
    assert obs1.id in bundle.observations
    assert obs2.id in bundle.observations
    assert "A" in bundle.business_objects
