import pytest
from argus.investigation.generator import InvestigationGenerator
from argus.investigation.registry import InvestigationRegistry
from argus.investigation.confidence import InvestigationConfidenceScorer
from argus.investigation.priority_engine import PriorityEngine
from argus.investigation.weights import WeightConfig
from argus.investigation.manual_validation import ManualValidationGenerator
from argus.investigation.explanation import ReasoningTreeBuilder
from argus.correlation.registry import EvidenceBundleRegistry, CorrelationRegistry, ObservationRegistry
from argus.correlation.evidence import EvidenceBundle

def test_investigation_generator():
    inv_reg = InvestigationRegistry()
    bundle_reg = EvidenceBundleRegistry()
    corr_reg = CorrelationRegistry()
    obs_reg = ObservationRegistry()
    
    conf_scorer = InvestigationConfidenceScorer(bundle_reg)
    prio_engine = PriorityEngine(bundle_reg, WeightConfig())
    val_gen = ManualValidationGenerator()
    reasoning_builder = ReasoningTreeBuilder(bundle_reg, corr_reg, obs_reg)
    
    generator = InvestigationGenerator(inv_reg, conf_scorer, prio_engine, val_gen, reasoning_builder)
    
    bundle = EvidenceBundle(title="Test", description="Test", strength=50, confidence=0.6)
    bundle.business_objects = ["User"]
    bundle_reg.add(bundle)
    
    inv = generator.process_bundle(bundle)
    assert inv is not None
    assert "User" in inv.business_objects
    assert len(inv_reg.get_all()) == 1
    
    # Test deduplication
    bundle2 = EvidenceBundle(title="Test2", description="Test2", strength=60, confidence=0.7)
    bundle2.business_objects = ["User"]
    bundle_reg.add(bundle2)
    
    inv2 = generator.process_bundle(bundle2)
    # Should merge into the same investigation because of shared category and business_object
    assert inv2 == inv
    assert len(inv_reg.get_all()) == 1
    assert len(inv.evidence_bundles) == 2
