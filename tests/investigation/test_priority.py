import pytest
from argus.investigation.priority_engine import PriorityEngine
from argus.investigation.models import Investigation, InvestigationPriority, InvestigationCategory
from argus.investigation.weights import WeightConfig
from argus.investigation.scoring import ScoreCalculator
from argus.investigation.ranking import InvestigationRanker
from argus.correlation.registry import EvidenceBundleRegistry
from argus.correlation.evidence import EvidenceBundle
from argus.runtime.mission import Mission

@pytest.fixture
def registry():
    return EvidenceBundleRegistry()

def test_priority_engine_scoring(registry):
    b = EvidenceBundle(title="T", description="D", strength=80)
    registry.add(b)
    
    config = WeightConfig()
    engine = PriorityEngine(registry, config)
    
    inv = Investigation(title="Admin bypass", summary="S", description="D", category=InvestigationCategory.API)
    inv.evidence_bundles.append(b.id)
    inv.confidence = 0.9  # High confidence
    inv.related_endpoints.append("/api/admin")
    
    priority = engine.evaluate(inv)
    
    assert inv.priority_score > 0
    assert len(inv.priority_explanation) > 0
    assert inv.priority == priority

def test_scoring_all_factors(registry):
    mission = Mission("test-mission")
    mission.scope = ["/api/v1"]
    mission.policy = {"priority_categories": ["Authorization"]}
    mission.technologies = ["python", "graphql"]
    
    calc = ScoreCalculator()
    
    inv = Investigation(
        title="Admin Organization Permission Check",
        summary="Review invitation and role check for admin users",
        description="Detailed review",
        category=InvestigationCategory.AUTHORIZATION,
        confidence=0.95,
        business_objects=["Organization", "Role"],
        workflows=["Organization Onboarding"],
        related_endpoints=["/api/v1/orgs/admin"],
        related_graph_nodes=["node1"],
        related_graph_edges=["edge1"],
        technologies=["graphql"]
    )
    
    score, explanations = calc.calculate(inv, registry, mission)
    
    assert score >= 70.0
    assert any("Authorization context" in e for e in explanations)
    assert any("Administrative workflow" in e for e in explanations)
    assert any("High-value business object" in e for e in explanations)
    assert any("Affects critical workflows" in e for e in explanations)
    assert any("Matches high-priority mission policy" in e for e in explanations)
    assert any("Directly in mission scope" in e for e in explanations)

def test_weight_configuration_validation():
    # Valid config
    valid_cfg = WeightConfig(
        evidence_strength=0.30,
        workflow_importance=0.20,
        business_object_importance=0.20,
        observation_confidence=0.10,
        correlation_confidence=0.10,
        reachability=0.10
    )
    assert valid_cfg is not None

    # Invalid config (sum != 1.0)
    with pytest.raises(ValueError, match="Base weights must sum to 1.0"):
        WeightConfig(
            evidence_strength=0.50,
            workflow_importance=0.50,
            business_object_importance=0.50,
            observation_confidence=0.10,
            correlation_confidence=0.10,
            reachability=0.10
        )

def test_investigation_ranking_sorting(registry):
    engine = PriorityEngine(registry, WeightConfig())
    
    inv1 = Investigation(title="T1", summary="S", description="D", category=InvestigationCategory.API)
    inv1.priority_score = 45.0
    inv1.priority = InvestigationPriority.MEDIUM
    
    inv2 = Investigation(title="T2", summary="S", description="D", category=InvestigationCategory.AUTHORIZATION)
    inv2.priority_score = 95.0
    inv2.priority = InvestigationPriority.CRITICAL
    
    inv3 = Investigation(title="T3", summary="S", description="D", category=InvestigationCategory.API)
    inv3.priority_score = 80.0
    inv3.priority = InvestigationPriority.HIGH
    
    investigations = [inv1, inv2, inv3]
    
    # Highest first
    ranked = InvestigationRanker.rank(investigations, highest_first=True)
    assert ranked[0].id == inv2.id
    assert ranked[1].id == inv3.id
    assert ranked[2].id == inv1.id
    
    # Lowest first
    ranked_lowest = InvestigationRanker.rank(investigations, highest_first=False)
    assert ranked_lowest[0].id == inv1.id
    assert ranked_lowest[1].id == inv3.id
    assert ranked_lowest[2].id == inv2.id

def test_investigation_ranking_filtering():
    inv1 = Investigation(title="T1", summary="S", description="D", category=InvestigationCategory.API)
    inv1.technologies = ["python"]
    inv1.business_objects = ["User"]
    inv1.workflows = ["Login"]
    inv1.priority = InvestigationPriority.LOW
    inv1.priority_score = 25.0

    inv2 = Investigation(title="T2", summary="S", description="D", category=InvestigationCategory.AUTHORIZATION)
    inv2.technologies = ["node"]
    inv2.business_objects = ["Organization"]
    inv2.workflows = ["Invitation"]
    inv2.priority = InvestigationPriority.HIGH
    inv2.priority_score = 85.0

    invs = [inv1, inv2]

    # Filter by category
    f_cat = InvestigationRanker.rank(invs, category="Authorization")
    assert len(f_cat) == 1 and f_cat[0].id == inv2.id

    # Filter by technology
    f_tech = InvestigationRanker.rank(invs, technology="python")
    assert len(f_tech) == 1 and f_tech[0].id == inv1.id

    # Filter by business object
    f_bo = InvestigationRanker.rank(invs, business_object="Organization")
    assert len(f_bo) == 1 and f_bo[0].id == inv2.id

    # Filter by workflow
    f_wf = InvestigationRanker.rank(invs, workflow="Login")
    assert len(f_wf) == 1 and f_wf[0].id == inv1.id

    # Filter by priority
    f_prio = InvestigationRanker.rank(invs, priority=InvestigationPriority.HIGH)
    assert len(f_prio) == 1 and f_prio[0].id == inv2.id

def test_mission_storage(registry):
    engine = PriorityEngine(registry, WeightConfig())
    mission = Mission("storage-test")
    
    inv1 = Investigation(title="Review Admin Route", summary="S", description="D", category=InvestigationCategory.AUTHORIZATION)
    inv1.confidence = 0.9
    inv1.related_endpoints.append("/admin")

    inv2 = Investigation(title="Review Guest Route", summary="S", description="D", category=InvestigationCategory.API)
    inv2.confidence = 0.2
    
    mission.investigations.add(inv1)
    mission.investigations.add(inv2)
    
    ranked = engine.evaluate_all([inv1, inv2], mission)
    
    assert len(mission.priority_queue) == 2
    assert mission.priority_queue[0] == str(ranked[0].id)
    assert str(inv1.id) in mission.priority_scores
    assert str(inv2.id) in mission.priority_scores
    assert mission.priority_scores[str(inv1.id)] == inv1.priority_score

def test_deterministic_scoring(registry):
    engine = PriorityEngine(registry, WeightConfig())
    inv = Investigation(
        title="Admin Organization Authorization",
        summary="Test determinism",
        description="Deterministic review",
        category=InvestigationCategory.AUTHORIZATION,
        confidence=0.85,
        business_objects=["Organization"],
        workflows=["Admin Workflow"]
    )
    
    score1 = engine.evaluate(inv)
    s1, exp1 = inv.priority_score, list(inv.priority_explanation)
    
    for _ in range(50):
        engine.evaluate(inv)
        assert inv.priority_score == s1
        assert inv.priority_explanation == exp1
