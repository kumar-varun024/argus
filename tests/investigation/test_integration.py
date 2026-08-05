import pytest
from argus.runtime.mission import Mission
from argus.investigation.registry import InvestigationRegistry
from argus.investigation.builder import InvestigationBuilder
from argus.correlation.evidence import EvidenceBundle
from argus.investigation.models import InvestigationCategory
from typer.testing import CliRunner

def test_mission_investigation_integration():
    mission = Mission("test")
    assert hasattr(mission, 'investigations')
    assert isinstance(mission.investigations, InvestigationRegistry)
    assert hasattr(mission, 'investigation_queue')
    assert hasattr(mission, 'reasoning_tree')
    assert hasattr(mission, 'priority_queue')
    assert hasattr(mission, 'priority_scores')

def test_investigation_builder_priority_integration():
    mission = Mission("integration-test")
    b1 = EvidenceBundle(title="Admin Authz Bundle", description="Authz bundle", strength=85, confidence=0.9)
    b1.authorization_context = ["role_check"]
    b1.business_objects = ["Organization"]
    b1.workflows = ["Admin Invitation"]
    mission.evidence_bundles.add(b1)
    
    b2 = EvidenceBundle(title="Tech Bundle", description="Tech discovery bundle", strength=40, confidence=0.5)
    mission.evidence_bundles.add(b2)
    
    builder = InvestigationBuilder(
        mission.investigations,
        mission.evidence_bundles,
        mission.correlations,
        mission.observations
    )
    
    builder.build_all()
    invs = mission.investigations.get_all()
    assert len(invs) > 0
    
    ranked = builder.prioritize_all(mission)
    assert len(ranked) == len(invs)
    assert len(mission.priority_queue) == len(invs)
    assert len(mission.priority_scores) == len(invs)
    assert mission.priority_queue[0] == str(ranked[0].id)

def test_cli_investigation_integration():
    from argus.cli.investigation_cli import investigations_app
    runner = CliRunner()
    
    # Test list
    res_list = runner.invoke(investigations_app, ["list"])
    assert res_list.exit_code == 0
    
    # Test priority
    res_prio = runner.invoke(investigations_app, ["priority"])
    assert res_prio.exit_code == 0
    
    # Test top
    res_top = runner.invoke(investigations_app, ["top", "--limit", "3"])
    assert res_top.exit_code == 0
    
    # Test rank
    res_rank = runner.invoke(investigations_app, ["rank", "--highest"])
    assert res_rank.exit_code == 0
