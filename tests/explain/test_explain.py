import pytest
import uuid
from datetime import datetime, timezone
from typer.testing import CliRunner

from argus.runtime.mission import Mission
from argus.investigation.models import Investigation, InvestigationCategory, InvestigationPriority
from argus.correlation.observation import Observation
from argus.correlation.models import ObservationCategory, ObservationPriority
from argus.correlation.correlation import Correlation
from argus.correlation.evidence import EvidenceBundle
from argus.explain.engine import ExplainabilityEngine
from argus.cli.explain_cli import app as explain_cli_app

runner = CliRunner()

@pytest.fixture
def sample_mission():
    mission = Mission(target="test.com")
    
    # 1. Add Observation
    obs_id = uuid.uuid4()
    obs = Observation(
        id=obs_id,
        source="test_agent",
        category=ObservationCategory.API,
        title="Test Observation",
        description="A test observation.",
        confidence=1.0,
        priority=ObservationPriority.HIGH,
        timestamp=datetime.now(timezone.utc)
    )
    mission.observations.add(obs)
    
    # 2. Add Correlation
    corr_id = uuid.uuid4()
    corr = Correlation(
        id=corr_id,
        title="Test Correlation",
        description="A test correlation.",
        observations=[obs_id],
        confidence=0.9,
        created_at=datetime.now(timezone.utc)
    )
    mission.correlations.add(corr)
    
    # 3. Add Evidence Bundle
    bundle_id = uuid.uuid4()
    bundle = EvidenceBundle(
        id=bundle_id,
        title="Test Evidence Bundle",
        description="A test bundle.",
        observations=[obs_id],
        correlations=[corr_id],
        strength=95,
        confidence=0.9,
        created_at=datetime.now(timezone.utc)
    )
    mission.evidence_bundles.add(bundle)
    
    # 4. Add Investigation
    inv_id = uuid.uuid4()
    inv = Investigation(
        id=inv_id,
        title="Test Investigation",
        summary="A test investigation.",
        description="Detailed description.",
        category=InvestigationCategory.AUTHORIZATION,
        priority=InvestigationPriority.HIGH,
        priority_score=90.0,
        priority_explanation=["High priority test"],
        confidence=0.85,
        observations=[obs_id],
        correlations=[corr_id],
        evidence_bundles=[bundle_id],
        business_objects=["User"],
        workflows=["Login"]
    )
    mission.investigations.add(inv)
    
    return mission, inv.id

def test_explainability_engine_generate(sample_mission):
    mission, inv_id = sample_mission
    inv = mission.investigations.find(inv_id)
    
    engine = ExplainabilityEngine(mission)
    explanation = engine.generate_explanation(inv)
    
    assert str(explanation.investigation_id) == str(inv_id)
    assert explanation.title == "Test Investigation"
    
    # Check reasoning chain
    # We expect steps: Investigation Created, Priority Evaluation, EvidenceBundle, Correlation, Observation
    chain_types = [step.source_type for step in explanation.reasoning_chain]
    assert "Investigation" in chain_types
    assert "Priority" in chain_types
    assert "EvidenceBundle" in chain_types
    assert "Correlation" in chain_types
    assert "Observation" in chain_types
    
    # Check timeline
    # We expect events for: Investigation, EvidenceBundle, Correlation, Observation
    assert len(explanation.timeline) == 4
    
    # Check graph
    assert len(explanation.explanation_graph.nodes) > 0
    node_types = [n.node_type for n in explanation.explanation_graph.nodes]
    assert "Investigation" in node_types
    assert "EvidenceBundle" in node_types
    assert "Correlation" in node_types
    assert "Observation" in node_types
    assert "BusinessObject" in node_types
    assert "Workflow" in node_types

def test_explain_cli_summary(sample_mission, monkeypatch):
    mission, inv_id = sample_mission
    
    def mock_get_mission(*args, **kwargs):
        return mission
    
    import argus.cli.explain_cli
    monkeypatch.setattr(argus.cli.explain_cli, "_get_active_mission", mock_get_mission)
    
    result = runner.invoke(explain_cli_app, ["summary", str(inv_id)])
    assert result.exit_code == 0
    assert "Test Investigation" in result.stdout
    assert "Reasoning Chain" in result.stdout

def test_explain_cli_graph(sample_mission, monkeypatch):
    mission, inv_id = sample_mission
    
    def mock_get_mission(*args, **kwargs):
        return mission
    
    import argus.cli.explain_cli
    monkeypatch.setattr(argus.cli.explain_cli, "_get_active_mission", mock_get_mission)
    
    result = runner.invoke(explain_cli_app, ["graph", str(inv_id)])
    assert result.exit_code == 0
    assert "Explanation Graph for Test Investigation" in result.stdout

def test_explain_cli_timeline(sample_mission, monkeypatch):
    mission, inv_id = sample_mission
    
    def mock_get_mission(*args, **kwargs):
        return mission
    
    import argus.cli.explain_cli
    monkeypatch.setattr(argus.cli.explain_cli, "_get_active_mission", mock_get_mission)
    
    result = runner.invoke(explain_cli_app, ["timeline", str(inv_id)])
    assert result.exit_code == 0
    assert "Timeline for Test Investigation" in result.stdout

def test_explain_cli_export(sample_mission, monkeypatch):
    mission, inv_id = sample_mission
    
    def mock_get_mission(*args, **kwargs):
        return mission
    
    import argus.cli.explain_cli
    monkeypatch.setattr(argus.cli.explain_cli, "_get_active_mission", mock_get_mission)
    
    result = runner.invoke(explain_cli_app, ["export", str(inv_id), "--format", "json"])
    assert result.exit_code == 0
    assert "Test Investigation" in result.stdout
