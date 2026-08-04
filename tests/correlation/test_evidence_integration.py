import pytest
from argus.runtime.mission import Mission
from argus.correlation.registry import EvidenceBundleRegistry

def test_mission_evidence_integration():
    mission = Mission("test")
    assert hasattr(mission, 'evidence_bundles')
    assert isinstance(mission.evidence_bundles, EvidenceBundleRegistry)

def test_cli_evidence_integration(capsys):
    from argus.correlation.cli import evidence_app
    from typer.testing import CliRunner
    
    runner = CliRunner()
    result = runner.invoke(evidence_app, ["list"])
    assert result.exit_code == 0
    assert "Evidence Fusion Engine not initialized on this mission." in result.stdout or "No evidence bundles found" in result.stdout or "Evidence Bundles" in result.stdout
