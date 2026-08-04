import pytest
from argus.runtime.mission import Mission
from argus.correlation.registry import CorrelationRegistry
from argus.correlation.graph import CorrelationGraph
from argus.correlation.correlation import Correlation

def test_mission_integration():
    mission = Mission("test")
    assert isinstance(mission.correlations, CorrelationRegistry)
    assert isinstance(mission.correlation_graph, CorrelationGraph)
    
    corr = Correlation(title="test", description="test")
    mission.correlations.add(corr)
    
    assert len(mission.correlations.get_all()) == 1

def test_cli_integration(capsys):
    from argus.correlation.cli import correlations_app
    from typer.testing import CliRunner
    
    runner = CliRunner()
    result = runner.invoke(correlations_app, ["list"])
    assert result.exit_code == 0
    assert "Correlations" in result.stdout
