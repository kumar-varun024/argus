import pytest
from argus.plugins.javascript.agent import JavaScriptSpecialist
from argus.runtime.mission import Mission
from argus.evidence.model import Evidence

def test_integration_incremental_analysis():
    specialist = JavaScriptSpecialist()
    mission = Mission("test_target")
    specialist.discover(mission)
    
    # Add identical evidence multiple times
    mission.evidence.add(Evidence(category="JavaScript", value="const secret = '123'; function a() {}", source="file1.js"))
    mission.evidence.add(Evidence(category="JavaScript", value="const secret = '123'; function a() {}", source="file2.js"))
    
    specialist.analyze(mission)
    
    # We should only have 2 symbols (1 function 'a', 1 constant 'secret') because the second payload was identical and skipped due to cache
    assert len(mission.javascript.symbols) == 2
    assert len(mission.javascript.processed_hashes) == 1
