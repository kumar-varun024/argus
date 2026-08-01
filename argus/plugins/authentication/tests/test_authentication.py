import pytest
from argus.runtime.mission import Mission
from argus.plugins.interfaces import ControlledMission
from argus.plugins.authentication.plugin import AuthenticationPlugin

def test_authentication_intelligence_plugin():
    mission = Mission("test")
    mission.endpoints = [{"path": "/api/reset_password"}, {"path": "/oauth/authorize"}]
    mission.cookies = ["session_id=abc; HttpOnly"]
    mission.tokens = ["ey12345.abc"]
    
    plugin = AuthenticationPlugin()
    controlled = ControlledMission(mission)
    plugin.execute(controlled)
    
    assert len(mission.authentication_workflows) > 0
    titles = [inv.title.lower() for inv in mission.authentication_workflows]
    
    # Should flag session attributes, account recovery, and oauth
    assert any("session cookie" in t for t in titles)
    assert any("recovery workflow" in t for t in titles)
    assert any("oauth trust" in t for t in titles)
    
    # Check extractions
    assert len(mission.sessions) == 1
    assert mission.sessions[0].name == "session_id"
    assert mission.sessions[0].http_only is True
    assert mission.sessions[0].secure_flag is False
