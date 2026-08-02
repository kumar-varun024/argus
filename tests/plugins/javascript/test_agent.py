import pytest
from argus.plugins.javascript.agent import JavaScriptSpecialist
from argus.runtime.mission import Mission

def test_javascript_specialist_initialization():
    specialist = JavaScriptSpecialist()
    assert specialist is not None

def test_javascript_specialist_discover():
    specialist = JavaScriptSpecialist()
    mission = Mission("test_target")
    specialist.discover(mission)
    assert hasattr(mission, "javascript")
    assert mission.javascript is not None

def test_javascript_specialist_generate_investigations():
    specialist = JavaScriptSpecialist()
    mission = Mission("test_target")
    specialist.discover(mission)
    
    from argus.plugins.javascript.models import JavaScriptRoute, JavaScriptSymbol, JavaScriptWebSocket
    mission.javascript.routes.append(JavaScriptRoute(path="/admin/dashboard", route_type="Client", source="app.js"))
    mission.endpoints.append({"url": "https://api.example.com/v1/users", "source": "app.js"})
    mission.javascript.symbols.append(JavaScriptSymbol(name="ENABLE_ADMIN", symbol_type="FeatureFlag", source="app.js"))
    mission.javascript.symbols.append(JavaScriptSymbol(name="Auth0", symbol_type="AuthProvider", source="app.js"))
    mission.javascript.symbols.append(JavaScriptSymbol(name="submitPayment", symbol_type="BusinessWorkflow", source="app.js"))
    mission.javascript.symbols.append(JavaScriptSymbol(name="GraphQL Detected", symbol_type="GraphQLEndpoint", source="app.js"))
    mission.javascript.websocket.append(JavaScriptWebSocket(url="wss://socket.example.com", source="app.js"))
    
    specialist.generate_investigations(mission)
    
    # 7 investigations should have been generated
    assert len(mission.javascript.investigations) == 7
    assert len(mission.investigations) == 7
    
    titles = [i.title for i in mission.investigations]
    assert "Hidden Admin Route Review" in titles
    assert "Hidden API Review" in titles
    assert "Feature Flag Review" in titles
    assert "Client Authorization Review" in titles
    assert "Business Workflow Review" in titles
    assert "GraphQL Configuration Review" in titles
    assert "WebSocket Security Review" in titles
    
    # Ensure no vulnerabilities were explicitly claimed
    for inv in mission.investigations:
        assert "vulnerabilit" not in inv.description.lower()
        assert "vulnerabilit" not in inv.reasoning.lower()
        
        # Must have confidence, priority, manual validation guidance
        assert inv.confidence > 0
        assert inv.priority in ["High", "Medium", "Low", "Critical"]
        assert "Manual validation guidance:" in inv.reasoning
