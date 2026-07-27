import pytest
from argus.agents.registry import AgentRegistry
from argus.agents.scheduler import AgentScheduler
from argus.agents.base import BaseAgent
from argus.agents.results import AgentHealth
from argus.core.mission import Mission

class DummyAgentA(BaseAgent):
    def __init__(self):
        super().__init__(name="AgentA", dependencies=[])
    def think(self, mission): pass
    def execute(self, mission): pass
    def evaluate(self, mission): pass
    def produce(self): return ["A"]

class DummyAgentB(BaseAgent):
    def __init__(self):
        super().__init__(name="AgentB", dependencies=["AgentA"])
    def think(self, mission): pass
    def execute(self, mission): pass
    def evaluate(self, mission): pass
    def produce(self): return ["B"]

class DummyAgentC(BaseAgent):
    def __init__(self):
        super().__init__(name="AgentC", dependencies=["AgentB"])
    def think(self, mission): pass
    def execute(self, mission): pass
    def evaluate(self, mission): pass
    def produce(self): return ["C"]

class FailingAgent(BaseAgent):
    def __init__(self):
        super().__init__(name="FailingAgent", dependencies=[])
    def think(self, mission): pass
    def execute(self, mission): raise ValueError("Crash")
    def evaluate(self, mission): pass

def test_agent_registration():
    registry = AgentRegistry()
    registry.register(DummyAgentA())
    
    with pytest.raises(ValueError):
        registry.register(DummyAgentA())

def test_dependency_resolution():
    registry = AgentRegistry()
    registry.register(DummyAgentC())
    registry.register(DummyAgentA())
    registry.register(DummyAgentB())
    
    order = registry.resolve_execution_order()
    names = [agent.name for agent in order]
    
    assert names == ["AgentA", "AgentB", "AgentC"]

def test_circular_dependency():
    class CircA(BaseAgent):
        def __init__(self): super().__init__("CircA", dependencies=["CircB"])
        def think(self, mission): pass
        def execute(self, mission): pass
        def evaluate(self, mission): pass
        
    class CircB(BaseAgent):
        def __init__(self): super().__init__("CircB", dependencies=["CircA"])
        def think(self, mission): pass
        def execute(self, mission): pass
        def evaluate(self, mission): pass
        
    registry = AgentRegistry()
    registry.register(CircA())
    registry.register(CircB())
    
    with pytest.raises(ValueError):
        registry.resolve_execution_order()

def test_scheduler_execution():
    registry = AgentRegistry()
    registry.register(DummyAgentC())
    registry.register(DummyAgentA())
    registry.register(DummyAgentB())
    
    mission = Mission("test")
    scheduler = AgentScheduler(registry)
    scheduler.run(mission)
    
    assert "AgentA" in mission.agent_results
    assert "AgentB" in mission.agent_results
    assert "AgentC" in mission.agent_results
    
    assert mission.agent_health["AgentA"] == AgentHealth.HEALTHY
    assert mission.agent_metrics["AgentA"].items_produced == 1
    
    # Check duplicate prevention
    scheduler.run(mission)
    # Execution metrics shouldn't double (metrics are overwritten if run again, but we skip)
    assert len(scheduler.executed_agents) == 3

def test_failure_isolation():
    registry = AgentRegistry()
    registry.register(FailingAgent())
    
    mission = Mission("test")
    scheduler = AgentScheduler(registry)
    
    # Should not raise exception
    scheduler.run(mission)
    
    assert mission.agent_health["FailingAgent"] == AgentHealth.FAILED
    assert mission.agent_metrics["FailingAgent"].errors == 1
