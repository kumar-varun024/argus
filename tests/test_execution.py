import pytest
from argus.core.mission import Mission
from argus.execution.engine import ExecutionEngine
from argus.execution.plan import ExecutionPlan, ExecutionStep
from argus.execution.state import ExecutionStatus
from argus.agents.registry import AgentRegistry
from argus.agents.base import BaseAgent

class MockAgentPass(BaseAgent):
    def __init__(self):
        super().__init__("MockAgentPass", "Passes perfectly.")
    def think(self, mission): pass
    def execute(self, mission): pass
    def evaluate(self, mission): pass
    def produce(self): return ["Passed test."]

class MockAgentFail(BaseAgent):
    def __init__(self):
        super().__init__("MockAgentFail", "Fails predictably.")
    def think(self, mission): pass
    def execute(self, mission): raise Exception("Simulated Failure")
    def evaluate(self, mission): pass

def setup_registry():
    r = AgentRegistry()
    r.register(MockAgentPass())
    r.register(MockAgentFail())
    return r

def test_engine_successful_execution():
    mission = Mission("test")
    engine = ExecutionEngine(setup_registry())
    
    plan = ExecutionPlan(
        title="Success Plan",
        objective="Run normally."
    )
    plan.steps.append(ExecutionStep(order=1, agent="MockAgentPass", action="Test"))
    
    result = engine.execute_plan(plan, mission)
    
    assert result.status == ExecutionStatus.COMPLETED
    assert plan.status == ExecutionStatus.COMPLETED
    assert len(result.step_results) == 1
    assert result.step_results[0].status == ExecutionStatus.COMPLETED
    
    # Mission recording check
    assert len(mission.execution_history) == 1
    assert mission.execution_results[plan.id].status == ExecutionStatus.COMPLETED

def test_engine_failure_handling():
    mission = Mission("test")
    engine = ExecutionEngine(setup_registry())
    
    plan = ExecutionPlan(
        title="Failing Plan",
        objective="Fail gracefully."
    )
    plan.steps.append(ExecutionStep(order=1, agent="MockAgentFail", action="Test"))
    plan.steps.append(ExecutionStep(order=2, agent="MockAgentPass", action="Test"))
    
    result = engine.execute_plan(plan, mission)
    
    # Execution should halt after failure
    assert result.status == ExecutionStatus.FAILED
    assert len(result.step_results) == 1
    assert result.step_results[0].status == ExecutionStatus.FAILED
    
    assert mission.execution_results[plan.id].status == ExecutionStatus.FAILED

def test_validator_blocked():
    mission = Mission("test")
    engine = ExecutionEngine(setup_registry())
    
    plan = ExecutionPlan(
        title="Blocked Plan",
        objective="Should be blocked by missing evidence.",
        required_evidence=["MissingKey"] # This should block the plan based on the strict validator check, unless it's mock
    )
    plan.steps.append(ExecutionStep(order=1, agent="MockAgentPass", action="Test"))
    
    result = engine.execute_plan(plan, mission)
    
    # Because plan.title does not contain 'mock' in lower case, it will fail validator in our simplistic mock check
    assert result.status == ExecutionStatus.BLOCKED
    assert plan.status == ExecutionStatus.BLOCKED
    assert len(result.step_results) == 0

def test_step_validator_missing_input():
    mission = Mission("test")
    engine = ExecutionEngine(setup_registry())
    
    plan = ExecutionPlan(
        title="Mock Plan with Missing Step Input",
        objective="Test step validator."
    )
    plan.steps.append(ExecutionStep(
        order=1, 
        agent="MockAgentPass", 
        action="Test", 
        required_inputs=["not_in_mission"]
    ))
    
    result = engine.execute_plan(plan, mission)
    
    assert result.status == ExecutionStatus.FAILED
    assert len(result.step_results) == 0 # Validator throws before step executes
