import pytest
from argus.runtime.mission import Mission
from argus.agents.business_logic.agent import BusinessLogicSpecialist
from argus.agents.business_logic.models import BusinessLogicContext, StateMachine, State
from argus.agents.business_logic.heuristics import BUSINESS_LOGIC_HEURISTIC_REGISTRY, BaseBusinessLogicHeuristic, BusinessHeuristicResult
from argus.agents.business_logic.workflow import WorkflowAnalyzer
from argus.agents.business_logic.states import StateMachineBuilder
from argus.workflows.models import Workflow, WorkflowStep
from argus.intelligence.models import Investigation

def test_workflow_discovery():
    builder = StateMachineBuilder()
    wf = Workflow(name="Order Lifecycle", description="")
    wf.steps.append(WorkflowStep(title="Draft", endpoint="/order", expected_state="Draft"))
    wf.steps.append(WorkflowStep(title="Submit", endpoint="/order", expected_state="Submitted"))
    
    context = BusinessLogicContext(mission_id="1", target="test", workflows=[wf])
    machines = builder.extract(context)
    
    assert len(machines) == 1
    sm = machines[wf.id]
    assert len(sm.states) == 2
    assert any(s.name == "Draft" for s in sm.states)

def test_business_rule_extraction():
    analyzer = WorkflowAnalyzer()
    wf1 = Workflow(name="Refund")
    wf1.dependencies = ["Payment"]
    
    context = BusinessLogicContext(mission_id="1", target="test", workflows=[wf1])
    rules = analyzer.extract_rules(context)
    
    assert len(rules) == 1
    assert rules[0]["type"] == "dependency"
    assert "Payment" in rules[0]["depends_on"]

def test_business_logic_specialist_run():
    mission = Mission(target="test.local")
    wf1 = Workflow(name="Checkout Workflow")
    wf1.steps = [WorkflowStep(title="S1", endpoint="/1"), WorkflowStep(title="S2", endpoint="/2"), WorkflowStep(title="S3", endpoint="/3")]
    wf1.dependencies = ["Login Workflow"]
    
    mission.workflows.append(wf1)
    
    specialist = BusinessLogicSpecialist()
    
    # Run specialist
    specialist.analyze(mission)
    
    assert len(mission.business_logic) > 0
    # Should trigger MissingPrerequisiteHeuristic and ReplayableTransactionHeuristic (checkout) and WorkflowShortcutHeuristic
    titles = [inv.title for inv in mission.business_logic]
    
    assert any("shortcut" in t.lower() for t in titles)
    assert any("replayable" in t.lower() for t in titles)
    assert any("prerequisite" in t.lower() for t in titles)

def test_duplicate_suppression():
    mission = Mission(target="test.local")
    specialist = BusinessLogicSpecialist()
    
    class DupHeuristic(BaseBusinessLogicHeuristic):
        @property
        def id(self) -> str: return "dup"
        def run(self, context):
            inv1 = Investigation(title="A", category="B", affected_objects=["C"])
            inv2 = Investigation(title="A", category="B", affected_objects=["C"])
            return [
                BusinessHeuristicResult(investigation=inv1),
                BusinessHeuristicResult(investigation=inv2)
            ]
            
    h = DupHeuristic()
    specialist.heuristics.append(h)
    
    specialist.analyze(mission)
    
    invs = [inv for inv in mission.business_logic if inv.title == "A"]
    assert len(invs) == 1 # Suppressed exactly one
    
    specialist.heuristics.pop()

def test_plugin_heuristics():
    class PluginHeuristic(BaseBusinessLogicHeuristic):
        @property
        def id(self) -> str: return "plugin_h"
        def run(self, context):
            inv = Investigation(title="Plugin Rule", category="Plugin", affected_objects=["Obj"])
            return [BusinessHeuristicResult(investigation=inv, matched_nodes=[], heuristic_id=self.id)]
            
    BUSINESS_LOGIC_HEURISTIC_REGISTRY.append(PluginHeuristic())
    
    mission = Mission(target="test.local")
    specialist = BusinessLogicSpecialist()
    specialist.analyze(mission)
    
    assert any(inv.title == "Plugin Rule" for inv in mission.business_logic)
    
    BUSINESS_LOGIC_HEURISTIC_REGISTRY.pop()
