from typing import List
from argus.agents.business_logic.models import BusinessLogicContext, StateMachine, State

class StateMachineBuilder:
    """Extracts state machines from workflows."""
    
    def extract(self, context: BusinessLogicContext) -> dict[str, StateMachine]:
        machines = {}
        for wf in context.workflows:
            # Basic extraction logic for demonstration
            # In reality, this might look at step parameters, naming conventions, or AI inferences
            sm = StateMachine(workflow_id=wf.id, name=f"{wf.name} State Machine")
            
            # Synthesize states based on workflow steps
            states = set()
            for step in wf.steps:
                if step.expected_state:
                    states.add(step.expected_state)
            
            # If no states are explicitly defined, try inferring from step names
            if not states and len(wf.steps) > 1:
                states = {"Draft", "Submitted", "Approved", "Completed"}
                
            sm.states = [State(name=s) for s in sorted(list(states))]
            machines[wf.id] = sm
            
        return machines
