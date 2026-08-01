from argus.agents.business_logic.models import BusinessLogicContext, StateMachine

class TransitionAnalyzer:
    """Analyzes and validates allowed state transitions."""
    
    def infer_transitions(self, sm: StateMachine, context: BusinessLogicContext) -> list[dict]:
        transitions = []
        # Mock logic: assume linear transition through the sorted states
        if sm.states:
            sorted_states = sorted(sm.states, key=lambda s: s.name)
            for i in range(len(sorted_states) - 1):
                transitions.append({
                    "from": sorted_states[i].name,
                    "to": sorted_states[i+1].name,
                    "action": f"transition_to_{sorted_states[i+1].name.lower()}"
                })
        return transitions
