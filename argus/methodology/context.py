from argus.runtime.mission import Mission
from argus.methodology.models import PlaybookStep

class MethodologyContext:
    """
    Wraps the Mission to provide a filtered, scope-aware context 
    specifically tailored for evaluating and executing a PlaybookStep.
    """
    
    def __init__(self, mission: Mission, step: PlaybookStep):
        self.mission = mission
        self.step = step
        
    def get_scoped_evidence(self):
        # In a real implementation, this would query the evidence store
        # for only the evidence required by the step.
        return self.mission.evidence
        
    def get_relevant_workflows(self):
        # Filters mission.workflows down to those required by the step.
        if not self.step.required_workflows:
            return self.mission.workflows
            
        relevant = []
        # Support either strings or object lists in mission.workflows
        for w in self.mission.workflows:
            name = w.name if hasattr(w, 'name') else str(w)
            if name in self.step.required_workflows:
                relevant.append(w)
        return relevant
