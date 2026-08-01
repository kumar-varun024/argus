from argus.agents.business_logic.models import BusinessLogicContext

class WorkflowAnalyzer:
    """Analyzes workflow preconditions and dependencies."""
    
    def extract_rules(self, context: BusinessLogicContext) -> list[dict]:
        rules = []
        for wf in context.workflows:
            if wf.dependencies:
                rules.append({
                    "type": "dependency",
                    "workflow": wf.name,
                    "depends_on": wf.dependencies,
                    "description": f"{wf.name} requires prior completion of {', '.join(wf.dependencies)}"
                })
        return rules
