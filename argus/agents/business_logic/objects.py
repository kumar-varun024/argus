from argus.agents.business_logic.models import BusinessLogicContext

class ObjectAnalyzer:
    """Identifies business objects and their relations."""
    
    def get_critical_objects(self, context: BusinessLogicContext) -> list[str]:
        critical = set()
        for wf in context.workflows:
            if wf.risk_score == "High" or wf.risk_score == "Critical":
                critical.update(wf.business_objects)
        return list(critical)
