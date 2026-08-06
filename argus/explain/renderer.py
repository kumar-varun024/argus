from argus.explain.models import Explanation

class ExplanationRenderer:
    """Renders Explanation objects into human-readable text."""
    
    def render_summary(self, explanation: Explanation) -> str:
        """Renders a comprehensive human-readable summary of the explanation."""
        text = f"Investigation: {explanation.title}\n"
        text += f"Summary: {explanation.summary}\n\n"
        
        text += "Reasoning Chain:\n"
        for step in explanation.reasoning_chain:
            text += f"- [{step.source_type}] {step.description}\n"
            
        if explanation.timeline:
            text += "\nTimeline:\n"
            for event in explanation.timeline:
                text += f"- {event.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}: [{event.event_type}] {event.description}\n"
                
        if explanation.priority_breakdown:
            text += "\nPriority Breakdown:\n"
            for factor, score in explanation.priority_breakdown.items():
                text += f"- {factor}: {score:.2f}\n"
                
        if explanation.confidence_breakdown:
            text += "\nConfidence Breakdown:\n"
            for factor, score in explanation.confidence_breakdown.items():
                text += f"- {factor}: {score:.2f}\n"

        if explanation.manual_validation:
            text += "\nManual Validation Guidelines:\n"
            text += explanation.manual_validation
            text += "\n"
            
        return text
