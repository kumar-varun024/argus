import json
from argus.explain.models import Explanation
from argus.explain.renderer import ExplanationRenderer

class ExplanationExporter:
    """Exports Explanation objects into various formats."""
    
    def __init__(self):
        self.renderer = ExplanationRenderer()
        
    def to_json(self, explanation: Explanation) -> str:
        return explanation.model_dump_json(indent=2)
        
    def to_markdown(self, explanation: Explanation) -> str:
        md = f"# Investigation: {explanation.title}\n\n"
        md += f"**Summary**: {explanation.summary}\n\n"
        
        md += "## Timeline\n"
        for event in explanation.timeline:
            md += f"- **{event.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}**: {event.description}\n"
            
        md += "\n## Reasoning Chain\n"
        for step in explanation.reasoning_chain:
            md += f"- **{step.source_type}**: {step.description}\n"
            
        md += "\n## Priority Breakdown\n"
        for k, v in explanation.priority_breakdown.items():
            md += f"- {k}: {v:.2f}\n"

        md += "\n## Confidence Breakdown\n"
        for k, v in explanation.confidence_breakdown.items():
            md += f"- {k}: {v:.2f}\n"
            
        if explanation.manual_validation:
            md += "\n## Manual Validation\n"
            md += explanation.manual_validation
            
        return md

    def to_html(self, explanation: Explanation) -> str:
        # A simple HTML skeleton wrapping the markdown for now
        md_text = self.to_markdown(explanation)
        html = f"<html>\n<head>\n<title>{explanation.title}</title>\n</head>\n<body>\n"
        html += f"<pre>\n{md_text}\n</pre>\n"
        html += "</body>\n</html>"
        return html

    def to_graph_json(self, explanation: Explanation) -> str:
        return explanation.explanation_graph.model_dump_json(indent=2)
