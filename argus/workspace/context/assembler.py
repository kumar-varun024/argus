from argus.workspace.context.models import ContextResult

class ContextAssembler:
    """Formats a structured ContextResult into a Markdown string for the LLM prompt."""
    
    def assemble(self, result: ContextResult) -> str:
        """Assembles the final context string, explicitly separating semantic categories."""
        parts = []
        
        parts.append("=========================================================")
        parts.append("ARGUS RESEARCH CONTEXT")
        parts.append("=========================================================\n")
        
        if not result.sources:
            parts.append(f"CONTEXT STATUS: {result.context_status}")
            parts.append("No relevant research evidence found for this query.")
            return "\n".join(parts)
            
        parts.append(f"CONTEXT STATUS: {result.context_status}\n")
        
        # Group sources
        observations = [s for s in result.sources if s.semantic_status == "OBSERVATION"]
        evidence = [s for s in result.sources if s.semantic_status == "EVIDENCE"]
        hypotheses = [s for s in result.sources if s.semantic_status == "HYPOTHESIS"]
        findings = [s for s in result.sources if s.semantic_status == "FINDING"]
        graph = [s for s in result.sources if s.semantic_status == "KNOWLEDGE_GRAPH"]
        
        if observations:
            parts.append("### RELEVANT OBSERVATIONS (Unconfirmed Facts)")
            for o in observations:
                parts.append(f"- [Evidence #{o.source_id}] {o.title}: {o.content}")
            parts.append("\n")
            
        if evidence:
            parts.append("### RELEVANT EVIDENCE (Collected Facts)")
            for e in evidence:
                qual = e.metadata.get("strength", "UNKNOWN")
                prov = e.metadata.get("provenance", "UNKNOWN")
                rel = e.metadata.get("relationship", "NONE")
                parts.append(f"- [Evidence #{e.source_id}] {e.title}: {e.content}")
                parts.append(f"  - Quality: {qual} | Provenance: {prov} | Relationship: {rel}")
            parts.append("\n")
            
        if hypotheses:
            parts.append("### ACTIVE HYPOTHESES (Unproven Theories)")
            for h in hypotheses:
                parts.append(f"- [Hypothesis #{h.source_id}] {h.title}: {h.content}")
            parts.append("\n")
            
        if findings:
            parts.append("### CONFIRMED FINDINGS")
            for f in findings:
                parts.append(f"- [Finding #{f.source_id}] {f.title}: {f.content}")
            parts.append("\n")
            
        if graph:
            parts.append("### KNOWLEDGE GRAPH CONTEXT")
            for g in graph:
                parts.append(f"- [{g.source_id}] {g.title}: {g.content}")
            parts.append("\n")
            
        parts.append("=========================================================")
        
        return "\n".join(parts)
