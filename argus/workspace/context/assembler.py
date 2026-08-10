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
                parts.append(f"- [{o.source_id}] {o.title}: {o.content}")
            parts.append("\n")
            
        if evidence:
            parts.append("### RELEVANT EVIDENCE (Collected Facts)")
            for e in evidence:
                parts.append(f"- [{e.source_id}] {e.title}: {e.content}")
            parts.append("\n")
            
        if hypotheses:
            parts.append("### ACTIVE HYPOTHESES (Unproven Theories)")
            for h in hypotheses:
                parts.append(f"- [{h.source_id}] {h.title}: {h.content}")
            parts.append("\n")
            
        if findings:
            parts.append("### CONFIRMED FINDINGS")
            for f in findings:
                parts.append(f"- [{f.source_id}] {f.title}: {f.content}")
            parts.append("\n")
            
        if graph:
            parts.append("### KNOWLEDGE GRAPH CONTEXT")
            for g in graph:
                parts.append(f"- [{g.source_id}] {g.title}: {g.content}")
            parts.append("\n")
            
        parts.append("=========================================================")
        parts.append("IMPORTANT POLICY:")
        parts.append("1. Do not invent evidence.")
        parts.append("2. Distinguish clearly between facts (Evidence) and guesses (Hypothesis).")
        parts.append("3. If context is contradictory, explicitly tell the user.")
        
        return "\n".join(parts)
