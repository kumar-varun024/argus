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
            
        parts.append(f"CONTEXT STATUS: {result.context_status}")
        if getattr(result, "user_permission_state", None):
            parts.append(f"USER PERMISSION STATE: {result.user_permission_state}")
        if getattr(result, "authorization_scope", None):
            parts.append(f"AUTHORIZATION SCOPE: {result.authorization_scope}")
        parts.append("")
        
        # Group sources
        observations = [s for s in result.sources if s.semantic_status == "OBSERVATION"]
        evidence = [s for s in result.sources if s.semantic_status in ["EVIDENCE", "VECTOR_EVIDENCE"]]
        hypotheses = [s for s in result.sources if s.semantic_status == "HYPOTHESIS"]
        findings = [s for s in result.sources if s.semantic_status in ["FINDING", "VECTOR_FINDING"]]
        graph = [s for s in result.sources if s.semantic_status == "KNOWLEDGE_GRAPH"]
        cve_knowledge = [s for s in result.sources if s.semantic_status == "CVE_KNOWLEDGE"]
        historical_memories = [s for s in result.sources if s.semantic_status == "HISTORICAL_MEMORY"]
        
        # New semantic states
        mission_states = [s for s in result.sources if s.semantic_status == "MISSION_STATE"]
        scopes = [s for s in result.sources if s.semantic_status == "SCOPE"]
        investigations = [s for s in result.sources if s.semantic_status == "INVESTIGATION_STATE"]
        
        if mission_states:
            parts.append("### ACTIVE MISSION STATE")
            for m in mission_states:
                parts.append(m.content)
            parts.append("\n")
            
        if scopes:
            parts.append("### AUTHORIZED SCOPE")
            for sc in scopes:
                parts.append(sc.content)
            parts.append("\n")
            
        if investigations:
            parts.append("### ACTIVE INVESTIGATION")
            for i in investigations:
                parts.append(i.content)
            parts.append("\n")
        
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
                if "strength" in e.metadata or "provenance" in e.metadata or "relationship" in e.metadata:
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

        if cve_knowledge:
            parts.append("### RELEVANT CVE & VULNERABILITY KNOWLEDGE")
            for cve in cve_knowledge:
                cve_id = cve.metadata.get("cve_id") or cve.source_id
                title = cve.title or cve_id
                if not title.startswith(cve_id):
                    header = f"- [{cve_id}] {title}"
                else:
                    header = f"- [{cve_id}]" if title == cve_id else f"- {title}"
                parts.append(header)

                details = []
                sev = cve.metadata.get("severity")
                if sev:
                    details.append(f"Severity: {str(sev).upper()}")
                cvss = cve.metadata.get("cvss_score")
                if cvss is not None and cvss != 0.0:
                    details.append(f"CVSS: {cvss}")
                cwes = cve.metadata.get("cwes")
                if cwes:
                    cwe_str = ", ".join(cwes) if isinstance(cwes, list) else str(cwes)
                    details.append(f"CWE: {cwe_str}")
                prods = cve.metadata.get("affected_products")
                if prods:
                    prod_str = ", ".join(prods) if isinstance(prods, list) else str(prods)
                    details.append(f"Affected: {prod_str}")

                if details:
                    parts.append(f"  - {' | '.join(details)}")
                if cve.content:
                    parts.append(f"  - Description: {cve.content}")
            parts.append("\n")

        if historical_memories:
            parts.append("### RECALLED MEMORIES & HISTORICAL PATTERNS")
            for mem in historical_memories:
                m_type = mem.metadata.get("memory_type") or mem.metadata.get("type", "")
                type_suffix = f" ({m_type})" if m_type else ""
                parts.append(f"- [Memory #{mem.source_id}]{type_suffix} {mem.title}")
                if mem.content:
                    parts.append(f"  - {mem.content}")
            parts.append("\n")

        parts.append("=========================================================")
        
        return "\n".join(parts)
