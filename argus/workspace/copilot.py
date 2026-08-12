from typing import List, Optional
from dataclasses import dataclass, field
from argus.workspace.context.models import ContextResult, ContextSource

@dataclass
class ResearchOpportunity:
    title: str
    explanation: str
    reason: str
    supporting_evidence: List[str]
    missing_evidence: List[str]
    confidence: str
    priority: str
    expected_value: str
    related_endpoints: List[str]
    related_findings: List[str]
    related_investigation: str
    suggested_verification: str
    status: str = "RECOMMENDED"

class ResearchCopilot:
    """The reasoning layer that identifies gaps and suggests prioritized research opportunities."""
    
    def evaluate(self, context: ContextResult) -> List[ResearchOpportunity]:
        opportunities = []
        
        sources_text = " ".join([s.content.lower() for s in context.sources])
        evidence_sources = [s for s in context.sources if s.semantic_status == "EVIDENCE"]
        
        # Heuristic 1: Duplicate Work / Dead-end Recognition
        # If we see multiple 403s on the same endpoint, mark as dead-end.
        # This is a basic implementation for the heuristic.
        forbidden_count = sum(1 for s in evidence_sources if "403" in s.content or "forbidden" in s.content.lower())
        if forbidden_count >= 3:
            opportunities.append(ResearchOpportunity(
                title="Deprioritize Current Path",
                explanation="We've already tested this endpoint multiple times and received 403 Forbidden.",
                reason="Multiple 403 responses indicate a strong authorization boundary.",
                supporting_evidence=[s.source_id for s in evidence_sources if "403" in s.content],
                missing_evidence=[],
                confidence="High",
                priority="Low",
                expected_value="Low",
                related_endpoints=[],
                related_findings=[],
                related_investigation="",
                suggested_verification="Investigate alternative mutation endpoints instead of repeating the same test.",
                status="DEPRIORITIZED"
            ))
            
        # Heuristic 2: Authorization/BOLA Gap
        # If we see Account A or Object IDs but no Account B comparison
        if "account a" in sources_text and "account b" not in sources_text:
            opportunities.append(ResearchOpportunity(
                title="Cross-Account Authorization Check",
                explanation="We have observed requests using Account A, but need to verify if Account B can access the same object.",
                reason="Testing cross-account access confirms BOLA/IDOR vulnerabilities.",
                supporting_evidence=[s.source_id for s in evidence_sources if "account a" in s.content.lower()],
                missing_evidence=["Account B access attempt to the same object ID"],
                confidence="Medium",
                priority="High",
                expected_value="High - Could prove critical severity IDOR",
                related_endpoints=[],
                related_findings=[],
                related_investigation="",
                suggested_verification="Compare authorized access using a second test account (Account B) with the same object ID.",
                status="RECOMMENDED"
            ))
            
        # Heuristic 3: GraphQL Specialist
        if "graphql" in sources_text and "schema" not in sources_text:
            opportunities.append(ResearchOpportunity(
                title="GraphQL Schema Extraction",
                explanation="A GraphQL endpoint was detected, but we haven't mapped its schema.",
                reason="Mapping the schema is the first step in GraphQL security analysis.",
                supporting_evidence=[s.source_id for s in evidence_sources if "graphql" in s.content.lower()],
                missing_evidence=["GraphQL Introspection / Schema definition"],
                confidence="High",
                priority="Medium",
                expected_value="Medium",
                related_endpoints=[],
                related_findings=[],
                related_investigation="",
                suggested_verification="Run the GraphQL specialist or attempt Introspection query.",
                status="RECOMMENDED"
            ))
            
        # Basic Fallback Opportunity if nothing specific matches
        if not opportunities and evidence_sources:
            opportunities.append(ResearchOpportunity(
                title="Expand Attack Surface",
                explanation="Current evidence is limited. We need to map more application functionality.",
                reason="Insufficient evidence to form a specific hypothesis.",
                supporting_evidence=[s.source_id for s in evidence_sources[:1]],
                missing_evidence=["Additional endpoints", "Business logic workflows"],
                confidence="Low",
                priority="Medium",
                expected_value="Medium",
                related_endpoints=[],
                related_findings=[],
                related_investigation="",
                suggested_verification="Perform general application spidering and functionality mapping.",
                status="RECOMMENDED"
            ))
            
        return opportunities
