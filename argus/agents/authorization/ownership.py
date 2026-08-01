from argus.agents.authorization.models import AuthzContext
from argus.authorization.analyzer import AuthorizationAnalyzer

class OwnershipAnalyzer:
    """Analyzes ownership chains for cross-tenant and IDOR risks."""
    
    def get_cross_tenant_objects(self, context: AuthzContext) -> list[str]:
        """Identifies objects that could potentially leak across tenants."""
        findings = []
        if context.graph:
            analyzer = AuthorizationAnalyzer(context.graph)
            chains = analyzer.get_ownership_chains()
            for chain in chains:
                if not any("tenant" in node.lower() or "org" in node.lower() for node in chain):
                    findings.append(chain[-1]) # Assuming last node is the resource
        return findings

