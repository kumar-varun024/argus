from argus.agents.authorization.models import AuthzContext

class PermissionAnalyzer:
    """Analyzes endpoints for function-level authorization risks."""
    
    def get_unprotected_mutations(self, context: AuthzContext) -> list[dict]:
        """Identifies endpoints that perform state mutations but lack clear authorization."""
        findings = []
        for ep in context.endpoints:
            # Assume endpoints are dicts with method, path, and security properties
            method = ep.get("method", "").upper()
            if method in ["POST", "PUT", "PATCH", "DELETE"]:
                if not ep.get("security") or len(ep.get("security", [])) == 0:
                    findings.append(ep)
        return findings
