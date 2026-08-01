from typing import List, Dict, Any
from argus.intelligence.models import Investigation

class BaseAuthenticationHeuristic:
    def run(self, context: Dict[str, Any]) -> List[Investigation]:
        pass

class SessionLifecycleHeuristic(BaseAuthenticationHeuristic):
    def run(self, context: Dict[str, Any]) -> List[Investigation]:
        invs = []
        sessions = context.get('sessions', [])
        for s in sessions:
            if s.mechanism == "Cookie" and not (s.secure_flag and s.http_only):
                inv = Investigation(
                    title=f"Review Session Cookie attributes: {s.name}",
                    category="Session Lifecycle",
                    affected_objects=[s.name],
                    reasoning=f"The session cookie '{s.name}' might lack Secure or HttpOnly flags. This could allow XSS or MiTM extraction.",
                    supporting_evidence=[f"Cookie: {s.name}", f"Secure: {s.secure_flag}", f"HttpOnly: {s.http_only}"],
                    manual_validation_steps=["1. Capture cookie setting response.", "2. Verify flags."]
                )
                invs.append(inv)
        return invs

class AccountRecoveryHeuristic(BaseAuthenticationHeuristic):
    def run(self, context: Dict[str, Any]) -> List[Investigation]:
        invs = []
        endpoints = context.get('endpoints', [])
        for ep in endpoints:
            path = ep.get("path", "").lower()
            if "reset" in path or "recover" in path or "forgot" in path:
                inv = Investigation(
                    title="Review Account Recovery Workflow",
                    category="Identity Transition",
                    affected_objects=[path],
                    reasoning="Password reset and account recovery flows are high-value targets for account takeover via token leakage, lack of rate-limiting, or host header injection.",
                    supporting_evidence=[f"Recovery endpoint: {path}"],
                    manual_validation_steps=["1. Request a password reset.", "2. Test token expiration.", "3. Test for Host header injection.", "4. Ensure tokens are single-use."]
                )
                invs.append(inv)
        return invs

class OAuthIntegrationHeuristic(BaseAuthenticationHeuristic):
    def run(self, context: Dict[str, Any]) -> List[Investigation]:
        invs = []
        has_oauth = context.get('has_oauth', False)
        if has_oauth:
            inv = Investigation(
                title="Review OAuth Trust Boundaries",
                category="OAuth Integration",
                affected_objects=["OAuth"],
                reasoning="OAuth flows can be vulnerable to CSRF (missing state parameter), open redirects on the callback, or improper token validation.",
                supporting_evidence=["OAuth endpoints detected in API."],
                manual_validation_steps=["1. Verify `state` parameter is used and validated.", "2. Test `redirect_uri` for open redirects.", "3. Check if identity can be spoofed during token exchange."]
            )
            invs.append(inv)
        return invs

AUTHN_HEURISTIC_REGISTRY = [
    SessionLifecycleHeuristic(),
    AccountRecoveryHeuristic(),
    OAuthIntegrationHeuristic()
]
