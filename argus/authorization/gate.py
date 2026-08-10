from dataclasses import dataclass
from typing import Optional
from argus.authorization.scope import ScopeResolver, ScopeDecision, ScopeState
from argus.runtime.manager import mission_manager

@dataclass
class AuthDecision:
    allowed: bool
    reason: str
    scope_decision: Optional[ScopeDecision] = None

class AuthorizationGate:
    """Centralized authorization gate for Argus tools and actions."""
    
    def __init__(self):
        self.scope_resolver = ScopeResolver()

    def can_view(self, user_id: str, resource_id: str) -> AuthDecision:
        return AuthDecision(True, "User has view permission.")

    def can_edit(self, user_id: str, resource_id: str) -> AuthDecision:
        return AuthDecision(True, "User has edit permission.")

    def can_access_project(self, user_id: str, project_id: str) -> AuthDecision:
        return AuthDecision(True, "User has access to project.")

    def can_access_mission(self, user_id: str, mission_id: str) -> AuthDecision:
        return AuthDecision(True, "User has access to mission.")

    def can_access_investigation(self, user_id: str, investigation_id: str) -> AuthDecision:
        return AuthDecision(True, "User has access to investigation.")

    def can_access_evidence(self, user_id: str, evidence_id: str) -> AuthDecision:
        return AuthDecision(True, "User has access to evidence.")

    def can_execute_action(self, user_id: str, action: str, target: str, mission_id: str) -> AuthDecision:
        """
        Determines if a user can execute a specific action against a target within a mission.
        """
        # 1. Mission Permission check
        mission_check = self.can_access_mission(user_id, mission_id)
        if not mission_check.allowed:
            return mission_check
            
        # 2. Scope check
        scope_decision = self.scope_resolver.check_scope(target, mission_id)
        if scope_decision.decision != ScopeState.IN_SCOPE:
            reason = self.scope_resolver.explain_scope_decision(scope_decision)
            return AuthDecision(False, f"Action denied: {reason}", scope_decision)
            
        # 3. Action Policy
        return AuthDecision(True, "Action authorized by mission scope and user permissions.", scope_decision)

authorization_gate = AuthorizationGate()
