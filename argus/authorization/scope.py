from enum import Enum
from dataclasses import dataclass, field
import fnmatch
from urllib.parse import urlparse
import ipaddress
from argus.runtime.manager import mission_manager

class ScopeState(str, Enum):
    IN_SCOPE = "IN_SCOPE"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    UNKNOWN = "UNKNOWN"
    PENDING_REVIEW = "PENDING_REVIEW"

@dataclass
class ScopeDecision:
    target: str
    decision: ScopeState
    matched_rule: str = None
    mission_id: str = None
    source: str = "Mission Scope"

class ScopeResolver:
    """Resolves and enforces authorized mission scope boundaries."""
    
    def check_scope(self, target: str, mission_id: str) -> ScopeDecision:
        """Determines if a target is within the scope of a mission."""
        mission = mission_manager.get_mission(mission_id)
        if not mission:
            return ScopeDecision(target, ScopeState.UNKNOWN, mission_id=mission_id, source="MissionNotFound")
            
        # Try to resolve what kind of target this is
        normalized_target = self.resolve_target(target)
            
        rules = mission.scope
        if not rules:
            return ScopeDecision(normalized_target, ScopeState.OUT_OF_SCOPE, mission_id=mission_id)
            
        for rule in rules:
            if self._match_rule(normalized_target, rule):
                return ScopeDecision(normalized_target, ScopeState.IN_SCOPE, matched_rule=rule, mission_id=mission_id)
                
        return ScopeDecision(normalized_target, ScopeState.OUT_OF_SCOPE, mission_id=mission_id)

    def _match_rule(self, target: str, rule: str) -> bool:
        # Wildcard domain match
        if rule.startswith("*."):
            if target.endswith(rule[2:]) or target == rule[2:]:
                return True
        # Exact match
        if target == rule:
            return True
            
        # Basic IP range support
        if "/" in rule:
            try:
                network = ipaddress.ip_network(rule)
                ip = ipaddress.ip_address(target)
                if ip in network:
                    return True
            except ValueError:
                pass
                
        return fnmatch.fnmatch(target, rule)

    def _is_url(self, target: str) -> bool:
        return target.startswith("http://") or target.startswith("https://")

    def resolve_target(self, target: str) -> str:
        """Normalize target."""
        if self._is_url(target):
            return self.resolve_url(target)
        return target

    def resolve_domain(self, target: str) -> str:
        return self.resolve_target(target)

    def resolve_url(self, url: str) -> str:
        """Extracts the hostname from a URL."""
        try:
            parsed = urlparse(url)
            return parsed.hostname or url
        except Exception:
            return url

    def resolve_ip(self, ip: str) -> str:
        return ip
        
    def resolve_subdomain(self, subdomain: str) -> str:
        return subdomain

    def resolve_resource(self, resource: str) -> str:
        return resource

    def explain_scope_decision(self, decision: ScopeDecision) -> str:
        """Provides a natural language explanation for a scope decision."""
        if decision.decision == ScopeState.IN_SCOPE:
            return f"`{decision.target}` matches the mission's `{decision.matched_rule}` scope rule."
        elif decision.decision == ScopeState.OUT_OF_SCOPE:
            return f"`{decision.target}` does not match any authorized target in this mission."
        else:
            return f"I can't determine that `{decision.target}` is authorized from the current mission scope."
