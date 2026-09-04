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
            base = rule[2:]
            if target == base or target.endswith("." + base):
                return True
            return False
        # Exact match
        if target == rule:
            return True
            
        # Basic IP range support
        if "/" in rule:
            try:
                network = ipaddress.ip_network(rule, strict=False)
                ip = ipaddress.ip_address(target)
                if ip in network:
                    return True
            except ValueError:
                pass
                
        return fnmatch.fnmatch(target, rule)

    def _is_url(self, target: str) -> bool:
        return target.startswith(("http://", "https://")) or "://" in target

    def resolve_target(self, target: str) -> str:
        """Normalize target by stripping protocol schemes, ports, and trailing paths."""
        if not target or not isinstance(target, str):
            return ""
        target = target.strip()
        if self._is_url(target):
            return self.resolve_url(target)

        # Handle host/path if not CIDR
        if "/" in target:
            try:
                ipaddress.ip_network(target, strict=False)
                return target
            except ValueError:
                target = target.split("/")[0]

        # Handle host:port notation
        if target.startswith("[") and "]" in target:
            # IPv6 with port e.g. [2001:db8::1]:8080 or [::1]
            host_part = target[1:target.index("]")]
            return host_part

        if ":" in target:
            try:
                ipaddress.ip_address(target)
                return target
            except ValueError:
                parts = target.rsplit(":", 1)
                if len(parts) == 2 and parts[1].isdigit():
                    return parts[0]

        return target

    def resolve_domain(self, target: str) -> str:
        return self.resolve_target(target)

    def resolve_url(self, url: str) -> str:
        """Extracts the hostname from a URL."""
        try:
            parsed = urlparse(url)
            host = parsed.hostname or parsed.netloc.split(":")[0]
            if host.startswith("[") and host.endswith("]"):
                host = host[1:-1]
            return host or url
        except Exception:
            return url

    def resolve_ip(self, ip: str) -> str:
        return self.resolve_target(ip)
        
    def resolve_subdomain(self, subdomain: str) -> str:
        return self.resolve_target(subdomain)

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
