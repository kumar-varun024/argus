import re
import time
import json
import uuid
import logging
from typing import Dict, Any, Optional
from dataclasses import dataclass, field
import httpx

from argus.authorization.scope import ScopeResolver, ScopeDecision, ScopeState
from argus.authorization.gate import authorization_gate, AuthDecision
from argus.evidence.model import Evidence, ProvenanceData

logger = logging.getLogger(__name__)

SENSITIVE_HEADERS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "apikey",
    "token",
    "access-token",
    "session",
    "session-id",
    "sessionid"
}

SENSITIVE_PARAM_PATTERNS = [
    re.compile(r'(api[_-]?key|token|bearer|access[_-]?token|refresh[_-]?token|pass|password|pwd|session[_-]?(id|token|key)?)=[^&]+', re.IGNORECASE)
]

def sanitize_headers(headers: Optional[Dict[str, str]]) -> Dict[str, str]:
    if not headers:
        return {}
    return {k: ("[REDACTED]" if k.lower() in SENSITIVE_HEADERS else v) for k, v in headers.items()}

def sanitize_url(url: str) -> str:
    for pattern in SENSITIVE_PARAM_PATTERNS:
        url = pattern.sub(r'\1=[REDACTED]', url)
    return url

def sanitize_dict(d: Any) -> Any:
    if isinstance(d, dict):
        new_d = {}
        for k, v in d.items():
            k_lower = k.lower()
            if any(term in k_lower for term in ["key", "token", "password", "secret", "session", "credential"]):
                new_d[k] = "[REDACTED]"
            else:
                new_d[k] = sanitize_dict(v)
        return new_d
    elif isinstance(d, list):
        return [sanitize_dict(item) for item in d]
    return d

def sanitize_body(body: Optional[str]) -> Optional[str]:
    if not body:
        return body
    try:
        data = json.loads(body)
        redacted_data = sanitize_dict(data)
        return json.dumps(redacted_data)
    except Exception:
        pass
    return body

@dataclass
class HttpResponse:
    success: bool
    status_code: Optional[int] = None
    headers: Dict[str, str] = field(default_factory=dict)
    request_headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    url: str = ""
    method: str = ""
    elapsed: float = 0.0
    error: Optional[str] = None
    scope_decision: Optional[ScopeDecision] = None
    authorization_decision: Optional[AuthDecision] = None

class AuthorizedHttpClient:
    """An authorization-aware HTTP client wrapper around httpx."""
    
    def __init__(self):
        self.scope_resolver = ScopeResolver()
        
    def request(
        self,
        mission,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        json: Optional[Any] = None,
        data: Optional[Any] = None,
        timeout: Optional[float] = None,
        action: str = "http_request",
        user_id: str = "system_user"
    ) -> HttpResponse:
        method = method.upper()
        
        # 1. Scope check
        scope_decision = self.scope_resolver.check_scope(url, mission.id)
        if scope_decision.decision != ScopeState.IN_SCOPE:
            logger.warning(
                "HTTP_REQUEST_BLOCKED_SCOPE: Target '%s' is out of scope for mission '%s'",
                sanitize_url(url), mission.id
            )
            return HttpResponse(
                success=False,
                url=url,
                method=method,
                error=f"Blocked by scope: {scope_decision.decision.value}",
                scope_decision=scope_decision
            )
            
        # 2. Authorization check
        auth_decision = authorization_gate.can_execute_action(user_id, action, url, mission.id)
        if not auth_decision.allowed:
            logger.warning(
                "HTTP_REQUEST_BLOCKED_AUTH: Action '%s' denied for target '%s' in mission '%s'",
                action, sanitize_url(url), mission.id
            )
            return HttpResponse(
                success=False,
                url=url,
                method=method,
                error=f"Blocked by authorization: {auth_decision.reason}",
                scope_decision=scope_decision,
                authorization_decision=auth_decision
            )
            
        logger.info(
            "HTTP_REQUEST_AUTHORIZED: Action '%s' allowed for target '%s' in mission '%s'",
            action, sanitize_url(url), mission.id
        )
        
        sanitized_url = sanitize_url(url)
        sanitized_headers = sanitize_headers(headers)
        logger.info("HTTP_REQUEST_STARTED: %s to %s", method, sanitized_url)
        
        start_time = time.time()
        try:
            # We sanitize the query parameters when logging, but pass them raw to the network.
            # Same for headers and body.
            response = httpx.request(
                method=method,
                url=url,
                headers=headers,
                params=params,
                json=json,
                data=data,
                timeout=timeout or 10.0,
                follow_redirects=True
            )
            elapsed = time.time() - start_time
            
            resp_headers = sanitize_headers(dict(response.headers))
            resp_body = sanitize_body(response.text)
            
            logger.info(
                "HTTP_REQUEST_COMPLETED: %s to %s responded with status %s in %.3fs",
                method, sanitized_url, response.status_code, elapsed
            )
            
            http_resp = HttpResponse(
                success=True,
                status_code=response.status_code,
                headers=resp_headers,
                request_headers=sanitized_headers,
                body=resp_body,
                url=url,
                method=method,
                elapsed=elapsed,
                scope_decision=scope_decision,
                authorization_decision=auth_decision
            )
            
            # Generate and add Evidence
            evidence = self._generate_evidence(mission, http_resp, action)
            self._add_evidence_to_mission(mission, evidence)
            logger.info("EVIDENCE_CREATED: Evidence '%s' added to mission '%s'", evidence.evidence_id, mission.id)
            
            return http_resp
            
        except httpx.TimeoutException as e:
            elapsed = time.time() - start_time
            logger.error("HTTP_REQUEST_FAILED: %s to %s failed with error: %s", method, sanitized_url, str(e))
            return HttpResponse(
                success=False,
                url=url,
                method=method,
                elapsed=elapsed,
                error=f"Timeout: {str(e)}",
                scope_decision=scope_decision,
                authorization_decision=auth_decision
            )
        except httpx.RequestError as e:
            elapsed = time.time() - start_time
            logger.error("HTTP_REQUEST_FAILED: %s to %s failed with error: %s", method, sanitized_url, str(e))
            return HttpResponse(
                success=False,
                url=url,
                method=method,
                elapsed=elapsed,
                error=f"Connection error: {str(e)}",
                scope_decision=scope_decision,
                authorization_decision=auth_decision
            )
        except Exception as e:
            elapsed = time.time() - start_time
            logger.error("HTTP_REQUEST_FAILED: %s to %s failed with unexpected error: %s", method, sanitized_url, str(e))
            return HttpResponse(
                success=False,
                url=url,
                method=method,
                elapsed=elapsed,
                error=f"Unexpected error: {str(e)}",
                scope_decision=scope_decision,
                authorization_decision=auth_decision
            )
            
    def _generate_evidence(self, mission, response: HttpResponse, action: str) -> Evidence:
        provenance = ProvenanceData(
            workflow_id=getattr(mission, "active_workflow_id", ""),
            step_id=action
        )
        
        sanitized_url = sanitize_url(response.url)
        
        # Maintain original category "HTTP Response" used in GraphQL tests
        evidence = Evidence(
            mission_id=mission.id,
            source_type="LOG",
            created_by="SYSTEM_GENERATED",
            title=f"HTTP {response.method} to {sanitized_url}",
            description=f"HTTP request to {sanitized_url} completed with status {response.status_code}",
            category="HTTP Response",
            value=response.body or "",
            source=sanitized_url,
            status="UNVERIFIED",
            confidence=1.0,
            severity="info",
            provenance=provenance,
            metadata={
                "method": response.method,
                "url": sanitized_url,
                "status_code": response.status_code,
                "elapsed": response.elapsed,
                "headers": response.headers,
                "request_headers": response.request_headers,
                "action": action,
                "scope_decision": {
                    "decision": response.scope_decision.decision.value if response.scope_decision else None,
                    "matched_rule": response.scope_decision.matched_rule if response.scope_decision else None
                } if response.scope_decision else None,
                "authorization_decision": {
                    "allowed": response.authorization_decision.allowed,
                    "reason": response.authorization_decision.reason
                } if response.authorization_decision else None
            }
        )
        return evidence
        
    def _add_evidence_to_mission(self, mission, evidence: Evidence):
        if hasattr(mission, "evidence") and mission.evidence is not None:
            if hasattr(mission.evidence, "add"):
                mission.evidence.add(evidence)
            elif isinstance(mission.evidence, list):
                mission.evidence.append(evidence)
                
    def get(self, mission, url: str, **kwargs) -> HttpResponse:
        return self.request(mission, "GET", url, **kwargs)
        
    def post(self, mission, url: str, **kwargs) -> HttpResponse:
        return self.request(mission, "POST", url, **kwargs)
        
    def put(self, mission, url: str, **kwargs) -> HttpResponse:
        return self.request(mission, "PUT", url, **kwargs)
        
    def patch(self, mission, url: str, **kwargs) -> HttpResponse:
        return self.request(mission, "PATCH", url, **kwargs)
        
    def delete(self, mission, url: str, **kwargs) -> HttpResponse:
        return self.request(mission, "DELETE", url, **kwargs)
        
    def head(self, mission, url: str, **kwargs) -> HttpResponse:
        return self.request(mission, "HEAD", url, **kwargs)
        
    def options(self, mission, url: str, **kwargs) -> HttpResponse:
        return self.request(mission, "OPTIONS", url, **kwargs)
