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
from argus.models.test_identity import TestIdentity

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
    raw_body: Optional[str] = None
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
                raw_body=response.text,
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


class AuthenticatedHttpClient(AuthorizedHttpClient):
    """
    A persistent, session-aware, and identity-injected HTTP client that strictly
    enforces mission scope boundaries and provides automated authentication flows.
    """

    def __init__(
        self,
        identity: Optional[TestIdentity] = None,
        proxy: Optional[str] = None,
        verify_ssl: bool = False,
        timeout: float = 10.0,
        max_retries: int = 3,
        backoff_factor: float = 0.5,
        follow_redirects: bool = True,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
    ):
        super().__init__()
        self.identity = identity
        self.proxy = proxy
        self.verify_ssl = verify_ssl
        self.default_timeout = timeout
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        self.follow_redirects = follow_redirects
        self.base_headers = dict(headers or {})

        client_kwargs: Dict[str, Any] = {
            "verify": self.verify_ssl,
            "follow_redirects": self.follow_redirects,
            "timeout": self.default_timeout,
        }
        if cookies:
            client_kwargs["cookies"] = cookies
        if self.proxy:
            client_kwargs["proxy"] = self.proxy

        self._client = httpx.Client(**client_kwargs)

    @property
    def cookies(self) -> httpx.Cookies:
        return self._client.cookies

    def __enter__(self) -> "AuthenticatedHttpClient":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def close(self) -> None:
        if self._client and not self._client.is_closed:
            self._client.close()

    def set_identity(self, identity: Optional[TestIdentity]) -> None:
        self.identity = identity

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
        user_id: str = "system_user",
        identity: Optional[TestIdentity] = None,
        cookies: Optional[Dict[str, str]] = None,
        max_retries: Optional[int] = None,
        backoff_factor: Optional[float] = None,
    ) -> HttpResponse:
        method = method.upper()

        # 1. Strict Scope Check - Block before credential transmission
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

        # 2. Authorization gate check
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

        # 3. Resolve active identity and inject credentials
        active_identity = identity or self.identity
        if active_identity is None and hasattr(mission, "get_active_identity"):
            active_identity = mission.get_active_identity()

        req_headers = dict(self.base_headers)
        if active_identity:
            req_headers.update(active_identity.get_auth_headers())
        if headers:
            req_headers.update(headers)

        req_cookies = dict(cookies or {})
        if active_identity:
            req_cookies.update(active_identity.get_cookies())

        sanitized_url = sanitize_url(url)
        sanitized_headers = sanitize_headers(req_headers)
        logger.info("HTTP_REQUEST_STARTED: %s to %s", method, sanitized_url)

        retries = max_retries if max_retries is not None else self.max_retries
        backoff = backoff_factor if backoff_factor is not None else self.backoff_factor
        request_timeout = timeout or self.default_timeout

        last_error = None
        last_elapsed = 0.0

        for attempt in range(max(1, retries + 1)):
            start_time = time.time()
            try:
                response = self._client.request(
                    method=method,
                    url=url,
                    headers=req_headers,
                    cookies=req_cookies or None,
                    params=params,
                    json=json,
                    data=data,
                    timeout=request_timeout,
                )
                elapsed = time.time() - start_time

                # Sync back any received cookies into active identity session
                if active_identity and response.cookies:
                    active_identity.update_session(cookies=dict(response.cookies))

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
                    raw_body=response.text,
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
                last_elapsed = time.time() - start_time
                last_error = f"Timeout: {str(e)}"
                logger.warning("HTTP_REQUEST_TIMEOUT (attempt %d/%d): %s to %s: %s", attempt + 1, retries + 1, method, sanitized_url, str(e))
            except httpx.RequestError as e:
                last_elapsed = time.time() - start_time
                last_error = f"Connection error: {str(e)}"
                logger.warning("HTTP_REQUEST_CONNECTION_ERROR (attempt %d/%d): %s to %s: %s", attempt + 1, retries + 1, method, sanitized_url, str(e))
            except Exception as e:
                last_elapsed = time.time() - start_time
                last_error = f"Unexpected error: {str(e)}"
                logger.error("HTTP_REQUEST_UNEXPECTED_ERROR: %s to %s: %s", method, sanitized_url, str(e))
                break

            if attempt < retries:
                time.sleep(backoff * (2 ** attempt))

        logger.error("HTTP_REQUEST_FAILED: %s to %s failed after retries: %s", method, sanitized_url, last_error)
        return HttpResponse(
            success=False,
            url=url,
            method=method,
            elapsed=last_elapsed,
            error=last_error,
            scope_decision=scope_decision,
            authorization_decision=auth_decision
        )

    def login(
        self,
        mission,
        identity: Optional[TestIdentity] = None,
        login_url: Optional[str] = None,
        payload: Optional[Dict[str, Any]] = None,
        login_type: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> HttpResponse:
        """
        Executes automated login for the specified or active identity,
        capturing cookies and bearer/JWT tokens into the identity state.
        """
        target_ident = identity or self.identity
        if target_ident is None and hasattr(mission, "get_active_identity"):
            target_ident = mission.get_active_identity()

        target_url = login_url
        if not target_url and target_ident:
            target_url = target_ident.login_url
        if not target_url:
            return HttpResponse(
                success=False,
                url="",
                method="POST",
                error="No login URL provided or configured on identity."
            )

        auth_payload = payload
        if auth_payload is None and target_ident:
            auth_payload = target_ident.login_payload or target_ident.credentials

        auth_type_format = login_type or (target_ident.login_type if target_ident else "json") or "json"

        if str(auth_type_format).lower() == "form":
            resp = self.post(
                mission=mission,
                url=target_url,
                data=auth_payload or {},
                headers=headers,
                identity=target_ident,
                action="http_login",
            )
        else:
            resp = self.post(
                mission=mission,
                url=target_url,
                json=auth_payload or {},
                headers=headers,
                identity=target_ident,
                action="http_login",
            )

        if resp.success and resp.status_code in (200, 201, 204, 301, 302, 303, 307, 308):
            captured_token = None
            raw_text = getattr(resp, "raw_body", None) or resp.body
            if raw_text:
                try:
                    body_json = json.loads(raw_text)
                    if isinstance(body_json, dict):
                        for k in ("token", "access_token", "jwt", "accessToken", "id_token", "bearer", "auth_token"):
                            if k in body_json and isinstance(body_json[k], str):
                                captured_token = body_json[k]
                                break
                            elif "data" in body_json and isinstance(body_json["data"], dict) and k in body_json["data"]:
                                captured_token = body_json["data"][k]
                                break
                except Exception:
                    pass

            if target_ident:
                target_ident.update_session(
                    cookies=dict(self._client.cookies),
                    token=captured_token,
                )

        return resp

