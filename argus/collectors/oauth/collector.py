"""oauth: Collector orchestration."""
from __future__ import annotations

import logging
import urllib.parse
from typing import Any, Dict, List, Optional, Set

from argus.collectors.base import BaseCollector
from argus.evidence.model import Evidence, ProvenanceData
from argus.graph.node import Node
from argus.http.client import AuthenticatedHttpClient, HttpResponse
from argus.collectors.oauth.models import DEFAULT_OAUTH_PROBE_ROUTES, DEFAULT_PROTECTED_API_ROUTES, LOGIN_ROUTE_PATTERNS, LOGOUT_ROUTE_PATTERNS, OAUTH_AUTH_ROUTE_PATTERNS, OAUTH_TOKEN_ROUTE_PATTERNS, PROTECTED_API_PATTERNS
from argus.collectors.oauth.payloads import OAuthPayloadGenerator
from argus.collectors.oauth.analyzer import OAuthAnalyzer, SessionSecurityAnalyzer, TokenValidationAnalyzer

logger = logging.getLogger(__name__)


class OAuthCollector(BaseCollector):
    """
    Argus Collector for OAuth 2.0 / OpenID Connect token testing and stateful auth validation.
    Orchestrates R1, R2, and R3 security checks across discovered endpoints.
    """

    def __init__(
        self,
        http_client: Optional[Any] = None,
        timeout: float = 10.0,
        payload_generator: Optional[OAuthPayloadGenerator] = None,
        analyzer: Optional[Any] = None,
    ):
        self.custom_http_client = http_client
        self.timeout = timeout
        self.generator = payload_generator or OAuthPayloadGenerator()
        self.oauth_analyzer = analyzer if isinstance(analyzer, OAuthAnalyzer) else OAuthAnalyzer()
        self.token_analyzer = analyzer if isinstance(analyzer, TokenValidationAnalyzer) else TokenValidationAnalyzer()
        self.session_analyzer = analyzer if isinstance(analyzer, SessionSecurityAnalyzer) else SessionSecurityAnalyzer()

    def execute(self, mission: Any) -> List[Evidence]:
        """Plugin adapter entrypoint executing the collector."""
        return self.collect(mission)

    def _execute_request(
        self,
        mission: Any,
        method: str,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        json_data: Optional[Any] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
    ) -> Optional[HttpResponse]:
        """
        Dispatches HTTP requests respecting custom mock clients, MultiIdentitySessionCoordinator,
        or AuthenticatedHttpClient.
        """
        method = method.upper()
        req_headers = dict(headers or {})
        req_cookies = dict(cookies or {})

        try:
            if self.custom_http_client is not None:
                # Mock client with .get / .post
                if method == "GET" and hasattr(self.custom_http_client, "get"):
                    try:
                        return self.custom_http_client.get(
                            mission, url, params=params, headers=req_headers, cookies=req_cookies, timeout=self.timeout
                        )
                    except TypeError:
                        try:
                            return self.custom_http_client.get(url, params=params, headers=req_headers, cookies=req_cookies)
                        except TypeError:
                            return self.custom_http_client.get(url)
                elif method == "POST" and hasattr(self.custom_http_client, "post"):
                    try:
                        return self.custom_http_client.post(
                            mission, url, data=data, json=json_data, headers=req_headers, cookies=req_cookies, timeout=self.timeout
                        )
                    except TypeError:
                        try:
                            return self.custom_http_client.post(url, data=data, json=json_data, headers=req_headers, cookies=req_cookies)
                        except TypeError:
                            return self.custom_http_client.post(url)
                elif hasattr(self.custom_http_client, "request"):
                    try:
                        return self.custom_http_client.request(
                            mission, method, url, params=params, data=data, json=json_data, headers=req_headers, cookies=req_cookies, timeout=self.timeout
                        )
                    except TypeError:
                        return self.custom_http_client.request(method, url)
                elif callable(self.custom_http_client):
                    return self.custom_http_client(url)

            # Production execution with AuthenticatedHttpClient
            with AuthenticatedHttpClient(timeout=self.timeout, max_retries=1) as client:
                if method == "GET":
                    return client.get(mission, url, params=params, headers=req_headers, cookies=req_cookies, timeout=self.timeout)
                elif method == "POST":
                    return client.post(mission, url, data=data, json=json_data, headers=req_headers, cookies=req_cookies, timeout=self.timeout)
                else:
                    return client.request(mission, method, url, params=params, data=data, json=json_data, headers=req_headers, cookies=req_cookies, timeout=self.timeout)

        except Exception as e:
            logger.debug(f"OAuthCollector request failed for {url}: {e}")
            return None

    def _extract_candidate_endpoints(self, raw_mission: Any) -> List[Dict[str, Any]]:
        """
        Extracts candidate endpoints from mission state, categorizing them as
        OAuth authorization endpoints, token endpoints, protected APIs, login, or logout routes.
        """
        candidates: List[Dict[str, Any]] = []
        seen_urls: Set[str] = set()

        endpoints = getattr(raw_mission, "endpoints", []) or []
        for ep in endpoints:
            url = None
            method = "GET"
            params: Dict[str, Any] = {}
            body: Any = None
            headers: Dict[str, str] = {}

            if isinstance(ep, str):
                url = ep
            elif isinstance(ep, dict):
                url = ep.get("url") or ep.get("endpoint") or ep.get("path")
                method = ep.get("method", "GET").upper()
                params = ep.get("params") or {}
                body = ep.get("body")
                headers = ep.get("headers") or {}
            elif hasattr(ep, "url"):
                url = getattr(ep, "url")
                method = getattr(ep, "method", "GET")

            if url and isinstance(url, str) and url not in seen_urls:
                seen_urls.add(url)
                parsed = urllib.parse.urlparse(url)
                base_url = f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else ""
                candidates.append({
                    "url": url,
                    "base_url": base_url,
                    "path": parsed.path or "/",
                    "method": method,
                    "params": params,
                    "body": body,
                    "headers": headers,
                    "query": parsed.query or "",
                    "source": "mission.endpoints",
                })

        # Inspect live_hosts or target
        live_hosts = getattr(raw_mission, "live_hosts", []) or []
        target = getattr(raw_mission, "target", "") or ""
        host_urls: List[str] = []

        for lh in live_hosts:
            if isinstance(lh, str) and lh.startswith("http"):
                host_urls.append(lh)
            elif isinstance(lh, dict) and lh.get("url"):
                host_urls.append(lh["url"])
            elif isinstance(lh, str) and lh:
                host_urls.append(f"http://{lh}")

        if not host_urls and target:
            host_urls.append(target if target.startswith("http") else f"http://{target}")

        for base_url in host_urls:
            parsed_base = urllib.parse.urlparse(base_url)
            clean_base = f"{parsed_base.scheme}://{parsed_base.netloc}" if parsed_base.netloc else base_url

            # If no candidates or very few, seed standard OAuth / API probe routes
            if len(candidates) < 3:
                for route in DEFAULT_OAUTH_PROBE_ROUTES + DEFAULT_PROTECTED_API_ROUTES:
                    probe_url = f"{clean_base.rstrip('/')}{route}"
                    if probe_url not in seen_urls:
                        seen_urls.add(probe_url)
                        candidates.append({
                            "url": probe_url,
                            "base_url": clean_base,
                            "path": route,
                            "method": "GET",
                            "params": {},
                            "body": None,
                            "headers": {},
                            "query": "",
                            "source": "default_probe",
                        })

        return candidates

    def _create_evidence_and_update_state(
        self,
        mission: Any,
        target_url: str,
        base_url: str,
        category: str,
        analysis: Dict[str, Any],
    ) -> Evidence:
        """
        Creates confirmed Evidence object, appends to mission.evidence & mission.vulnerabilities,
        and expands KnowledgeGraph nodes and HAS_ENDPOINT and HAS_VULNERABILITY edges.
        """
        raw_mission = getattr(mission, "_mission", mission)
        template_id = analysis.get("template_id", "oauth-misconfiguration")
        misconfig_type = analysis.get("misconfiguration_type", "generic")
        severity = analysis.get("severity", "high")
        confidence = analysis.get("confidence", 0.95)
        param = analysis.get("parameter", "")
        payload = analysis.get("payload", "")
        snippet = analysis.get("snippet", "")
        status_code = analysis.get("status_code", 200)
        desc = analysis.get("description", f"OAuth/OIDC Authentication vulnerability: {misconfig_type}")

        parsed_url = urllib.parse.urlparse(target_url)
        clean_base = base_url or (f"{parsed_url.scheme}://{parsed_url.netloc}" if parsed_url.netloc else target_url)

        title = f"OAuth / Stateful Auth Vulnerability ({misconfig_type.replace('_', ' ').title()}) on {target_url}"

        ev = Evidence(
            mission_id=getattr(raw_mission, "id", ""),
            source_type="LOG",
            created_by="SYSTEM_GENERATED",
            title=title,
            description=desc,
            category=category,
            value=target_url,
            source=target_url,
            status="CONFIRMED",
            confidence=confidence,
            severity=severity,
            provenance=ProvenanceData(step_id="oauth_collector"),
            tags=["oauth", "oidc", "token_validation", "session_management", misconfig_type, template_id],
            metadata={
                "url": target_url,
                "host": clean_base,
                "path": parsed_url.path or "/",
                "parameter": param,
                "payload": str(payload),
                "category": category,
                "severity": severity,
                "misconfiguration_type": misconfig_type,
                "template_id": template_id,
                "status_code": status_code,
                "evidence_snippet": snippet[:250],
                **{k: v for k, v in analysis.items() if k not in ("vulnerable", "snippet", "description")},
            },
        )

        # 1. Add to mission.evidence
        if hasattr(raw_mission, "evidence") and raw_mission.evidence is not None:
            if hasattr(raw_mission.evidence, "add"):
                raw_mission.evidence.add(ev)
            elif isinstance(raw_mission.evidence, list):
                raw_mission.evidence.append(ev)

        # 2. Add to mission.vulnerabilities
        if hasattr(raw_mission, "vulnerabilities") and isinstance(raw_mission.vulnerabilities, list):
            raw_mission.vulnerabilities.append({
                "name": title,
                "template_id": template_id,
                "severity": severity,
                "category": category,
                "host": clean_base,
                "url": target_url,
                "description": desc,
                "parameter": param,
                "misconfiguration_type": misconfig_type,
                "evidence_snippet": snippet[:250],
            })

        # 3. KnowledgeGraph Node & Edge Expansion
        graph = getattr(raw_mission, "attack_surface_graph", None) or getattr(raw_mission, "graph", None)
        if graph is not None and hasattr(graph, "add") and hasattr(graph, "connect"):
            lh_id = f"live_host:{clean_base}"
            ep_id = f"endpoint:{target_url}"
            vuln_id = f"vulnerability:{template_id}:{target_url}:{param}" if param else f"vulnerability:{template_id}:{target_url}"

            graph.add(Node(id=lh_id, type="live_host", value=clean_base, metadata={"url": clean_base}))
            graph.add(Node(id=ep_id, type="endpoint", value=target_url, metadata={"url": target_url, "status_code": status_code}))
            graph.add(Node(id=vuln_id, type="vulnerability", value=title, metadata=ev.metadata))

            graph.connect(lh_id, ep_id, edge_type="HAS_ENDPOINT")
            graph.connect(lh_id, vuln_id, edge_type="HAS_VULNERABILITY")
            graph.connect(ep_id, vuln_id, edge_type="HAS_VULNERABILITY")

        # 4. ControlledMission publish
        if mission is not raw_mission and hasattr(mission, "publish_finding"):
            try:
                mission.publish_finding(ev.evidence_id if hasattr(ev, "evidence_id") else getattr(ev, "id", ""), ev)
            except Exception:
                pass

        return ev

    def collect(self, mission: Any) -> List[Evidence]:
        """
        Main collection routine: fuzzes candidate endpoints across R1 (OAuth flows),
        R2 (JWT token validation), and R3 (stateful session management).
        """
        raw_mission = getattr(mission, "_mission", mission)
        candidates = self._extract_candidate_endpoints(raw_mission)
        if not candidates:
            logger.info("OAuthCollector: No candidate endpoints found to test.")
            return []

        logger.info(f"OAuthCollector: Testing {len(candidates)} candidate endpoints for auth vulnerabilities...")
        detected_evidence: List[Evidence] = []
        confirmed_keys: Set[str] = set()

        for cand in candidates:
            url = cand["url"]
            base_url = cand.get("base_url") or ""
            path = cand.get("path") or ""
            query = cand.get("query") or ""
            method = cand.get("method", "GET")

            # -------------------------------------------------------------
            # 1. R1: OAuth/OIDC Authorization Endpoint Testing
            # -------------------------------------------------------------
            is_auth_endpoint = any(p.search(path) for p in OAUTH_AUTH_ROUTE_PATTERNS) or "redirect_uri=" in url or "response_type=" in url or "client_id=" in url or "oauth" in path or "authorize" in path

            if is_auth_endpoint:
                # 1.1 Redirect URI Manipulation (Open Redirect, Subdomain, Traversal)
                redirect_payloads = self.generator.generate_redirect_uri_payloads(url, base_url)
                for pmeta in redirect_payloads:
                    manip_uri = pmeta["redirect_uri"]
                    
                    # Build target test URL with injected redirect_uri
                    if "?" in url:
                        # Replace or append redirect_uri
                        parsed_u = urllib.parse.urlparse(url)
                        q_dict = urllib.parse.parse_qs(parsed_u.query)
                        q_dict["redirect_uri"] = [manip_uri]
                        if "client_id" not in q_dict:
                            q_dict["client_id"] = ["test_client_id"]
                        if "response_type" not in q_dict:
                            q_dict["response_type"] = ["code"]
                        new_query = urllib.parse.urlencode(q_dict, doseq=True)
                        test_url = urllib.parse.urlunparse(parsed_u._replace(query=new_query))
                    else:
                        test_url = f"{url}?client_id=test_client_id&response_type=code&redirect_uri={urllib.parse.quote_plus(manip_uri)}"

                    resp = self._execute_request(raw_mission, "GET", test_url)
                    verdict = self.oauth_analyzer.analyze_redirect_uri_response(resp, pmeta, test_url)
                    if verdict and verdict.get("vulnerable"):
                        key = f"{verdict['misconfiguration_type']}:{url}:{pmeta['type']}"
                        if key not in confirmed_keys:
                            confirmed_keys.add(key)
                            ev = self._create_evidence_and_update_state(
                                mission, url, base_url, "oauth_misconfiguration", verdict
                            )
                            detected_evidence.append(ev)

                # 1.2 State Parameter CSRF Validation
                state_payloads = self.generator.generate_state_payloads()
                for smeta in state_payloads:
                    state_val = smeta["state_value"]
                    parsed_u = urllib.parse.urlparse(url)
                    q_dict = urllib.parse.parse_qs(parsed_u.query)
                    if state_val is not None:
                        q_dict["state"] = [state_val]
                    else:
                        q_dict.pop("state", None)
                    if "client_id" not in q_dict:
                        q_dict["client_id"] = ["test_client_id"]
                    if "response_type" not in q_dict:
                        q_dict["response_type"] = ["code"]
                    new_query = urllib.parse.urlencode(q_dict, doseq=True)
                    test_url = urllib.parse.urlunparse(parsed_u._replace(query=new_query))

                    resp = self._execute_request(raw_mission, "GET", test_url)
                    verdict = self.oauth_analyzer.analyze_state_validation(resp, smeta)
                    if verdict and verdict.get("vulnerable"):
                        key = f"{verdict['misconfiguration_type']}:{url}:{smeta['type']}"
                        if key not in confirmed_keys:
                            confirmed_keys.add(key)
                            ev = self._create_evidence_and_update_state(
                                mission, url, base_url, "oauth_misconfiguration", verdict
                            )
                            detected_evidence.append(ev)

                # 1.3 Referer Leakage
                resp = self._execute_request(raw_mission, "GET", url)
                verdict = self.oauth_analyzer.analyze_referer_leakage(resp, url)
                if verdict and verdict.get("vulnerable"):
                    key = f"referer_leakage:{url}"
                    if key not in confirmed_keys:
                        confirmed_keys.add(key)
                        ev = self._create_evidence_and_update_state(
                            mission, url, base_url, "oauth_misconfiguration", verdict
                        )
                        detected_evidence.append(ev)

            # -------------------------------------------------------------
            # 1.4 Authorization Code Reuse Testing (Token Endpoints)
            # -------------------------------------------------------------
            is_token_endpoint = any(p.search(path) for p in OAUTH_TOKEN_ROUTE_PATTERNS) or "oauth/token" in path
            if is_token_endpoint:
                code_payload = {
                    "grant_type": "authorization_code",
                    "code": "REPLAYABLE_AUTH_CODE_12345",
                    "client_id": "test_app",
                    "redirect_uri": f"{base_url}/callback",
                }
                resp1 = self._execute_request(raw_mission, "POST", url, data=code_payload)
                resp2 = self._execute_request(raw_mission, "POST", url, data=code_payload)
                verdict = self.oauth_analyzer.analyze_code_reuse(resp1, resp2)
                if verdict and verdict.get("vulnerable"):
                    key = f"code_reuse:{url}"
                    if key not in confirmed_keys:
                        confirmed_keys.add(key)
                        ev = self._create_evidence_and_update_state(
                            mission, url, base_url, "oauth_misconfiguration", verdict
                        )
                        detected_evidence.append(ev)

            # -------------------------------------------------------------
            # 2. R2: Token Validation & JWT Tampering Testing
            # -------------------------------------------------------------
            is_api_or_protected = any(p.search(path) for p in PROTECTED_API_PATTERNS) or "api" in path or "user" in path or "admin" in path or not is_auth_endpoint
            if is_api_or_protected:
                jwt_payloads = self.generator.generate_tampered_jwt_payloads()
                for jmeta in jwt_payloads:
                    token = jmeta["token"]
                    ttype = jmeta["type"]
                    auth_header = {"Authorization": f"Bearer {token}"}
                    resp = self._execute_request(raw_mission, method, url, headers=auth_header)

                    verdict = None
                    if "alg_none" in ttype:
                        verdict = self.token_analyzer.analyze_alg_none(resp)
                    elif ttype == "invalid_signature":
                        verdict = self.token_analyzer.analyze_signature_bypass(resp)
                    elif ttype == "key_confusion":
                        verdict = self.token_analyzer.analyze_key_confusion(resp)
                    elif ttype in ("expired_token", "invalid_audience", "invalid_issuer", "future_nbf"):
                        claim_name = ttype.split("_")[0] if ttype != "future_nbf" else "nbf"
                        verdict = self.token_analyzer.analyze_claims_validation(resp, claim_name)
                    elif ttype == "scope_escalation":
                        verdict = self.token_analyzer.analyze_scope_escalation(resp)

                    if verdict and verdict.get("vulnerable"):
                        key = f"{verdict['misconfiguration_type']}:{url}:{ttype}"
                        if key not in confirmed_keys:
                            confirmed_keys.add(key)
                            ev = self._create_evidence_and_update_state(
                                mission, url, base_url, "token_validation", verdict
                            )
                            detected_evidence.append(ev)

            # -------------------------------------------------------------
            # 3. R3: Stateful Authentication & Session Analysis
            # -------------------------------------------------------------
            # 3.1 Cookie Security Attributes
            probe_resp = self._execute_request(raw_mission, method, url)
            if probe_resp and probe_resp.headers:
                set_cookie_raw = probe_resp.headers.get("Set-Cookie") or probe_resp.headers.get("set-cookie") or ""
                cookie_headers = [c.strip() for c in set_cookie_raw.split("\n") if c.strip()] if "\n" in set_cookie_raw else ([set_cookie_raw] if set_cookie_raw else [])
                
                cookie_verdicts = self.session_analyzer.analyze_cookie_security(cookie_headers, url)
                for cverdict in cookie_verdicts:
                    key = f"cookie_flags:{url}:{cverdict.get('cookie_name')}"
                    if key not in confirmed_keys:
                        confirmed_keys.add(key)
                        ev = self._create_evidence_and_update_state(
                            mission, url, base_url, "session_management", cverdict
                        )
                        detected_evidence.append(ev)

            # 3.2 Session Fixation Testing on Login Endpoints
            is_login_endpoint = any(p.search(path) for p in LOGIN_ROUTE_PATTERNS) or "login" in path or "signin" in path
            if is_login_endpoint:
                pre_auth_cookie_val = "FIXATED_SESSION_ID_PRE_AUTH_9999"
                login_payload = {"username": "admin", "password": "password123"}
                login_resp = self._execute_request(
                    raw_mission,
                    "POST",
                    url,
                    data=login_payload,
                    cookies={"session_id": pre_auth_cookie_val, "sess": pre_auth_cookie_val},
                )
                if login_resp and login_resp.headers:
                    post_set_cookie = login_resp.headers.get("Set-Cookie") or login_resp.headers.get("set-cookie") or ""
                    # If server does not issue a new Set-Cookie or returns the same pre-auth cookie
                    if pre_auth_cookie_val in post_set_cookie or not post_set_cookie:
                        verdict = self.session_analyzer.analyze_session_fixation(pre_auth_cookie_val, pre_auth_cookie_val, url)
                        if verdict and verdict.get("vulnerable"):
                            key = f"session_fixation:{url}"
                            if key not in confirmed_keys:
                                confirmed_keys.add(key)
                                ev = self._create_evidence_and_update_state(
                                    mission, url, base_url, "session_management", verdict
                                )
                                detected_evidence.append(ev)

            # 3.3 Insufficient Logout Invalidation
            is_logout_endpoint = any(p.search(path) for p in LOGOUT_ROUTE_PATTERNS) or "logout" in path
            if is_logout_endpoint:
                # 1. Execute logout request
                logout_resp = self._execute_request(raw_mission, "POST", url, cookies={"session_id": "ACTIVE_LOGOUT_TEST_COOKIE"})
                # 2. Check if a protected route still accepts the token
                protected_url = f"{base_url}/api/user/profile" if base_url else f"{url}/../user/profile"
                post_logout_resp = self._execute_request(raw_mission, "GET", protected_url, cookies={"session_id": "ACTIVE_LOGOUT_TEST_COOKIE"})
                verdict = self.session_analyzer.analyze_logout_invalidation(post_logout_resp)
                if verdict and verdict.get("vulnerable"):
                    key = f"logout_invalidation:{url}"
                    if key not in confirmed_keys:
                        confirmed_keys.add(key)
                        ev = self._create_evidence_and_update_state(
                            mission, url, base_url, "session_management", verdict
                        )
                        detected_evidence.append(ev)

        logger.info(f"OAuthCollector: Testing complete. Emitted {len(detected_evidence)} evidence finding(s).")
        return detected_evidence
