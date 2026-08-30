"""
Unit and Component tests for OAuthCollector, OAuthPayloadGenerator,
OAuthAnalyzer, TokenValidationAnalyzer, and SessionSecurityAnalyzer.
"""
from typing import Any, Dict, List, Optional, Tuple
import urllib.parse
import pytest

from argus.collectors.oauth import (
    OAuthCollector,
    OAuthPayloadGenerator,
    OAuthAnalyzer,
    TokenValidationAnalyzer,
    SessionSecurityAnalyzer,
    b64url_encode,
    b64url_decode,
    create_mock_jwt,
    create_hs256_jwt,
)
from argus.evidence.model import Evidence
from argus.evidence.store import EvidenceStore
from argus.graph.graph import KnowledgeGraph
from argus.graph.attack_surface import AttackSurfaceGraphBuilder
from argus.http.client import HttpResponse
from argus.runtime.mission import Mission


class MockOAuthHttpClient:
    """Configurable HTTP client for OAuth, Token, and Session tests."""

    def __init__(self, routes: Optional[Dict[str, Tuple[int, str, Dict[str, str], float]]] = None):
        # key -> (status_code, body, headers, elapsed)
        self.routes: Dict[str, Tuple[int, str, Dict[str, str], float]] = dict(routes or {})
        self.requested_urls: List[str] = []
        self.requested_posts: List[Dict[str, Any]] = []

    def set_route(
        self,
        key: str,
        status_code: int,
        body: str,
        headers: Optional[Dict[str, str]] = None,
        elapsed: float = 0.05,
    ):
        self.routes[key] = (status_code, body, headers or {}, elapsed)

    def get(self, mission_or_url: Any, url: Optional[str] = None, **kwargs) -> HttpResponse:
        target_url = url if url is not None else mission_or_url
        if not isinstance(target_url, str):
            target_url = str(target_url)
        self.requested_urls.append(target_url)

        headers = kwargs.get("headers") or {}
        cookies = kwargs.get("cookies") or {}

        # 1. Exact match on URL
        if target_url in self.routes:
            st, bd, hd, el = self.routes[target_url]
            return HttpResponse(success=(200 <= st < 300), status_code=st, raw_body=bd, body=bd, headers=hd, url=target_url, elapsed=el)

        # 2. Match on Authorization header
        auth_hdr = headers.get("Authorization") or headers.get("authorization")
        if auth_hdr and f"auth:{auth_hdr}" in self.routes:
            st, bd, hd, el = self.routes[f"auth:{auth_hdr}"]
            return HttpResponse(success=(200 <= st < 300), status_code=st, raw_body=bd, body=bd, headers=hd, url=target_url, elapsed=el)

        # 3. Match on cookie
        for ck, cv in cookies.items():
            cookie_key = f"cookie:{ck}:{cv}"
            if cookie_key in self.routes:
                st, bd, hd, el = self.routes[cookie_key]
                return HttpResponse(success=(200 <= st < 300), status_code=st, raw_body=bd, body=bd, headers=hd, url=target_url, elapsed=el)

        # 4. Substring / query param match
        unquoted = urllib.parse.unquote_plus(target_url)
        for key, (st, bd, hd, el) in self.routes.items():
            if key in target_url or key in unquoted:
                return HttpResponse(success=(200 <= st < 300), status_code=st, raw_body=bd, body=bd, headers=hd, url=target_url, elapsed=el)

        # Default benign fallback (404 or 401 for unknown)
        return HttpResponse(
            success=False,
            status_code=401,
            raw_body='{"error": "unauthorized"}',
            body='{"error": "unauthorized"}',
            headers={"Content-Type": "application/json"},
            url=target_url,
            elapsed=0.05,
        )

    def post(self, mission_or_url: Any, url: Optional[str] = None, **kwargs) -> HttpResponse:
        target_url = url if url is not None else mission_or_url
        if not isinstance(target_url, str):
            target_url = str(target_url)

        data = kwargs.get("data") or {}
        json_data = kwargs.get("json") or {}
        headers = kwargs.get("headers") or {}
        cookies = kwargs.get("cookies") or {}
        self.requested_posts.append({"url": target_url, "data": data, "json": json_data, "headers": headers, "cookies": cookies})

        # 1. Exact match on URL
        if target_url in self.routes:
            st, bd, hd, el = self.routes[target_url]
            return HttpResponse(success=(200 <= st < 300), status_code=st, raw_body=bd, body=bd, headers=hd, url=target_url, elapsed=el)

        # 2. Check code / grant_type match
        if isinstance(data, dict):
            code_val = data.get("code")
            if code_val and f"code:{code_val}" in self.routes:
                st, bd, hd, el = self.routes[f"code:{code_val}"]
                return HttpResponse(success=(200 <= st < 300), status_code=st, raw_body=bd, body=bd, headers=hd, url=target_url, elapsed=el)

        # 3. Check cookie match
        for ck, cv in cookies.items():
            cookie_key = f"cookie:{ck}:{cv}"
            if cookie_key in self.routes:
                st, bd, hd, el = self.routes[cookie_key]
                return HttpResponse(success=(200 <= st < 300), status_code=st, raw_body=bd, body=bd, headers=hd, url=target_url, elapsed=el)

        return HttpResponse(
            success=True,
            status_code=200,
            raw_body='{"status": "ok"}',
            body='{"status": "ok"}',
            headers={"Content-Type": "application/json"},
            url=target_url,
            elapsed=0.05,
        )


# =============================================================================
# PAYLOAD GENERATOR TESTS
# =============================================================================

def test_oauth_payload_generator_redirect_uri_vectors():
    """Validates generation of redirect URI vectors."""
    gen = OAuthPayloadGenerator(attacker_domain="evil.com")
    payloads = gen.generate_redirect_uri_payloads("https://target.com/oauth/authorize", "https://target.com")
    assert len(payloads) >= 5

    types = [p["type"] for p in payloads]
    assert "open_redirect" in types
    assert "subdomain_bypass" in types
    assert "path_traversal_bypass" in types


def test_oauth_payload_generator_state_vectors():
    """Validates generation of state parameter vectors."""
    gen = OAuthPayloadGenerator()
    payloads = gen.generate_state_payloads()
    assert len(payloads) >= 3

    types = [p["type"] for p in payloads]
    assert "missing_state" in types
    assert "static_state" in types
    assert "predictable_state" in types


def test_oauth_payload_generator_jwt_vectors():
    """Validates generation of tampered JWT token vectors."""
    gen = OAuthPayloadGenerator()
    payloads = gen.generate_tampered_jwt_payloads()
    assert len(payloads) >= 8

    types = [p["type"] for p in payloads]
    assert "alg_none" in types
    assert "invalid_signature" in types
    assert "key_confusion" in types
    assert "expired_token" in types
    assert "invalid_audience" in types
    assert "invalid_issuer" in types
    assert "future_nbf" in types
    assert "scope_escalation" in types


# =============================================================================
# R1: OAUTH/OIDC FLOW MISCONFIGURATION TESTS
# =============================================================================

def test_oauth_redirect_uri_open_redirect_detection():
    """R1: Test detection of open redirect to external domain via redirect_uri."""
    mission = Mission(target="oauth.target.com")
    mission.endpoints = [{"url": "https://oauth.target.com/oauth/authorize"}]
    mission.live_hosts = ["https://oauth.target.com"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    mission.attack_surface_graph = KnowledgeGraph()

    client = MockOAuthHttpClient()
    client.set_route(
        "redirect_uri=https%3A%2F%2Fattacker.com%2Fcallback",
        302,
        "",
        headers={"Location": "https://attacker.com/callback?code=AUTH_CODE_XYZ"},
    )

    collector = OAuthCollector(http_client=client)
    evidence = collector.collect(mission)

    assert len(evidence) >= 1
    ev = next(e for e in evidence if e.metadata.get("misconfiguration_type") == "open_redirect")
    assert ev.category == "oauth_misconfiguration"
    assert ev.severity in ("critical", "high")
    assert ev.status == "CONFIRMED"
    assert ev.confidence >= 0.95
    assert ev.metadata["parameter"] == "redirect_uri"


def test_oauth_redirect_uri_subdomain_bypass_detection():
    """R1: Test detection of subdomain matching bypass on redirect_uri."""
    mission = Mission(target="target.com")
    mission.endpoints = [{"url": "https://target.com/oauth/authorize"}]
    mission.live_hosts = ["https://target.com"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    mission.attack_surface_graph = KnowledgeGraph()

    client = MockOAuthHttpClient()
    client.set_route(
        "target.com.attacker.com",
        302,
        "",
        headers={"Location": "https://target.com.attacker.com/callback?code=STOLEN_CODE"},
    )

    collector = OAuthCollector(http_client=client)
    evidence = collector.collect(mission)

    assert len(evidence) >= 1
    ev = next(e for e in evidence if e.metadata.get("misconfiguration_type") == "subdomain_bypass")
    assert ev.category == "oauth_misconfiguration"
    assert ev.status == "CONFIRMED"


def test_oauth_redirect_uri_path_traversal_bypass_detection():
    """R1: Test detection of path traversal bypass on redirect_uri."""
    mission = Mission(target="target.com")
    mission.endpoints = [{"url": "https://target.com/oauth/authorize"}]
    mission.live_hosts = ["https://target.com"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    mission.attack_surface_graph = KnowledgeGraph()

    client = MockOAuthHttpClient()
    client.set_route(
        "oauth/callback/../../attacker",
        302,
        "",
        headers={"Location": "https://target.com/attacker?code=TRAVERSAL_CODE"},
    )

    collector = OAuthCollector(http_client=client)
    evidence = collector.collect(mission)

    assert len(evidence) >= 1
    ev = next(e for e in evidence if e.metadata.get("misconfiguration_type") == "path_traversal_bypass")
    assert ev.category == "oauth_misconfiguration"
    assert ev.severity == "high"


def test_oauth_state_parameter_csrf_vulnerability():
    """R1: Test detection of missing state parameter verification (CSRF risk)."""
    mission = Mission(target="target.com")
    mission.endpoints = [{"url": "https://target.com/oauth/authorize?client_id=app1&redirect_uri=https://target.com/cb&response_type=code"}]
    mission.live_hosts = ["https://target.com"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    mission.attack_surface_graph = KnowledgeGraph()

    client = MockOAuthHttpClient()
    # Server returns 302 with code even when state parameter is omitted
    client.set_route(
        "https://target.com/oauth/authorize?client_id=app1&redirect_uri=https%3A%2F%2Ftarget.com%2Fcb&response_type=code",
        302,
        "",
        headers={"Location": "https://target.com/cb?code=NO_STATE_CODE_123"},
    )

    collector = OAuthCollector(http_client=client)
    evidence = collector.collect(mission)

    assert len(evidence) >= 1
    ev = next(e for e in evidence if e.metadata.get("misconfiguration_type") == "missing_state")
    assert ev.category == "oauth_misconfiguration"
    assert ev.metadata["parameter"] == "state"


def test_oauth_token_leakage_via_referer_detection():
    """R1: Test detection of token/code leakage via Referer to 3rd party domains."""
    analyzer = OAuthAnalyzer()
    resp = HttpResponse(
        success=True,
        status_code=200,
        raw_body='<html><head></head><body><a href="https://external-tracker.com/pixel">Pixel</a></body></html>',
        body='<html><head></head><body><a href="https://external-tracker.com/pixel">Pixel</a></body></html>',
        headers={"Content-Type": "text/html"},
        url="https://target.com/oauth/callback?code=SENSITIVE_CODE_12345",
    )
    verdict = analyzer.analyze_referer_leakage(resp, "https://target.com/oauth/callback?code=SENSITIVE_CODE_12345")
    assert verdict is not None
    assert verdict["vulnerable"] is True
    assert verdict["misconfiguration_type"] == "referer_token_leakage"


def test_oauth_authorization_code_reuse_detection():
    """R1: Test detection of authorization code replay / reuse on token endpoint."""
    mission = Mission(target="target.com")
    mission.endpoints = [{"url": "https://target.com/oauth/token", "method": "POST"}]
    mission.live_hosts = ["https://target.com"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    mission.attack_surface_graph = KnowledgeGraph()

    client = MockOAuthHttpClient()
    client.set_route(
        "https://target.com/oauth/token",
        200,
        '{"access_token": "token_replayed_12345", "token_type": "Bearer", "expires_in": 3600}',
        headers={"Content-Type": "application/json"},
    )

    collector = OAuthCollector(http_client=client)
    evidence = collector.collect(mission)

    assert len(evidence) >= 1
    ev = next(e for e in evidence if e.metadata.get("misconfiguration_type") == "authorization_code_reuse")
    assert ev.severity == "critical"
    assert ev.confidence >= 0.95


# =============================================================================
# R2: TOKEN VALIDATION & JWT SECURITY TESTS
# =============================================================================

def test_jwt_alg_none_signature_bypass_detection():
    """R2: Test detection of protected API accepting unsigned JWT with alg:none."""
    mission = Mission(target="api.target.com")
    mission.endpoints = [{"url": "https://api.target.com/api/user/profile", "method": "GET"}]
    mission.live_hosts = ["https://api.target.com"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    mission.attack_surface_graph = KnowledgeGraph()

    gen = OAuthPayloadGenerator()
    alg_none_item = next(p for p in gen.generate_tampered_jwt_payloads() if p["type"] == "alg_none")
    token = alg_none_item["token"]

    client = MockOAuthHttpClient()
    client.set_route(
        f"auth:Bearer {token}",
        200,
        '{"user": "admin", "role": "superuser", "secret_key": "flag_alg_none_accepted"}',
        headers={"Content-Type": "application/json"},
    )

    collector = OAuthCollector(http_client=client)
    evidence = collector.collect(mission)

    assert len(evidence) >= 1
    ev = next(e for e in evidence if e.metadata.get("misconfiguration_type") == "alg_none_bypass")
    assert ev.category == "token_validation"
    assert ev.severity == "critical"
    assert ev.confidence >= 0.95


def test_jwt_alg_none_case_mutations_detection():
    """R2: Test detection of alg:None and alg:NONE case variation bypasses."""
    analyzer = TokenValidationAnalyzer()
    resp = HttpResponse(
        success=True,
        status_code=200,
        raw_body='{"status": "success", "user": "admin", "role": "superuser"}',
        body='{"status": "success", "user": "admin", "role": "superuser"}',
        url="https://api.target.com/api/admin",
    )
    verdict = analyzer.analyze_alg_none(resp)
    assert verdict is not None
    assert verdict["vulnerable"] is True
    assert verdict["severity"] == "critical"


def test_jwt_invalid_signature_acceptance_detection():
    """R2: Test detection of API accepting forged/invalid JWT signature."""
    mission = Mission(target="api.target.com")
    mission.endpoints = [{"url": "https://api.target.com/api/admin/users", "method": "GET"}]
    mission.live_hosts = ["https://api.target.com"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    mission.attack_surface_graph = KnowledgeGraph()

    gen = OAuthPayloadGenerator()
    inv_sig_item = next(p for p in gen.generate_tampered_jwt_payloads() if p["type"] == "invalid_signature")
    token = inv_sig_item["token"]

    client = MockOAuthHttpClient()
    client.set_route(
        f"auth:Bearer {token}",
        200,
        '{"users": ["admin", "root"], "status": "authorized"}',
        headers={"Content-Type": "application/json"},
    )

    collector = OAuthCollector(http_client=client)
    evidence = collector.collect(mission)

    assert len(evidence) >= 1
    ev = next(e for e in evidence if e.metadata.get("misconfiguration_type") == "invalid_signature_acceptance")
    assert ev.category == "token_validation"
    assert ev.severity == "critical"


def test_jwt_key_confusion_rs256_hs256_detection():
    """R2: Test detection of HMAC-SHA256 signature using public RSA key (key confusion)."""
    mission = Mission(target="api.target.com")
    mission.endpoints = [{"url": "https://api.target.com/api/user/profile", "method": "GET"}]
    mission.live_hosts = ["https://api.target.com"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    mission.attack_surface_graph = KnowledgeGraph()

    gen = OAuthPayloadGenerator()
    kc_item = next(p for p in gen.generate_tampered_jwt_payloads() if p["type"] == "key_confusion")
    token = kc_item["token"]

    client = MockOAuthHttpClient()
    client.set_route(
        f"auth:Bearer {token}",
        200,
        '{"user": "admin", "role": "admin", "auth": "key_confusion_success"}',
        headers={"Content-Type": "application/json"},
    )

    collector = OAuthCollector(http_client=client)
    evidence = collector.collect(mission)

    assert len(evidence) >= 1
    ev = next(e for e in evidence if e.metadata.get("misconfiguration_type") == "key_confusion")
    assert ev.category == "token_validation"
    assert ev.severity == "critical"


def test_jwt_expired_claims_acceptance_detection():
    """R2: Test detection of expired token acceptance."""
    mission = Mission(target="api.target.com")
    mission.endpoints = [{"url": "https://api.target.com/api/me", "method": "GET"}]
    mission.live_hosts = ["https://api.target.com"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    mission.attack_surface_graph = KnowledgeGraph()

    gen = OAuthPayloadGenerator()
    exp_item = next(p for p in gen.generate_tampered_jwt_payloads() if p["type"] == "expired_token")
    token = exp_item["token"]

    client = MockOAuthHttpClient()
    client.set_route(
        f"auth:Bearer {token}",
        200,
        '{"user": "admin", "email": "admin@target.com", "status": "authenticated"}',
        headers={"Content-Type": "application/json"},
    )

    collector = OAuthCollector(http_client=client)
    evidence = collector.collect(mission)

    assert len(evidence) >= 1
    ev = next(e for e in evidence if e.metadata.get("misconfiguration_type") == "improper_claims_expired")
    assert ev.category == "token_validation"
    assert ev.severity == "high"


def test_jwt_invalid_audience_and_issuer_acceptance_detection():
    """R2: Test detection of unauthorized audience / issuer acceptance."""
    analyzer = TokenValidationAnalyzer()
    resp = HttpResponse(
        success=True,
        status_code=200,
        raw_body='{"user": "admin", "role": "superuser"}',
        body='{"user": "admin", "role": "superuser"}',
        url="https://api.target.com/api/profile",
    )
    verdict_aud = analyzer.analyze_claims_validation(resp, "aud")
    assert verdict_aud is not None
    assert verdict_aud["vulnerable"] is True
    assert verdict_aud["severity"] == "high"

    verdict_iss = analyzer.analyze_claims_validation(resp, "iss")
    assert verdict_iss is not None
    assert verdict_iss["vulnerable"] is True


def test_jwt_future_nbf_acceptance_detection():
    """R2: Test detection of future not-before (nbf) token acceptance."""
    analyzer = TokenValidationAnalyzer()
    resp = HttpResponse(
        success=True,
        status_code=200,
        raw_body='{"user": "admin", "profile": "active"}',
        body='{"user": "admin", "profile": "active"}',
        url="https://api.target.com/api/profile",
    )
    verdict = analyzer.analyze_claims_validation(resp, "nbf")
    assert verdict is not None
    assert verdict["vulnerable"] is True
    assert verdict["severity"] == "medium"


def test_jwt_scope_escalation_detection():
    """R2: Test detection of token scope escalation."""
    mission = Mission(target="api.target.com")
    mission.endpoints = [{"url": "https://api.target.com/api/admin/users", "method": "GET"}]
    mission.live_hosts = ["https://api.target.com"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    mission.attack_surface_graph = KnowledgeGraph()

    gen = OAuthPayloadGenerator()
    scope_item = next(p for p in gen.generate_tampered_jwt_payloads() if p["type"] == "scope_escalation")
    token = scope_item["token"]

    client = MockOAuthHttpClient()
    client.set_route(
        f"auth:Bearer {token}",
        200,
        '{"status": "success", "admin_action": "granted", "role": "superuser"}',
        headers={"Content-Type": "application/json"},
    )

    collector = OAuthCollector(http_client=client)
    evidence = collector.collect(mission)

    assert len(evidence) >= 1
    ev = next(e for e in evidence if e.metadata.get("misconfiguration_type") == "scope_escalation")
    assert ev.category == "token_validation"
    assert ev.severity == "high"


# =============================================================================
# R3: SESSION & STATEFUL AUTHENTICATION TESTS
# =============================================================================

def test_session_cookie_missing_secure_and_httponly_flags():
    """R3: Test detection of session cookies lacking Secure and HttpOnly flags."""
    mission = Mission(target="auth.target.com")
    mission.endpoints = [{"url": "https://auth.target.com/login", "method": "POST"}]
    mission.live_hosts = ["https://auth.target.com"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    mission.attack_surface_graph = KnowledgeGraph()

    client = MockOAuthHttpClient()
    client.set_route(
        "https://auth.target.com/login",
        200,
        '{"status": "authenticated"}',
        headers={"Set-Cookie": "session_id=insecure_token_12345; Path=/"},
    )

    collector = OAuthCollector(http_client=client)
    evidence = collector.collect(mission)

    assert len(evidence) >= 1
    ev = next(e for e in evidence if e.metadata.get("misconfiguration_type") == "insecure_cookie_attributes")
    assert ev.category == "session_management"
    assert ev.metadata["cookie_name"] == "session_id"
    assert "Secure" in ev.metadata["missing_flags"]
    assert "HttpOnly" in ev.metadata["missing_flags"]


def test_session_cookie_samesite_validation():
    """R3: Test detection of missing SameSite attribute."""
    analyzer = SessionSecurityAnalyzer()
    findings = analyzer.analyze_cookie_security(
        ["session=xyz123; Secure; HttpOnly"],
        "https://target.com/login",
    )
    assert len(findings) >= 1
    assert "SameSite" in findings[0]["missing_flags"]


def test_session_fixation_vulnerability_detection():
    """R3: Test detection of pre-authentication session ID retention post-login."""
    mission = Mission(target="target.com")
    mission.endpoints = [{"url": "https://target.com/api/auth/login", "method": "POST"}]
    mission.live_hosts = ["https://target.com"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    mission.attack_surface_graph = KnowledgeGraph()

    client = MockOAuthHttpClient()
    # Server accepts pre-login session_id and doesn't issue a new cookie
    client.set_route(
        "https://target.com/api/auth/login",
        200,
        '{"status": "authenticated", "user": "admin"}',
        headers={"Set-Cookie": "session_id=FIXATED_SESSION_ID_PRE_AUTH_9999; Path=/; Secure; HttpOnly"},
    )

    collector = OAuthCollector(http_client=client)
    evidence = collector.collect(mission)

    assert len(evidence) >= 1
    ev = next(e for e in evidence if e.metadata.get("misconfiguration_type") == "session_fixation")
    assert ev.category == "session_management"
    assert ev.severity == "high"
    assert ev.confidence >= 0.95


def test_session_insufficient_logout_invalidation():
    """R3: Test detection of session cookie remaining valid after logout action."""
    mission = Mission(target="target.com")
    mission.endpoints = [
        {"url": "https://target.com/logout", "method": "POST"},
        {"url": "https://target.com/api/user/profile", "method": "GET"},
    ]
    mission.live_hosts = ["https://target.com"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    mission.attack_surface_graph = KnowledgeGraph()

    client = MockOAuthHttpClient()
    # Logout endpoint succeeds
    client.set_route(
        "https://target.com/logout",
        200,
        '{"status": "logged_out"}',
    )
    # Protected endpoint still accepts the cookie after logout
    client.set_route(
        "cookie:session_id:ACTIVE_LOGOUT_TEST_COOKIE",
        200,
        '{"user": "admin", "profile": "active_post_logout"}',
    )

    collector = OAuthCollector(http_client=client)
    evidence = collector.collect(mission)

    assert len(evidence) >= 1
    ev = next(e for e in evidence if e.metadata.get("misconfiguration_type") == "insufficient_logout_invalidation")
    assert ev.category == "session_management"
    assert ev.severity == "medium"


# =============================================================================
# KNOWLEDGE GRAPH & ATTACK SURFACE BUILDER TESTS
# =============================================================================

def test_oauth_collector_knowledge_graph_node_and_edge_wiring():
    """R4: Test that confirmed findings create live_host, endpoint, vulnerability nodes and HAS_VULNERABILITY edges."""
    mission = Mission(target="oauth.target.com")
    mission.endpoints = [{"url": "https://oauth.target.com/oauth/authorize"}]
    mission.live_hosts = ["https://oauth.target.com"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    graph = KnowledgeGraph()
    mission.attack_surface_graph = graph

    client = MockOAuthHttpClient()
    client.set_route(
        "redirect_uri=https%3A%2F%2Fattacker.com%2Fcallback",
        302,
        "",
        headers={"Location": "https://attacker.com/callback?code=AUTH123"},
    )

    collector = OAuthCollector(http_client=client)
    evidence = collector.collect(mission)

    assert len(evidence) >= 1
    # Check graph nodes
    assert len(graph.nodes_by_type("live_host")) >= 1
    assert len(graph.nodes_by_type("endpoint")) >= 1
    assert len(graph.nodes_by_type("vulnerability")) >= 1

    # Check edges
    has_endpoint_edges = [e for e in graph.edges if e.type == "HAS_ENDPOINT"]
    has_vuln_edges = [e for e in graph.edges if e.type == "HAS_VULNERABILITY"]

    assert len(has_endpoint_edges) >= 1
    assert len(has_vuln_edges) >= 2  # live_host -> vuln, endpoint -> vuln

    # Verify reconstruction via AttackSurfaceGraphBuilder
    builder = AttackSurfaceGraphBuilder()
    reconstructed = builder.build_from_evidence(list(mission.evidence), target="oauth.target.com")
    assert len(reconstructed.nodes_by_type("vulnerability")) >= 1
    assert any(e.type == "HAS_VULNERABILITY" for e in reconstructed.edges)
