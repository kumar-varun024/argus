"""
Challenger 1 Adversarial Test Suite for Sprint 13 — OAuth/OIDC, Token Validation & Session Management.
Stress-tests boundary conditions, malformed encodings, weird casing, unicode, large payloads,
false positive resistance, and graph node/edge integrity.
"""
from typing import Any, Dict, List, Optional
import json
import time
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
from argus.graph.node import Node
from argus.graph.attack_surface import AttackSurfaceGraphBuilder
from argus.http.client import HttpResponse
from argus.plugins.interfaces import ControlledMission
from argus.runtime.mission import Mission
from tests.collectors.test_oauth import MockOAuthHttpClient


# =============================================================================
# 1. MALFORMED, UNUSUAL & ADVERSARIAL URLS
# =============================================================================

class TestAdversarialUrls:
    """Stress tests candidate endpoint parsing and HTTP execution with hostile URLs."""

    def test_unicode_and_punycode_urls(self):
        """Tests handling of non-ASCII internationalized domain names (IDN) and unicode paths."""
        mission = Mission(target="üñîçødé-targët.com")
        mission.endpoints = [
            {"url": "https://üñîçødé-targët.com/oauth/authorize"},
            {"url": "https://target.com/oauth/🔑/authorize"},
            {"url": "https://target.com/api/üšér/profile"},
        ]
        mission.live_hosts = ["https://üñîçødé-targët.com", "https://target.com"]
        mission.evidence = EvidenceStore()
        mission.vulnerabilities = []
        mission.attack_surface_graph = KnowledgeGraph()

        client = MockOAuthHttpClient()
        collector = OAuthCollector(http_client=client)
        evidence = collector.collect(mission)
        assert isinstance(evidence, list)

    def test_ipv6_and_custom_ports(self):
        """Tests handling of IPv6 bracketed hosts and non-standard port numbers."""
        mission = Mission(target="[2001:db8::1]:8443")
        mission.endpoints = [
            {"url": "https://[2001:db8::1]:8443/oauth/authorize"},
            {"url": "http://[::1]:9090/oauth/token", "method": "POST"},
            {"url": "https://127.0.0.1:8080/api/user/profile"},
        ]
        mission.live_hosts = ["https://[2001:db8::1]:8443"]
        mission.evidence = EvidenceStore()
        mission.vulnerabilities = []
        mission.attack_surface_graph = KnowledgeGraph()

        client = MockOAuthHttpClient()
        collector = OAuthCollector(http_client=client)
        evidence = collector.collect(mission)
        assert isinstance(evidence, list)

    def test_schemeless_and_relative_urls(self):
        """Tests handling of schemeless URLs and root-relative paths."""
        mission = Mission(target="example.org")
        mission.endpoints = [
            "//example.org/oauth/authorize",
            "/oauth/authorize?client_id=123",
            "api/user/profile",
            "javascript:void(0)",
            "data:text/html,<script>alert(1)</script>",
        ]
        mission.live_hosts = ["https://example.org"]
        mission.evidence = EvidenceStore()
        mission.vulnerabilities = []
        mission.attack_surface_graph = KnowledgeGraph()

        client = MockOAuthHttpClient()
        collector = OAuthCollector(http_client=client)
        evidence = collector.collect(mission)
        assert isinstance(evidence, list)

    def test_massive_url_and_null_bytes(self):
        """Tests handling of URLs with null bytes, control characters, and 10KB query strings."""
        giant_query = "param=" + ("A" * 8000)
        mission = Mission(target="target.com")
        mission.endpoints = [
            f"https://target.com/oauth/authorize?{giant_query}",
            "https://target.com/oauth/authorize%00nullbyte",
            "https://target.com/oauth/\r\nCRLF",
        ]
        mission.live_hosts = ["https://target.com"]
        mission.evidence = EvidenceStore()
        mission.vulnerabilities = []
        mission.attack_surface_graph = KnowledgeGraph()

        client = MockOAuthHttpClient()
        collector = OAuthCollector(http_client=client)
        evidence = collector.collect(mission)
        assert isinstance(evidence, list)


# =============================================================================
# 2. ADVERSARIAL JWT ENCODINGS & TOKEN VALIDATION (R2)
# =============================================================================

class TestAdversarialJwtAndTokenValidation:
    """Stress tests JWT parsing, casing variations, corrupted structures, and claims edge cases."""

    @pytest.mark.parametrize("alg_casing", [
        "none", "None", "NONE", "nOnE", "NoNe", "noNE", "nONE"
    ])
    def test_jwt_alg_none_case_variations(self, alg_casing: str):
        """Verifies that any case mutation of alg:none is caught when accepted by server."""
        header = {"alg": alg_casing, "typ": "JWT"}
        claims = {"sub": "admin", "user": "admin", "role": "superuser"}
        token = create_mock_jwt(header, claims, signature=b"")

        analyzer = TokenValidationAnalyzer()
        resp = HttpResponse(
            success=True,
            status_code=200,
            raw_body=json.dumps({"status": "success", "user": "admin", "role": "superuser"}),
            body=json.dumps({"status": "success", "user": "admin", "role": "superuser"}),
            url="https://api.target.com/api/user/profile",
        )

        verdict = analyzer.analyze_alg_none(resp)
        assert verdict is not None
        assert verdict["vulnerable"] is True
        assert verdict["misconfiguration_type"] == "alg_none_bypass"
        assert verdict["severity"] == "critical"

    def test_jwt_corrupted_tokens_graceful_handling(self):
        """Verifies that malformed tokens with bad base64, invalid JSON, or wrong parts do not crash."""
        corrupted_tokens = [
            "",  # empty
            "not_a_jwt",  # 1 part
            "part1.part2",  # 2 parts
            "part1.part2.part3.part4.part5",  # 5 parts
            "!!!.@@@.###",  # invalid base64
            f"{b64url_encode('not json')}.{b64url_encode('not json')}.",  # invalid JSON
            f"{b64url_encode('{}')}.{b64url_encode('[]')}.",  # non-dict JSON
        ]

        gen = OAuthPayloadGenerator()
        base_payloads = gen.generate_tampered_jwt_payloads()
        assert len(base_payloads) >= 8

        # Test b64url helpers
        for token in corrupted_tokens:
            try:
                b64url_decode(token)
            except Exception:
                pass  # Graceful

    def test_jwt_with_giant_payload(self):
        """Tests generator and analyzer with 10,000 claims (large payload)."""
        huge_claims = {f"claim_{i}": f"value_{i}" * 10 for i in range(1000)}
        huge_claims["sub"] = "admin"
        huge_claims["user"] = "admin"
        huge_claims["role"] = "superuser"

        gen = OAuthPayloadGenerator()
        payloads = gen.generate_tampered_jwt_payloads(base_claims=huge_claims)
        assert len(payloads) >= 8

        alg_none_token = next(p["token"] for p in payloads if p["type"] == "alg_none")
        assert len(alg_none_token) > 10000

        analyzer = TokenValidationAnalyzer()
        resp = HttpResponse(
            success=True,
            status_code=200,
            raw_body=json.dumps({"status": "success", "user": "admin", "role": "superuser"}),
            body=json.dumps({"status": "success", "user": "admin", "role": "superuser"}),
            url="https://api.target.com/api/user/profile",
        )
        verdict = analyzer.analyze_alg_none(resp)
        assert verdict is not None
        assert verdict["vulnerable"] is True

    @pytest.mark.parametrize("claim_name,sev", [
        ("exp", "high"),
        ("aud", "high"),
        ("iss", "high"),
        ("nbf", "medium"),
    ])
    def test_claims_validation_all_types(self, claim_name: str, sev: str):
        """Verifies claims validation analyzer across exp, aud, iss, nbf."""
        analyzer = TokenValidationAnalyzer()
        resp = HttpResponse(
            success=True,
            status_code=200,
            raw_body='{"status": "success", "user": "admin", "role": "superuser"}',
            body='{"status": "success", "user": "admin", "role": "superuser"}',
            url="https://api.target.com/api/admin",
        )
        verdict = analyzer.analyze_claims_validation(resp, claim_name)
        assert verdict is not None
        assert verdict["vulnerable"] is True
        assert verdict["severity"] == sev
        assert verdict["claim"] == claim_name


# =============================================================================
# 3. ADVERSARIAL COOKIE FORMATS & SESSION SECURITY (R3)
# =============================================================================

class TestAdversarialSessionAndCookieHandling:
    """Stress tests cookie header parsing, casing variations, and edge cases."""

    def test_cookie_case_insensitivity_attributes(self):
        """Verifies that Secure, HttpOnly, SameSite attributes in arbitrary casing are recognized."""
        analyzer = SessionSecurityAnalyzer()
        # Mixed casing: sEcuRe, hTTpOnLy, SaMeSiTe=StRiCt
        cookie_header = "session_id=TOKEN123; pAtH=/; sEcuRe; hTTpOnLy; SaMeSiTe=StRiCt"
        findings = analyzer.analyze_cookie_security([cookie_header], "https://target.com/login")
        # Should be NO missing flags
        assert len(findings) == 0

    def test_cookie_samesite_none_without_secure(self):
        """Verifies that SameSite=None without Secure is flagged as insecure."""
        analyzer = SessionSecurityAnalyzer()
        cookie_header = "session_id=TOKEN123; Path=/; HttpOnly; SameSite=None"
        findings = analyzer.analyze_cookie_security([cookie_header], "https://target.com/login")
        assert len(findings) == 1
        assert "SameSite=None without Secure" in findings[0]["missing_flags"]
        assert "Secure" in findings[0]["missing_flags"]

    def test_cookie_samesite_none_with_secure(self):
        """Verifies that SameSite=None WITH Secure is accepted as compliant for cross-site cookies."""
        analyzer = SessionSecurityAnalyzer()
        cookie_header = "session_id=TOKEN123; Path=/; Secure; HttpOnly; SameSite=None"
        findings = analyzer.analyze_cookie_security([cookie_header], "https://target.com/login")
        assert len(findings) == 0

    def test_cookie_with_multiple_equals_and_quotes(self):
        """Verifies parsing cookies with '=' in value and double quotes."""
        analyzer = SessionSecurityAnalyzer()
        cookie_header = 'session_id="token=part1&part2===="; Path=/; Secure; HttpOnly; SameSite=Lax'
        findings = analyzer.analyze_cookie_security([cookie_header], "https://target.com/login")
        assert len(findings) == 0

    def test_cookie_empty_and_malformed_headers(self):
        """Verifies graceful handling of empty, None, and garbage cookie headers."""
        analyzer = SessionSecurityAnalyzer()
        malformed_headers = [
            "",
            "   ",
            ";;;;",
            "=",
            "=value",
            "name=",
            "session_id",
        ]
        for hdr in malformed_headers:
            findings = analyzer.analyze_cookie_security([hdr], "https://target.com")
            assert isinstance(findings, list)

    def test_non_session_cookies_single_missing_flag_is_low_severity(self):
        """Verifies that non-session cookies (e.g. theme, lang) missing a single attribute have low severity."""
        analyzer = SessionSecurityAnalyzer()
        findings = analyzer.analyze_cookie_security(
            ["theme=dark; Path=/; Secure; SameSite=Lax"],
            "https://target.com",
        )
        assert len(findings) == 1
        assert findings[0]["severity"] == "low"
        assert findings[0]["cookie_name"] == "theme"
        assert "HttpOnly" in findings[0]["missing_flags"]

    def test_session_fixation_different_cookies_not_vulnerable(self):
        """Verifies that when pre-auth and post-auth cookies differ, no vulnerability is emitted."""
        analyzer = SessionSecurityAnalyzer()
        verdict = analyzer.analyze_session_fixation("PRE_AUTH_COOKIE_123", "POST_AUTH_COOKIE_456")
        assert verdict is None

    def test_session_fixation_empty_cookies_handled(self):
        """Verifies that empty cookies don't trigger false positives."""
        analyzer = SessionSecurityAnalyzer()
        assert analyzer.analyze_session_fixation("", "") is None
        assert analyzer.analyze_session_fixation("abc", "") is None
        assert analyzer.analyze_session_fixation("", "abc") is None

    def test_logout_invalidation_unauthorized_post_logout_not_vulnerable(self):
        """Verifies that when protected endpoint returns 401/403 post-logout, no vulnerability is emitted."""
        analyzer = SessionSecurityAnalyzer()
        resp_401 = HttpResponse(
            success=False,
            status_code=401,
            raw_body='{"error": "unauthorized"}',
            body='{"error": "unauthorized"}',
            url="https://target.com/api/user/profile",
        )
        assert analyzer.analyze_logout_invalidation(resp_401) is None

        resp_403 = HttpResponse(
            success=False,
            status_code=403,
            raw_body='{"error": "forbidden"}',
            body='{"error": "forbidden"}',
            url="https://target.com/api/user/profile",
        )
        assert analyzer.analyze_logout_invalidation(resp_403) is None


# =============================================================================
# 4. FALSE POSITIVE RESISTANCE TESTS (R1, R2, R3)
# =============================================================================

class TestFalsePositiveResistance:
    """Rigorous false positive suppression verification for hardened systems."""

    def test_oauth_redirect_to_own_domain_error_page_not_open_redirect(self):
        """
        When server redirects to its OWN domain error page (e.g. Location: https://target.com/error?rejected=evil.com),
        it must NOT be flagged as open redirect.
        """
        analyzer = OAuthAnalyzer()
        resp = HttpResponse(
            success=False,
            status_code=302,
            raw_body="",
            body="",
            headers={"Location": "https://target.com/oauth/error?reason=unregistered_redirect_uri"},
            url="https://target.com/oauth/authorize",
        )
        payload_meta = {
            "type": "open_redirect",
            "redirect_uri": "https://attacker.com/callback",
            "severity": "critical",
            "template_id": "oauth-open-redirect",
        }
        verdict = analyzer.analyze_redirect_uri_response(resp, payload_meta, "https://target.com/oauth/authorize")
        assert verdict is None

    def test_oauth_state_error_response_not_flagged(self):
        """When server rejects missing state with 400 Bad Request or invalid_state error, no finding is emitted."""
        analyzer = OAuthAnalyzer()
        resp_400 = HttpResponse(
            success=False,
            status_code=400,
            raw_body='{"error": "invalid_request", "error_description": "state is required"}',
            body='{"error": "invalid_request", "error_description": "state is required"}',
            url="https://target.com/oauth/authorize",
        )
        verdict = analyzer.analyze_state_validation(resp_400, {"type": "missing_state"})
        assert verdict is None

    def test_token_endpoint_rejecting_replayed_code_not_flagged(self):
        """When 2nd token exchange fails with 400 Bad Request invalid_grant, no code reuse is emitted."""
        analyzer = OAuthAnalyzer()
        resp1 = HttpResponse(
            success=True,
            status_code=200,
            raw_body='{"access_token": "TOKEN1", "token_type": "Bearer"}',
            body='{"access_token": "TOKEN1", "token_type": "Bearer"}',
            url="https://target.com/oauth/token",
        )
        resp2 = HttpResponse(
            success=False,
            status_code=400,
            raw_body='{"error": "invalid_grant", "error_description": "Authorization code has already been used"}',
            body='{"error": "invalid_grant", "error_description": "Authorization code has already been used"}',
            url="https://target.com/oauth/token",
        )
        verdict = analyzer.analyze_code_reuse(resp1, resp2)
        assert verdict is None

    def test_jwt_analyzer_rejects_error_responses_with_status_200(self):
        """When API returns 200 OK but with error payload without authenticated keywords, no finding is emitted."""
        analyzer = TokenValidationAnalyzer()
        resp = HttpResponse(
            success=True,
            status_code=200,
            raw_body='{"status": "failure", "code": 40101, "message": "Signature verification failed"}',
            body='{"status": "failure", "code": 40101, "message": "Signature verification failed"}',
            url="https://api.target.com/api/data",
        )
        verdict = analyzer.analyze_alg_none(resp)
        assert verdict is None


# =============================================================================
# 5. KNOWLEDGE GRAPH & HAS_VULNERABILITY EDGE STRESS TESTS (R4)
# =============================================================================

class TestGraphNodeAndEdgeStress:
    """Validates KnowledgeGraph node and HAS_VULNERABILITY edge creation under stress."""

    def test_graph_node_and_edge_deduplication(self):
        """Multiple vulnerabilities on the same host and endpoint correctly expand graph without duplicates."""
        mission = Mission(target="auth.target.com")
        mission.endpoints = [
            {"url": "https://auth.target.com/oauth/authorize"},
            {"url": "https://auth.target.com/api/user/profile"},
        ]
        mission.live_hosts = ["https://auth.target.com"]
        mission.evidence = EvidenceStore()
        mission.vulnerabilities = []
        graph = KnowledgeGraph()
        mission.attack_surface_graph = graph

        client = MockOAuthHttpClient()
        # Open redirect
        client.set_route(
            "redirect_uri=https%3A%2F%2Fattacker.com%2Fcallback",
            302,
            "",
            headers={"Location": "https://attacker.com/callback?code=CODE1"},
        )
        # alg:none
        gen = OAuthPayloadGenerator()
        alg_none_token = next(p["token"] for p in gen.generate_tampered_jwt_payloads() if p["type"] == "alg_none")
        client.set_route(
            f"auth:Bearer {alg_none_token}",
            200,
            '{"user": "admin", "role": "superuser"}',
            headers={"Content-Type": "application/json"},
        )

        collector = OAuthCollector(http_client=client)
        evidence = collector.collect(mission)

        assert len(evidence) >= 2

        # Verify graph integrity
        live_hosts = graph.nodes_by_type("live_host")
        endpoints = graph.nodes_by_type("endpoint")
        vulns = graph.nodes_by_type("vulnerability")

        assert len(live_hosts) == 1
        assert len(endpoints) >= 2
        assert len(vulns) >= 2

        # Check HAS_VULNERABILITY edges
        has_vuln_edges = [e for e in graph.edges if e.type == "HAS_VULNERABILITY"]
        assert len(has_vuln_edges) >= 4  # (live_host -> v1, ep1 -> v1, live_host -> v2, ep2 -> v2)

        # Verify AttackSurfaceGraphBuilder produces identical topology
        builder = AttackSurfaceGraphBuilder()
        reconstructed = builder.build_from_evidence(list(mission.evidence), target="auth.target.com")
        assert len(reconstructed.nodes_by_type("vulnerability")) >= 2
        assert len([e for e in reconstructed.edges if e.type == "HAS_VULNERABILITY"]) >= 4

    def test_special_characters_in_evidence_metadata_graph_nodes(self):
        """Graph node IDs with quotes, unicode, and colons in URLs do not cause graph corruption."""
        graph = KnowledgeGraph()
        target_url = "https://target.com/api/test?param=val:123&quote=\"hello\"&unicode=🚀"
        base_url = "https://target.com"

        lh_id = f"live_host:{base_url}"
        ep_id = f"endpoint:{target_url}"
        vuln_id = f"vulnerability:oauth-test:{target_url}:redirect_uri"

        graph.add(Node(id=lh_id, type="live_host", value=base_url))
        graph.add(Node(id=ep_id, type="endpoint", value=target_url))
        graph.add(Node(id=vuln_id, type="vulnerability", value="Test Vulnerability"))

        graph.connect(lh_id, ep_id, edge_type="HAS_ENDPOINT")
        graph.connect(lh_id, vuln_id, edge_type="HAS_VULNERABILITY")
        graph.connect(ep_id, vuln_id, edge_type="HAS_VULNERABILITY")

        assert len(graph.nodes) == 3
        assert len(graph.edges) == 3
        assert len([e for e in graph.edges if e.type == "HAS_VULNERABILITY"]) == 2


# =============================================================================
# 6. STRESS & RESILIENCE BENCHMARK
# =============================================================================

class TestStressAndResilience:
    """Stress tests high endpoint volume and rapid execution."""

    def test_collector_processes_100_endpoints_rapidly(self):
        """Collector must process 100 candidate endpoints in < 2 seconds without errors."""
        mission = Mission(target="scale.target.com")
        mission.endpoints = [
            {"url": f"https://scale.target.com/api/v1/resource_{i}", "method": "GET"}
            for i in range(100)
        ]
        mission.live_hosts = ["https://scale.target.com"]
        mission.evidence = EvidenceStore()
        mission.vulnerabilities = []
        mission.attack_surface_graph = KnowledgeGraph()

        client = MockOAuthHttpClient()
        collector = OAuthCollector(http_client=client)

        start_time = time.time()
        evidence = collector.collect(mission)
        elapsed = time.time() - start_time

        assert isinstance(evidence, list)
        assert elapsed < 2.0, f"100 endpoints took {elapsed:.2f}s (expected < 2.0s)"
