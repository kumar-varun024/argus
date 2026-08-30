"""
Adversarial, boundary, and false-positive suppression tests for OAuthCollector.
Verifies resilience against malformed inputs, error conditions, and guarantees that
properly hardened OAuth flows, signed JWTs, and secure session cookies emit ZERO findings.
"""
from typing import Any, Dict, List, Optional
import pytest

from argus.collectors.oauth import OAuthCollector, OAuthPayloadGenerator
from argus.evidence.store import EvidenceStore
from argus.graph.graph import KnowledgeGraph
from argus.http.client import HttpResponse
from argus.plugins.interfaces import ControlledMission
from argus.runtime.mission import Mission
from tests.collectors.test_oauth import MockOAuthHttpClient


def test_oauth_false_positive_rejection_properly_configured_flow():
    """
    False Positive Rejection: Properly configured authorization server rejecting
    manipulated redirect_uris with 400 Bad Request must emit 0 evidence.
    """
    mission = Mission(target="oauth.secure.com")
    mission.endpoints = [{"url": "https://oauth.secure.com/oauth/authorize"}]
    mission.live_hosts = ["https://oauth.secure.com"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    mission.attack_surface_graph = KnowledgeGraph()

    client = MockOAuthHttpClient()
    # Server strictly returns 400 Bad Request with error=invalid_request for all unapproved redirect_uris
    client.set_route(
        "redirect_uri=",
        400,
        '{"error": "invalid_request", "error_description": "The redirect URI is not registered."}',
    )

    collector = OAuthCollector(http_client=client)
    evidence = collector.collect(mission)

    # Must NOT emit any open redirect evidence
    assert len([e for e in evidence if e.metadata.get("misconfiguration_type") == "open_redirect"]) == 0
    assert len([e for e in evidence if e.metadata.get("misconfiguration_type") == "subdomain_bypass"]) == 0


def test_jwt_false_positive_rejection_proper_signature_enforcement():
    """
    False Positive Rejection: Protected APIs rejecting unsigned, forged, or expired tokens
    with 401 Unauthorized must emit 0 evidence.
    """
    mission = Mission(target="api.secure.com")
    mission.endpoints = [{"url": "https://api.secure.com/api/user/profile", "method": "GET"}]
    mission.live_hosts = ["https://api.secure.com"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    mission.attack_surface_graph = KnowledgeGraph()

    client = MockOAuthHttpClient()
    # Mock client returns 401 Unauthorized for all tampered tokens by default

    collector = OAuthCollector(http_client=client)
    evidence = collector.collect(mission)

    token_evidence = [e for e in evidence if e.category == "token_validation"]
    assert len(token_evidence) == 0


def test_session_cookie_false_positive_rejection_secure_cookies():
    """
    False Positive Rejection: Cookies with Secure, HttpOnly, and SameSite flags
    must emit 0 cookie security findings.
    """
    mission = Mission(target="secure.com")
    mission.endpoints = [{"url": "https://secure.com/login", "method": "GET"}]
    mission.live_hosts = ["https://secure.com"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    mission.attack_surface_graph = KnowledgeGraph()

    client = MockOAuthHttpClient()
    client.set_route(
        "https://secure.com/login",
        200,
        '{"status": "ready"}',
        headers={"Set-Cookie": "session_id=SECURE_RANDOM_TOKEN_123; Path=/; Secure; HttpOnly; SameSite=Strict"},
    )

    collector = OAuthCollector(http_client=client)
    evidence = collector.collect(mission)

    cookie_evidence = [e for e in evidence if e.metadata.get("misconfiguration_type") == "insecure_cookie_attributes"]
    assert len(cookie_evidence) == 0


def test_session_fixation_false_positive_rejection_new_cookie_issued():
    """
    False Positive Rejection: When server issues a new distinct session ID post-login,
    no session fixation evidence should be emitted.
    """
    mission = Mission(target="secure.com")
    mission.endpoints = [{"url": "https://secure.com/api/auth/login", "method": "POST"}]
    mission.live_hosts = ["https://secure.com"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    mission.attack_surface_graph = KnowledgeGraph()

    client = MockOAuthHttpClient()
    # Server issues a completely new session cookie
    client.set_route(
        "https://secure.com/api/auth/login",
        200,
        '{"status": "authenticated"}',
        headers={"Set-Cookie": "session_id=REGENERATED_NEW_SESSION_ID_56789; Path=/; Secure; HttpOnly; SameSite=Lax"},
    )

    collector = OAuthCollector(http_client=client)
    evidence = collector.collect(mission)

    fixation_evidence = [e for e in evidence if e.metadata.get("misconfiguration_type") == "session_fixation"]
    assert len(fixation_evidence) == 0


def test_session_logout_false_positive_rejection_token_invalidated():
    """
    False Positive Rejection: When server invalidates session on logout (subsequent request returns 401),
    no insufficient logout invalidation evidence should be emitted.
    """
    mission = Mission(target="secure.com")
    mission.endpoints = [
        {"url": "https://secure.com/logout", "method": "POST"},
        {"url": "https://secure.com/api/user/profile", "method": "GET"},
    ]
    mission.live_hosts = ["https://secure.com"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    mission.attack_surface_graph = KnowledgeGraph()

    client = MockOAuthHttpClient()
    client.set_route(
        "https://secure.com/logout",
        200,
        '{"status": "logged_out"}',
    )
    # Protected endpoint rejects the cookie post-logout with 401
    client.set_route(
        "cookie:session_id:ACTIVE_LOGOUT_TEST_COOKIE",
        401,
        '{"error": "session expired"}',
    )

    collector = OAuthCollector(http_client=client)
    evidence = collector.collect(mission)

    logout_evidence = [e for e in evidence if e.metadata.get("misconfiguration_type") == "insufficient_logout_invalidation"]
    assert len(logout_evidence) == 0


def test_oauth_collector_empty_mission_handling():
    """Verifies that an empty mission is handled gracefully without errors."""
    mission = Mission(target="")
    mission.endpoints = []
    mission.live_hosts = []
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    mission.attack_surface_graph = KnowledgeGraph()

    collector = OAuthCollector(http_client=MockOAuthHttpClient())
    evidence = collector.collect(mission)
    assert evidence == []


def test_oauth_collector_malformed_urls_handling():
    """Verifies resilience when handling unusual or malformed endpoint representations."""
    mission = Mission(target="target.com")
    mission.endpoints = [
        "javascript:void(0)",
        {"url": None},
        {"url": "ftp://files.target.com/test"},
        12345,
    ]
    mission.live_hosts = ["https://target.com"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    mission.attack_surface_graph = KnowledgeGraph()

    collector = OAuthCollector(http_client=MockOAuthHttpClient())
    evidence = collector.collect(mission)
    assert isinstance(evidence, list)


def test_oauth_collector_controlled_mission_wrapper_compatibility():
    """Verifies seamless execution when wrapped in ControlledMission."""
    raw_mission = Mission(target="target.com")
    raw_mission.endpoints = [{"url": "https://target.com/oauth/authorize"}]
    raw_mission.live_hosts = ["https://target.com"]
    raw_mission.evidence = EvidenceStore()
    raw_mission.vulnerabilities = []
    raw_mission.attack_surface_graph = KnowledgeGraph()

    controlled = ControlledMission(raw_mission)

    client = MockOAuthHttpClient()
    client.set_route(
        "redirect_uri=https%3A%2F%2Fattacker.com%2Fcallback",
        302,
        "",
        headers={"Location": "https://attacker.com/callback?code=CODE1"},
    )

    collector = OAuthCollector(http_client=client)
    evidence = collector.execute(controlled)

    assert len(evidence) >= 1
    assert len(raw_mission.vulnerabilities) >= 1
    assert any(e.type == "HAS_VULNERABILITY" for e in raw_mission.attack_surface_graph.edges)
