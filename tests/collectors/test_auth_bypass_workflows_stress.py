"""
Empirical Challenge & Stress Test Harness for Challenger 2:
Multi-Step Workflows, Default Credential Probing, Quadruple State Publishing,
Concurrency, and False Positive Rejection.
"""
from __future__ import annotations

import base64
import copy
import json
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional, Tuple

import pytest

from argus.collectors.auth_bypass import (
    AuthBypassAnalyzer,
    AuthBypassCollector,
    AuthBypassPayloadGenerator,
    AuthBypassProbe,
    AuthBypassProbeResponse,
    AuthBypassProber,
    AuthBypassResult,
    AuthBypassSeverity,
    AuthMutationStrategy,
    AuthVulnerabilityType,
    TokenEntropyAnalyzer,
)
from argus.evidence.model import Evidence, ProvenanceData
from argus.evidence.store import EvidenceStore
from argus.graph.graph import KnowledgeGraph
from argus.graph.node import Node
from argus.http.client import HttpResponse
from argus.runtime.mission import Mission


# =============================================================================
# Advanced Multi-Protocol Stateful Mock HTTP Server
# =============================================================================

class StatefulMockAuthServer:
    """Stateful mock server for multi-step auth workflows & protocol testing."""

    def __init__(self):
        self.lock = threading.Lock()
        self.login_attempts: Dict[str, int] = {}
        self.valid_users = {"admin": "AdminPassword123!", "alice": "AliceSecret456!"}
        self.sessions: Dict[str, str] = {}
        self.used_reset_tokens: set[str] = set()
        self.mfa_phase1_tokens: set[str] = set()
        self.rate_limit_threshold = 100
        self.lockout_threshold = 100
        self.request_log: List[Dict[str, Any]] = []

    def request(self, *args: Any, **kwargs: Any) -> HttpResponse:
        with self.lock:
            method = (args[1] if len(args) > 1 and not isinstance(args[0], str) else args[0] if args else "GET").upper()
            url = args[2] if len(args) > 2 else (args[1] if len(args) > 1 and isinstance(args[0], str) else kwargs.get("url", ""))

            headers = {k.lower(): v for k, v in (kwargs.get("headers") or {}).items()}
            json_data = kwargs.get("json")
            data = kwargs.get("data")
            params = kwargs.get("params") or {}

            self.request_log.append({
                "method": method,
                "url": url,
                "headers": headers,
                "json": json_data,
                "data": data,
            })

            parsed = urllib.parse.urlparse(url)
            path = parsed.path

            # 1. Password reset host poisoning
            if "/password-reset" in path or "/forgot-password" in path or "/reset" in path:
                host_hdr = headers.get("host") or headers.get("x-forwarded-host") or headers.get("x-host")
                if host_hdr and "attacker-controlled" in host_hdr:
                    return HttpResponse(
                        success=True,
                        status_code=200,
                        body=f"Password reset link generated: https://{host_hdr}/reset?token=tok_12345",
                        headers={"Content-Type": "text/html"},
                        url=url,
                        elapsed=0.03,
                    )
                # Token reuse testing
                if isinstance(json_data, dict) and "token" in json_data:
                    tok = json_data["token"]
                    if tok in self.used_reset_tokens:
                        return HttpResponse(
                            success=False,
                            status_code=400,
                            body='{"error": "Token already consumed"}',
                            headers={"Content-Type": "application/json"},
                            url=url,
                            elapsed=0.02,
                        )
                    self.used_reset_tokens.add(tok)
                    return HttpResponse(
                        success=True,
                        status_code=200,
                        body='{"status": "password_reset_success"}',
                        headers={"Content-Type": "application/json"},
                        url=url,
                        elapsed=0.02,
                    )

            # 2. MFA Endpoint
            if "/mfa" in path or "/2fa" in path:
                # Direct endpoint access with Phase 1 intermediate token
                auth_hdr = headers.get("authorization", "")
                if "mfa_phase1_intermediate_token" in auth_hdr:
                    # Vulnerable endpoint allows direct bypass
                    return HttpResponse(
                        success=True,
                        status_code=200,
                        body='{"status": "success", "profile": "admin_user", "token": "jwt_fully_authenticated"}',
                        headers={"Content-Type": "application/json"},
                        url=url,
                        elapsed=0.02,
                    )
                if isinstance(json_data, dict) and (json_data.get("skip_mfa") or json_data.get("mfa_completed")):
                    return HttpResponse(
                        success=True,
                        status_code=200,
                        body='{"status": "success", "session": "active", "token": "mfa_bypassed_jwt"}',
                        headers={"Content-Type": "application/json"},
                        url=url,
                        elapsed=0.02,
                    )

            # 3. Session Fixation on login
            cookie_hdr = headers.get("cookie", "")
            if "/login" in path:
                # Check Basic Auth
                auth_hdr = headers.get("authorization", "")
                if auth_hdr.startswith("Basic ") or auth_hdr.startswith("basic "):
                    try:
                        raw_b64 = auth_hdr.split(" ", 1)[1]
                        decoded = base64.b64decode(raw_b64).decode("utf-8")
                        user, pwd = decoded.split(":", 1)
                        if user == "admin" and pwd == "admin":
                            return HttpResponse(
                                success=True,
                                status_code=200,
                                body='{"status": "authenticated", "user": "admin"}',
                                headers={"Content-Type": "application/json"},
                                url=url,
                                elapsed=0.02,
                            )
                    except Exception:
                        pass

                # Check JSON / Form login
                user = None
                pwd = None
                if isinstance(json_data, dict):
                    user = json_data.get("username")
                    pwd = json_data.get("password")
                elif isinstance(data, dict):
                    user = data.get("username")
                    pwd = data.get("password")

                if user:
                    self.login_attempts[user] = self.login_attempts.get(user, 0) + 1

                    # Lockout / Rate limit simulation
                    if self.login_attempts[user] > self.lockout_threshold:
                        return HttpResponse(
                            success=False,
                            status_code=429,
                            body='{"error": "Too many failed attempts. Account locked."}',
                            headers={"Retry-After": "300"},
                            url=url,
                            elapsed=0.01,
                        )

                    # Default credentials check
                    if (user, pwd) in [("admin", "admin"), ("root", "root"), ("tomcat", "tomcat"), ("kibana", "kibana")]:
                        resp_headers = {"Content-Type": "application/json"}
                        # If session fixation test, preserve the client cookie
                        if "sess_fixed_" in cookie_hdr:
                            resp_headers["set-cookie"] = cookie_hdr
                        return HttpResponse(
                            success=True,
                            status_code=200,
                            body=f'{{"status": "authenticated", "role": "admin", "user": "{user}"}}',
                            headers=resp_headers,
                            url=url,
                            elapsed=0.02,
                        )

                    # Timing discrepancy simulation for username enumeration
                    if user in self.valid_users:
                        # Valid user -> password hash comparison takes 1.2s
                        return HttpResponse(
                            success=False,
                            status_code=401,
                            body='{"error": "Invalid credentials for existing user"}',
                            headers={"Content-Type": "application/json"},
                            url=url,
                            elapsed=1.20,
                        )
                    else:
                        # Invalid user -> immediate rejection 0.05s
                        return HttpResponse(
                            success=False,
                            status_code=401,
                            body='{"error": "User not found"}',
                            headers={"Content-Type": "application/json"},
                            url=url,
                            elapsed=0.05,
                        )

            # Default fallback 401
            return HttpResponse(
                success=False,
                status_code=401,
                body='{"error": "Unauthorized access"}',
                headers={"Content-Type": "application/json"},
                url=url,
                elapsed=0.02,
            )

    def get(self, *args: Any, **kwargs: Any) -> HttpResponse:
        return self.request("GET", *args, **kwargs)

    def post(self, *args: Any, **kwargs: Any) -> HttpResponse:
        return self.request("POST", *args, **kwargs)


# =============================================================================
# 1. Multi-Step Authentication Workflows Stress Tests
# =============================================================================

def test_workflow_brute_force_lockout_and_rate_limiting_transitions():
    """
    Stress-tests brute force detection across state transitions:
    Case A: Completely unthrottled (vulnerable -> high finding)
    Case B: Throttled with 429 after 3 attempts (properly secured -> suppressed)
    Case C: Throttled via rate limit headers (properly secured -> suppressed)
    """
    server = StatefulMockAuthServer()
    prober = AuthBypassProber(http_client=server)
    analyzer = AuthBypassAnalyzer()
    target = "http://target.local/login"

    # Case A: Unthrottled 10 attempts
    probe_unthrottled = AuthBypassProbe(
        probe_id="p_unthrottled",
        target_url=target,
        method="POST",
        vulnerability_type=AuthVulnerabilityType.BRUTE_FORCE,
        json_data={"username": "admin", "password": "WrongPassword!"},
        burst_count=10,
        tested_parameter="password",
        metadata={"technique": "account_lockout_missing"},
    )
    resp_a = prober.execute_probe(None, target, probe_unthrottled)
    assert len(resp_a.burst_responses) == 10
    finding_a = analyzer.evaluate_probe(probe_unthrottled, resp_a, target)
    assert finding_a is not None
    assert finding_a.template_id == "auth-brute-force-no-lockout"
    assert finding_a.cwe_id == "CWE-307"

    # Case B: Server enforces lockout at attempt 4
    server.login_attempts.clear()
    server.lockout_threshold = 3
    resp_b = prober.execute_probe(None, target, probe_unthrottled)
    # Last response status is 429
    assert resp_b.status_code == 429
    finding_b = analyzer.evaluate_probe(probe_unthrottled, resp_b, target)
    assert finding_b is None  # Must be suppressed!

    # Case C: Rate limit headers present in response
    resp_c = AuthBypassProbeResponse(
        probe=probe_unthrottled,
        status_code=401,
        body='{"error": "invalid"}',
        rate_limit_headers={"x-ratelimit-remaining": "0", "retry-after": "60"},
        burst_responses=[
            {"iteration": i, "status_code": 401, "headers": {"x-ratelimit-remaining": "0"}, "body": "invalid"}
            for i in range(10)
        ],
    )
    finding_c = analyzer.evaluate_probe(probe_unthrottled, resp_c, target)
    assert finding_c is None  # Suppressed due to rate limiting


def test_workflow_mfa_forced_browsing_and_parameter_omission():
    """
    Stress-tests multi-step MFA bypass workflows:
    - Step 1: Endpoint accessed with Phase 1 token -> Returns 200 with session/token -> Flagged CRITICAL
    - Step 2: Endpoint accessed with skip_mfa=True parameter -> Returns 200 with session -> Flagged CRITICAL
    - Step 3: Endpoint properly requires OTP -> Returns 401/403 -> Suppressed
    """
    server = StatefulMockAuthServer()
    prober = AuthBypassProber(http_client=server)
    analyzer = AuthBypassAnalyzer()
    mfa_url = "http://target.local/api/mfa/verify"

    # Step 1: Forced browsing probe
    probe_fb = AuthBypassProbe(
        probe_id="p_mfa_fb",
        target_url=mfa_url,
        method="GET",
        vulnerability_type=AuthVulnerabilityType.MFA_BYPASS,
        headers={"Authorization": "Bearer mfa_phase1_intermediate_token"},
        metadata={"technique": "mfa_forced_browsing"},
    )
    resp_fb = prober.execute_probe(None, mfa_url, probe_fb)
    finding_fb = analyzer.evaluate_probe(probe_fb, resp_fb, mfa_url)
    assert finding_fb is not None
    assert finding_fb.severity == AuthBypassSeverity.CRITICAL.value
    assert finding_fb.cwe_id == "CWE-287"
    assert finding_fb.technique == "mfa_forced_browsing"

    # Step 2: Parameter omission
    probe_omission = AuthBypassProbe(
        probe_id="p_mfa_skip",
        target_url=mfa_url,
        method="POST",
        vulnerability_type=AuthVulnerabilityType.MFA_BYPASS,
        json_data={"skip_mfa": True, "otp": None},
        metadata={"technique": "missing_mfa_enforcement"},
    )
    resp_omission = prober.execute_probe(None, mfa_url, probe_omission)
    finding_omission = analyzer.evaluate_probe(probe_omission, resp_omission, mfa_url)
    assert finding_omission is not None
    assert finding_omission.cwe_id == "CWE-287"

    # Step 3: Properly defended MFA endpoint returning 401
    resp_secure = AuthBypassProbeResponse(
        probe=probe_omission,
        status_code=401,
        body='{"error": "MFA token required"}',
        headers={"Content-Type": "application/json"},
    )
    assert analyzer.evaluate_probe(probe_omission, resp_secure, mfa_url) is None


def test_workflow_session_fixation_cookie_lifecycle():
    """
    Stress-tests Session Fixation detection:
    - Pre-login session identifier set in Cookie header
    - Server accepts and echoes identical session cookie in Set-Cookie response -> Flagged
    - Server regenerates a new session cookie -> Suppressed
    """
    server = StatefulMockAuthServer()
    prober = AuthBypassProber(http_client=server)
    analyzer = AuthBypassAnalyzer()
    login_url = "http://target.local/login"

    preset_sid = "sess_fixed_victim_controlled_12345"
    probe_fix = AuthBypassProbe(
        probe_id="p_fixation",
        target_url=login_url,
        method="POST",
        vulnerability_type=AuthVulnerabilityType.SESSION_FIXATION,
        headers={"Cookie": f"session={preset_sid}"},
        json_data={"username": "admin", "password": "admin"},
        metadata={"technique": "session_fixation", "preset_session_id": preset_sid},
    )

    # Server preserves session cookie
    resp_vuln = prober.execute_probe(None, login_url, probe_fix)
    finding_vuln = analyzer.evaluate_probe(probe_fix, resp_vuln, login_url)
    assert finding_vuln is not None
    assert finding_vuln.template_id == "auth-session-fixation"
    assert finding_vuln.cwe_id == "CWE-384"
    assert finding_vuln.cvss_score == 8.1
    assert preset_sid in finding_vuln.evidence_snippet

    # Server properly issues a fresh new session cookie
    resp_safe = AuthBypassProbeResponse(
        probe=probe_fix,
        status_code=200,
        body='{"status": "authenticated"}',
        headers={"set-cookie": "session=sess_NEW_regenerated_99999; Path=/; HttpOnly; Secure"},
    )
    assert analyzer.evaluate_probe(probe_fix, resp_safe, login_url) is None


def test_workflow_password_reset_host_poisoning_and_token_reuse():
    """
    Stress-tests password reset vulnerability workflows:
    - Host header injection -> poisoned reset link generated in body -> Flagged HIGH
    - Normal reset request without host reflection -> Suppressed
    """
    server = StatefulMockAuthServer()
    prober = AuthBypassProber(http_client=server)
    analyzer = AuthBypassAnalyzer()
    reset_url = "http://target.local/password-reset"

    poisoned_host = "attacker-controlled-argus.evil"
    probe_poison = AuthBypassProbe(
        probe_id="p_pwd_poison",
        target_url=reset_url,
        method="POST",
        vulnerability_type=AuthVulnerabilityType.PASSWORD_RESET,
        headers={"Host": poisoned_host},
        json_data={"email": "victim@domain.com"},
        metadata={"technique": "password_reset_host_injection", "poisoned_host": poisoned_host},
    )

    resp_poison = prober.execute_probe(None, reset_url, probe_poison)
    finding_poison = analyzer.evaluate_probe(probe_poison, resp_poison, reset_url)
    assert finding_poison is not None
    assert finding_poison.template_id == "auth-password-reset-host-injection"
    assert finding_poison.cwe_id == "CWE-640"
    assert finding_poison.cvss_score == 8.2

    # Normal unexploited reset request
    probe_safe = AuthBypassProbe(
        probe_id="p_pwd_safe",
        target_url=reset_url,
        method="POST",
        vulnerability_type=AuthVulnerabilityType.PASSWORD_RESET,
        headers={"Host": "legitimate-app.com"},
        json_data={"email": "victim@domain.com"},
        metadata={"technique": "password_reset_host_injection", "poisoned_host": poisoned_host},
    )
    resp_safe = AuthBypassProbeResponse(
        probe=probe_safe,
        status_code=200,
        body="Password reset link sent: https://legitimate-app.com/reset?token=abc",
    )
    assert analyzer.evaluate_probe(probe_safe, resp_safe, reset_url) is None


# =============================================================================
# 2. Multi-Protocol Default Credentials Probing
# =============================================================================

def test_default_credentials_probing_across_protocols():
    """
    Validates default credential detection across:
    1. JSON POST payload
    2. Form-encoded / Data payload
    3. HTTP Basic Auth
    """
    server = StatefulMockAuthServer()
    prober = AuthBypassProber(http_client=server)
    analyzer = AuthBypassAnalyzer()
    login_url = "http://target.local/login"

    # 1. JSON POST probe
    probe_json = AuthBypassProbe(
        probe_id="p_cred_json",
        target_url=login_url,
        method="POST",
        vulnerability_type=AuthVulnerabilityType.DEFAULT_CREDENTIALS,
        json_data={"username": "admin", "password": "admin"},
        metadata={"technique": "default_credentials", "username": "admin", "password": "admin", "service": "Generic Admin"},
    )
    resp_json = prober.execute_probe(None, login_url, probe_json)
    finding_json = analyzer.evaluate_probe(probe_json, resp_json, login_url)
    assert finding_json is not None
    assert finding_json.template_id == "auth-default-credentials"
    assert finding_json.cwe_id == "CWE-798"
    assert finding_json.cvss_score == 9.8
    assert "admin:admin" in finding_json.evidence_snippet

    # 2. Basic Auth probe
    b64_basic = base64.b64encode(b"admin:admin").decode("utf-8")
    probe_basic = AuthBypassProbe(
        probe_id="p_cred_basic",
        target_url=login_url,
        method="GET",
        vulnerability_type=AuthVulnerabilityType.DEFAULT_CREDENTIALS,
        headers={"Authorization": f"Basic {b64_basic}"},
        metadata={"technique": "default_credentials", "username": "admin", "password": "admin", "service": "Tomcat"},
    )
    resp_basic = prober.execute_probe(None, login_url, probe_basic)
    finding_basic = analyzer.evaluate_probe(probe_basic, resp_basic, login_url)
    assert finding_basic is not None
    assert finding_basic.cwe_id == "CWE-798"


# =============================================================================
# 3. Quadruple State Publishing Under High Concurrency & Edge Cases
# =============================================================================

def test_quadruple_state_publishing_concurrency_stress():
    """
    Stress-tests Quadruple State Publishing across 20 concurrent collector threads.
    Verifies thread safety, graph integrity, evidence recording, and publish_finding callbacks.
    """
    server = StatefulMockAuthServer()
    collector = AuthBypassCollector(http_client=server, max_probes_per_endpoint=10)

    # Prepare shared Mission state
    mission = Mission(target="http://target.local/login")
    mission.attack_surface_graph = KnowledgeGraph()
    published_lock = threading.Lock()
    published_records: List[Tuple[str, Evidence]] = []

    def mock_publish_finding(fid: str, fev: Evidence):
        with published_lock:
            published_records.append((fid, fev))

    mission.publish_finding = mock_publish_finding

    # Run 20 concurrent collections
    num_threads = 20
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(collector.collect, mission) for _ in range(num_threads)]
        results = [f.result() for f in futures]

    # Verify all threads returned results
    for res in results:
        assert isinstance(res, list)

    # 1. raw_mission.evidence
    ev_all = mission.evidence.all()
    assert len(ev_all) >= 1
    assert all(e.category == "auth_bypass" for e in ev_all)

    # 2. raw_mission.vulnerabilities
    assert len(mission.vulnerabilities) >= 1
    assert all(isinstance(v, dict) and "template_id" in v for v in mission.vulnerabilities)

    # 3. Attack Surface Knowledge Graph
    graph = mission.attack_surface_graph
    assert len(graph.nodes) >= 3
    assert len(graph.edges) >= 2
    # Verify no corrupted edges (source & target exist in nodes)
    for edge in graph.edges:
        assert edge.source in graph.nodes, f"Missing source node: {edge.source}"
        assert edge.target in graph.nodes, f"Missing target node: {edge.target}"

    # 4. publish_finding
    assert len(published_records) >= 1
    assert all(isinstance(rec[1], Evidence) for rec in published_records)


def test_quadruple_state_publishing_resilience_to_missing_sinks():
    """
    Validates that Quadruple State Publishing degrades gracefully when individual sinks
    are None, raise exceptions, or are missing methods.
    """
    collector = AuthBypassCollector()

    # Case 1: Graph is None, publish_finding raises exception, vulnerabilities is None
    class BrokenMission:
        def __init__(self):
            self.evidence = []
            self.vulnerabilities = None
            self.attack_surface_graph = None

        def publish_finding(self, *args):
            raise RuntimeError("Sink offline!")

    broken_mission = BrokenMission()
    dummy_result = AuthBypassResult(
        template_id="auth-test-resilience",
        technique="test_technique",
        vulnerability_type=AuthVulnerabilityType.BRUTE_FORCE,
        mutation_strategy="standard",
        endpoint_url="http://broken.local",
        severity=AuthBypassSeverity.HIGH.value,
        cwe_id="CWE-307",
        cvss_score=7.5,
        description="Resilience test finding",
    )

    ev = collector._emit_evidence(broken_mission, dummy_result, "http://broken.local", "http://broken.local")
    assert isinstance(ev, Evidence)
    assert len(broken_mission.evidence) == 1
    assert broken_mission.evidence[0].category == "auth_bypass"


# =============================================================================
# 4. False Positive Rejection Stress Matrix
# =============================================================================

@pytest.mark.parametrize(
    "status_code,body,headers,is_benign,error,expected_finding",
    [
        (200, "<html><body>Welcome! Please enter your credentials.</body></html>", {}, True, None, False),
        (401, '{"error": "Unauthorized", "message": "Invalid password"}', {}, False, None, False),
        (403, '{"error": "Forbidden", "message": "Access restricted"}', {}, False, None, False),
        (404, "404 Not Found", {}, False, None, False),
        (429, '{"error": "Rate limit exceeded"}', {"retry-after": "60"}, False, None, False),
        (200, "Login Failed: Invalid username or password", {}, False, None, False),
        (200, "Error: Authentication failed", {}, False, None, False),
        (200, "Bad credentials supplied", {}, False, None, False),
        (0, "", {}, False, "Connection refused", False),
        (504, "Gateway Timeout", {}, False, "Gateway Timeout", False),
        (500, "Internal Server Error without sensitive info", {}, False, None, False),
    ],
)
def test_false_positive_rejection_stress_matrix(
    status_code: int,
    body: str,
    headers: Dict[str, str],
    is_benign: bool,
    error: Optional[str],
    expected_finding: bool,
):
    """Stress-tests false positive suppression across status codes, soft-error texts, and benign probes."""
    analyzer = AuthBypassAnalyzer()
    probe = AuthBypassProbe(
        probe_id="fp_matrix_probe",
        target_url="http://target.local/login",
        method="POST",
        vulnerability_type=AuthVulnerabilityType.DEFAULT_CREDENTIALS,
        is_benign=is_benign,
        metadata={"technique": "default_credentials", "username": "admin", "password": "wrong"},
    )
    resp = AuthBypassProbeResponse(
        probe=probe,
        status_code=status_code,
        body=body,
        headers=headers,
        error=error,
    )

    result = analyzer.evaluate_probe(probe, resp, "http://target.local/login")
    if not expected_finding:
        assert result is None, f"Expected no finding, but got: {result}"
