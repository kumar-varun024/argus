"""
Unit and Component tests for Authentication Bypass & Credential Attack Detection Module:
AuthBypassCollector, AuthBypassPayloadGenerator, AuthBypassProber, AuthBypassAnalyzer,
TokenEntropyAnalyzer, Quadruple State Publishing, and False Positive Rejection.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import json
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple, Union
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
from argus.evidence.model import Evidence
from argus.evidence.store import EvidenceStore
from argus.graph.attack_surface import AttackSurfaceGraphBuilder
from argus.graph.graph import KnowledgeGraph
from argus.graph.node import Node
from argus.http.client import HttpResponse
from argus.runtime.mission import Mission


# =============================================================================
# Configurable Mock HTTP Client for Auth Bypass Testing
# =============================================================================

class MockAuthHttpClient:
    """Configurable mock HTTP client for authentication bypass unit tests."""

    def __init__(self, routes: Optional[Dict[str, Tuple[int, str, Dict[str, str], float]]] = None):
        # key -> (status_code, body, headers, elapsed)
        self.routes: Dict[str, Tuple[int, str, Dict[str, str], float]] = dict(routes or {})
        self.request_history: List[Dict[str, Any]] = []

    def set_route(
        self,
        key: str,
        status_code: int,
        body: str,
        headers: Optional[Dict[str, str]] = None,
        elapsed: float = 0.05,
    ) -> None:
        self.routes[key] = (status_code, body, headers or {}, elapsed)

    def request(self, mission_or_method: Any, *args: Any, **kwargs: Any) -> HttpResponse:
        # Polymorphic signature support: (mission, method, url) or (method, url)
        if isinstance(mission_or_method, str):
            method = mission_or_method.upper()
            url = args[0] if args else kwargs.get("url", "")
        else:
            method = (args[0] if args else kwargs.get("method", "GET")).upper()
            url = args[1] if len(args) > 1 else kwargs.get("url", "")

        target_url = str(url)
        headers = kwargs.get("headers") or {}
        json_data = kwargs.get("json")
        data = kwargs.get("data")
        params = kwargs.get("params") or {}

        self.request_history.append({
            "method": method,
            "url": target_url,
            "headers": headers,
            "json": json_data,
            "data": data,
            "params": params,
        })

        # 1. Exact match on URL
        if target_url in self.routes:
            st, bd, hd, el = self.routes[target_url]
            return HttpResponse(
                success=(200 <= st < 300),
                status_code=st,
                raw_body=bd,
                body=bd,
                headers=hd,
                url=target_url,
                elapsed=el,
            )

        # 2. Match on Authorization header
        auth_hdr = headers.get("Authorization") or headers.get("authorization")
        if auth_hdr and f"auth:{auth_hdr}" in self.routes:
            st, bd, hd, el = self.routes[f"auth:{auth_hdr}"]
            return HttpResponse(
                success=(200 <= st < 300),
                status_code=st,
                raw_body=bd,
                body=bd,
                headers=hd,
                url=target_url,
                elapsed=el,
            )

        # 3. Match on Host / X-Forwarded-Host header
        for hdr_name in ["Host", "X-Forwarded-Host", "X-Forwarded-Server", "X-Host"]:
            if hdr_name in headers and f"hdr:{hdr_name}:{headers[hdr_name]}" in self.routes:
                st, bd, hd, el = self.routes[f"hdr:{hdr_name}:{headers[hdr_name]}"]
                return HttpResponse(
                    success=(200 <= st < 300),
                    status_code=st,
                    raw_body=bd,
                    body=bd,
                    headers=hd,
                    url=target_url,
                    elapsed=el,
                )

        # 4. Match on JSON username/password or token
        if isinstance(json_data, dict):
            user = json_data.get("username") or json_data.get("email")
            pwd = json_data.get("password")
            if user and pwd and f"user:{user}:{pwd}" in self.routes:
                st, bd, hd, el = self.routes[f"user:{user}:{pwd}"]
                return HttpResponse(
                    success=(200 <= st < 300),
                    status_code=st,
                    raw_body=bd,
                    body=bd,
                    headers=hd,
                    url=target_url,
                    elapsed=el,
                )
            if user and f"user:{user}" in self.routes:
                st, bd, hd, el = self.routes[f"user:{user}"]
                return HttpResponse(
                    success=(200 <= st < 300),
                    status_code=st,
                    raw_body=bd,
                    body=bd,
                    headers=hd,
                    url=target_url,
                    elapsed=el,
                )
            token_val = json_data.get("token")
            if token_val and f"token:{token_val}" in self.routes:
                st, bd, hd, el = self.routes[f"token:{token_val}"]
                return HttpResponse(
                    success=(200 <= st < 300),
                    status_code=st,
                    raw_body=bd,
                    body=bd,
                    headers=hd,
                    url=target_url,
                    elapsed=el,
                )

        # 5. Match on Cookie header
        cookie_hdr = headers.get("Cookie") or headers.get("cookie")
        if cookie_hdr:
            for k in self.routes:
                if k.startswith("cookie:") and k[7:] in cookie_hdr:
                    st, bd, hd, el = self.routes[k]
                    return HttpResponse(
                        success=(200 <= st < 300),
                        status_code=st,
                        raw_body=bd,
                        body=bd,
                        headers=hd,
                        url=target_url,
                        elapsed=el,
                    )

        # Default fallback
        return HttpResponse(
            success=False,
            status_code=401,
            raw_body='{"error": "invalid credentials"}',
            body='{"error": "invalid credentials"}',
            headers={"Content-Type": "application/json"},
            url=target_url,
            elapsed=0.05,
        )

    def get(self, *args: Any, **kwargs: Any) -> HttpResponse:
        if args and not isinstance(args[0], str):
            mission = args[0]
            url = args[1] if len(args) > 1 else kwargs.get("url", "")
            return self.request(mission, "GET", url, **kwargs)
        url = args[0] if args else kwargs.get("url", "")
        return self.request("GET", url, **kwargs)

    def post(self, *args: Any, **kwargs: Any) -> HttpResponse:
        if args and not isinstance(args[0], str):
            mission = args[0]
            url = args[1] if len(args) > 1 else kwargs.get("url", "")
            return self.request(mission, "POST", url, **kwargs)
        url = args[0] if args else kwargs.get("url", "")
        return self.request("POST", url, **kwargs)


# =============================================================================
# 1. R3: Shannon Entropy and Token Predictability Tests
# =============================================================================

def test_token_entropy_shannon_calculation():
    """Validates mathematical Shannon entropy calculation on predictable vs high entropy tokens."""
    analyzer = TokenEntropyAnalyzer()

    # Empty token has 0 entropy
    assert analyzer.calculate_shannon_entropy("") == 0.0

    # Low entropy repeating strings
    low_entropy = analyzer.calculate_shannon_entropy("aaaaaaaaaaaa")
    assert low_entropy == 0.0

    simple_repeat = analyzer.calculate_shannon_entropy("abababababab")
    assert round(simple_repeat, 2) == 1.0

    # Prefix stripping (sess_, usr_, tok_)
    with_prefix = analyzer.calculate_shannon_entropy("sess_aaaaaaaa")
    assert with_prefix == 0.0

    # Cryptographically random token (hex / base64)
    crypto_token = "4f8a1b2c3d4e5f6a7b8c9d0e1f2a3b4c"
    high_entropy = analyzer.calculate_shannon_entropy(crypto_token)
    assert high_entropy >= 3.5


def test_token_entropy_sequential_detection():
    """Validates detection of sequential incremental numbers and low edit distance tokens."""
    analyzer = TokenEntropyAnalyzer()

    # Less than 3 tokens cannot determine progression
    assert not analyzer.detect_sequential_tokens(["tok_100", "tok_101"])

    # Numeric progression (increment by 1)
    seq_tokens = ["sess_1001", "sess_1002", "sess_1003", "sess_1004"]
    assert analyzer.detect_sequential_tokens(seq_tokens)

    # Numeric progression (increment by 10)
    seq_step10 = ["tok_10", "tok_20", "tok_30"]
    assert analyzer.detect_sequential_tokens(seq_step10)

    # String Levenshtein edit distance progression
    similar_tokens = [
        "session_alpha_01",
        "session_alpha_02",
        "session_alpha_03",
    ]
    assert analyzer.detect_sequential_tokens(similar_tokens)

    # Truly random tokens
    random_tokens = [
        "9f83ab29f0c14b62",
        "3d12ee98bb01ca44",
        "77bca210fed938a1",
    ]
    assert not analyzer.detect_sequential_tokens(random_tokens)


def test_token_entropy_timestamp_leak():
    """Validates detection of embedded Unix epoch timestamps in tokens."""
    analyzer = TokenEntropyAnalyzer()

    # Empty token
    assert not analyzer.detect_timestamp_leak("")

    # 10-digit current epoch timestamp (using word boundary separators)
    current_epoch = int(time.time())
    token_with_epoch = f"reset-{current_epoch}-user123"
    assert analyzer.detect_timestamp_leak(token_with_epoch)

    # 13-digit millisecond epoch timestamp
    current_epoch_ms = int(time.time() * 1000)
    token_with_epoch_ms = f"sess.{current_epoch_ms}.data"
    assert analyzer.detect_timestamp_leak(token_with_epoch_ms)

    # Far past / unrelated numbers
    old_epoch_token = "sess-1000000000-data"
    assert not analyzer.detect_timestamp_leak(old_epoch_token)

    # Completely random hex token
    random_token = "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"
    assert not analyzer.detect_timestamp_leak(random_token)


# =============================================================================
# 2. R4: Mutation & Evasion Strategies Tests
# =============================================================================

def test_auth_mutation_case_sensitivity():
    """Validates case sensitivity mutations on usernames and URL paths."""
    gen = AuthBypassPayloadGenerator()
    probe = AuthBypassProbe(
        probe_id="p1",
        target_url="http://example.com/admin/login",
        method="POST",
        json_data={"username": "administrator", "password": "password"},
    )
    mutated = gen.apply_case_sensitivity_mutation(probe)

    assert mutated.strategy == AuthMutationStrategy.CASE_SENSITIVITY
    assert mutated.probe_id.endswith("_case_mut")
    assert mutated.json_data["username"] == "Administrator"
    assert mutated.target_url == "http://example.com/Admin/login"


def test_auth_mutation_unicode_homoglyphs():
    """Validates Unicode homoglyph injection (Cyrillic a/o) into username fields."""
    gen = AuthBypassPayloadGenerator()
    probe = AuthBypassProbe(
        probe_id="p2",
        target_url="http://example.com/api/login",
        method="POST",
        json_data={"username": "admin"},
    )
    mutated = gen.apply_unicode_normalization_mutation(probe)

    assert mutated.strategy == AuthMutationStrategy.UNICODE_NORMALIZATION
    assert mutated.probe_id.endswith("_unicode_mut")
    # Latin 'a' (0x61) replaced by Cyrillic 'а' (0x0430)
    assert "\u0430" in mutated.json_data["username"]
    assert mutated.tampered_value == mutated.json_data["username"]


def test_auth_mutation_auth_headers_and_ip_spoofing():
    """Validates loopback IP injection and URL rewrite headers."""
    gen = AuthBypassPayloadGenerator()
    probe = AuthBypassProbe(
        probe_id="p3",
        target_url="http://example.com/internal/auth",
        method="GET",
        headers={"User-Agent": "ARGUS"},
    )
    mutated = gen.apply_auth_header_mutation(probe)

    assert mutated.strategy == AuthMutationStrategy.AUTH_HEADER_MANIPULATION
    assert mutated.headers["X-Forwarded-For"] == "127.0.0.1"
    assert mutated.headers["X-Real-IP"] == "127.0.0.1"
    assert mutated.headers["X-Original-URL"] == "/admin"
    assert mutated.headers["X-Rewrite-URL"] == "/admin"
    assert mutated.headers["X-Custom-IP-Authorization"] == "127.0.0.1"


def test_auth_mutation_token_format_manipulation():
    """Validates Bearer token format variations (lowercase, double space)."""
    gen = AuthBypassPayloadGenerator()
    probe = AuthBypassProbe(
        probe_id="p4",
        target_url="http://example.com/api/user",
        method="GET",
        headers={"Authorization": "Bearer sample_token_123"},
    )
    mutated = gen.apply_token_format_mutation(probe)

    assert mutated.strategy == AuthMutationStrategy.TOKEN_FORMAT_MANIPULATION
    assert mutated.headers["Authorization"] == "bearer  sample_token_123"


def test_auth_mutation_response_and_method_override():
    """Validates X-HTTP-Method-Override header application."""
    gen = AuthBypassPayloadGenerator()
    probe = AuthBypassProbe(
        probe_id="p5",
        target_url="http://example.com/api/protected",
        method="POST",
    )
    mutated = gen.apply_response_manipulation_mutation(probe)

    assert mutated.strategy == AuthMutationStrategy.RESPONSE_MANIPULATION
    assert mutated.headers["X-HTTP-Method-Override"] == "GET"


def test_auth_mutation_dispatcher():
    """Validates general apply_mutation dispatcher across all strategies."""
    gen = AuthBypassPayloadGenerator()
    probe = AuthBypassProbe(
        probe_id="base",
        target_url="http://example.com/login",
        method="POST",
        json_data={"username": "root"},
    )

    m1 = gen.apply_mutation(probe, AuthMutationStrategy.CASE_SENSITIVITY)
    assert m1.strategy == AuthMutationStrategy.CASE_SENSITIVITY

    m2 = gen.apply_mutation(probe, "unicode_normalization")
    assert m2.strategy == AuthMutationStrategy.UNICODE_NORMALIZATION

    m3 = gen.apply_mutation(probe, AuthMutationStrategy.AUTH_HEADER_MANIPULATION)
    assert m3.headers.get("X-Forwarded-For") == "127.0.0.1"

    m4 = gen.apply_mutation(probe, AuthMutationStrategy.TOKEN_FORMAT_MANIPULATION)
    assert m4.strategy == AuthMutationStrategy.TOKEN_FORMAT_MANIPULATION

    m5 = gen.apply_mutation(probe, AuthMutationStrategy.RESPONSE_MANIPULATION)
    assert m5.headers.get("X-HTTP-Method-Override") == "GET"

    m_standard = gen.apply_mutation(probe, AuthMutationStrategy.STANDARD)
    assert m_standard.probe_id == "base"


# =============================================================================
# 3. Detection Modes 1 - 6 Unit Tests
# =============================================================================

def test_detection_mode_1_brute_force_missing_lockout():
    """Tests detection of missing account lockout and rate limiting across login bursts."""
    analyzer = AuthBypassAnalyzer()
    probe = AuthBypassProbe(
        probe_id="bf_burst_1",
        target_url="http://example.com/api/login",
        method="POST",
        vulnerability_type=AuthVulnerabilityType.BRUTE_FORCE,
        tested_parameter="password",
        metadata={"technique": "account_lockout_missing"},
    )

    burst_resps = [
        {"iteration": i, "status_code": 401, "elapsed": 0.05, "headers": {}, "body": '{"error":"bad auth"}'}
        for i in range(10)
    ]
    response = AuthBypassProbeResponse(
        probe=probe,
        status_code=401,
        body='{"error":"bad auth"}',
        burst_responses=burst_resps,
        rate_limit_headers={},
    )

    result = analyzer.evaluate_probe(probe, response, "http://example.com/api/login")
    assert result is not None
    assert result.template_id == "auth-brute-force-no-lockout"
    assert result.technique == "account_lockout_missing"
    assert result.cwe_id == "CWE-307"
    assert result.cvss_score == 7.5
    assert result.severity == AuthBypassSeverity.HIGH.value
    assert "lacks account lockout" in result.description


def test_detection_mode_1_brute_force_timing_enumeration():
    """Tests detection of username enumeration via timing differential."""
    analyzer = AuthBypassAnalyzer()
    probe = AuthBypassProbe(
        probe_id="bf_enum_1",
        target_url="http://example.com/login",
        method="POST",
        vulnerability_type=AuthVulnerabilityType.BRUTE_FORCE,
        tested_parameter="username",
        metadata={"technique": "username_enumeration_timing"},
    )

    burst_resps = [
        {"iteration": i, "status_code": 401, "elapsed": 1.25, "headers": {}, "body": "Invalid user"}
        for i in range(5)
    ]
    response = AuthBypassProbeResponse(
        probe=probe,
        status_code=401,
        body="Invalid user",
        burst_responses=burst_resps,
    )

    result = analyzer.evaluate_probe(probe, response, "http://example.com/login")
    assert result is not None
    assert result.template_id == "auth-username-enumeration-timing"
    assert result.cwe_id == "CWE-208"
    assert result.cvss_score == 5.3
    assert result.severity == AuthBypassSeverity.MEDIUM.value


def test_detection_mode_2_password_reset_host_injection():
    """Tests detection of Host header poisoning in password reset flow."""
    analyzer = AuthBypassAnalyzer()
    poisoned_host = "attacker-controlled-argus.evil"
    probe = AuthBypassProbe(
        probe_id="pwd_reset_1",
        target_url="http://example.com/forgot-password",
        method="POST",
        vulnerability_type=AuthVulnerabilityType.PASSWORD_RESET,
        tested_parameter="Host",
        metadata={"technique": "password_reset_host_injection", "poisoned_host": poisoned_host},
    )

    response = AuthBypassProbeResponse(
        probe=probe,
        status_code=200,
        body=f"Password reset link sent: https://{poisoned_host}/reset?token=xyz",
        headers={"Content-Type": "text/html"},
    )

    result = analyzer.evaluate_probe(probe, response, "http://example.com/forgot-password")
    assert result is not None
    assert result.template_id == "auth-password-reset-host-injection"
    assert result.cwe_id == "CWE-640"
    assert result.cvss_score == 8.2
    assert result.severity == AuthBypassSeverity.HIGH.value
    assert poisoned_host in result.description


def test_detection_mode_3_mfa_bypass_parameter_omission():
    """Tests detection of MFA bypass via parameter omission or state injection."""
    analyzer = AuthBypassAnalyzer()
    probe = AuthBypassProbe(
        probe_id="mfa_skip_1",
        target_url="http://example.com/api/mfa/verify",
        method="POST",
        vulnerability_type=AuthVulnerabilityType.MFA_BYPASS,
        tested_parameter="skip_mfa",
        metadata={"technique": "missing_mfa_enforcement"},
    )

    response = AuthBypassProbeResponse(
        probe=probe,
        status_code=200,
        body='{"status": "success", "session": "active", "token": "mfa_bypassed_jwt"}',
        headers={"Content-Type": "application/json"},
    )

    result = analyzer.evaluate_probe(probe, response, "http://example.com/api/mfa/verify")
    assert result is not None
    assert result.template_id == "auth-mfa-bypass"
    assert result.cwe_id == "CWE-287"
    assert result.cvss_score == 8.8
    assert result.severity == AuthBypassSeverity.CRITICAL.value


def test_detection_mode_4_session_fixation():
    """Tests detection of session fixation where pre-login session is retained."""
    analyzer = AuthBypassAnalyzer()
    preset_sid = "sess_fixed_1234567890abcdef"
    probe = AuthBypassProbe(
        probe_id="sess_fix_1",
        target_url="http://example.com/login",
        method="POST",
        vulnerability_type=AuthVulnerabilityType.SESSION_FIXATION,
        tested_parameter="Cookie",
        metadata={"technique": "session_fixation", "preset_session_id": preset_sid},
    )

    response = AuthBypassProbeResponse(
        probe=probe,
        status_code=200,
        body='{"status": "logged_in"}',
        headers={"set-cookie": f"session={preset_sid}; Path=/; HttpOnly"},
    )

    result = analyzer.evaluate_probe(probe, response, "http://example.com/login")
    assert result is not None
    assert result.template_id == "auth-session-fixation"
    assert result.cwe_id == "CWE-384"
    assert result.cvss_score == 8.1
    assert result.severity == AuthBypassSeverity.HIGH.value
    assert preset_sid in result.evidence_snippet


def test_detection_mode_5_jwt_manipulation_alg_none_and_unsigned():
    """Tests detection of JWT manipulation vulnerabilities (alg: none, missing signature)."""
    analyzer = AuthBypassAnalyzer()
    probe = AuthBypassProbe(
        probe_id="jwt_none_1",
        target_url="http://example.com/api/admin/dashboard",
        method="GET",
        vulnerability_type=AuthVulnerabilityType.JWT_MANIPULATION,
        tested_parameter="Authorization",
        metadata={"technique": "jwt_alg_none"},
    )

    response = AuthBypassProbeResponse(
        probe=probe,
        status_code=200,
        body='{"admin_access": true, "welcome": "admin"}',
        headers={"Content-Type": "application/json"},
    )

    result = analyzer.evaluate_probe(probe, response, "http://example.com/api/admin/dashboard")
    assert result is not None
    assert result.template_id == "auth-jwt-jwt_alg_none"
    assert result.cwe_id == "CWE-345"
    assert result.cvss_score == 9.8
    assert result.severity == AuthBypassSeverity.CRITICAL.value


def test_detection_mode_6_default_credentials():
    """Tests detection of default administrative credentials on portals and APIs."""
    analyzer = AuthBypassAnalyzer()
    probe = AuthBypassProbe(
        probe_id="def_cred_1",
        target_url="http://example.com/grafana/login",
        method="POST",
        vulnerability_type=AuthVulnerabilityType.DEFAULT_CREDENTIALS,
        tested_parameter="username:password",
        metadata={"technique": "default_credentials", "username": "admin", "password": "admin", "service": "Grafana"},
    )

    response = AuthBypassProbeResponse(
        probe=probe,
        status_code=200,
        body='{"message": "Logged in", "user": "admin"}',
        headers={"Content-Type": "application/json"},
    )

    result = analyzer.evaluate_probe(probe, response, "http://example.com/grafana/login")
    assert result is not None
    assert result.template_id == "auth-default-credentials"
    assert result.cwe_id == "CWE-798"
    assert result.cvss_score == 9.8
    assert result.severity == AuthBypassSeverity.CRITICAL.value
    assert "admin:admin" in result.evidence_snippet


# =============================================================================
# 4. Deep Session Analysis & Sensitive Leak Detection Tests
# =============================================================================

def test_session_token_analysis_insecure_cookie_attributes():
    """Tests detection of missing Secure, HttpOnly, and SameSite cookie flags on HTTPS."""
    analyzer = AuthBypassAnalyzer()
    probe = AuthBypassProbe(
        probe_id="sess_audit_1",
        target_url="https://example.com/api/login",
        method="GET",
        vulnerability_type=AuthVulnerabilityType.SESSION_TOKEN_ANALYSIS,
        tested_parameter="Set-Cookie",
    )

    # Missing Secure, HttpOnly, and SameSite
    response = AuthBypassProbeResponse(
        probe=probe,
        status_code=200,
        body="{}",
        headers={"set-cookie": "session_id=abc123xyz; Path=/"},
    )

    result = analyzer.evaluate_probe(probe, response, "https://example.com/api/login")
    assert result is not None
    assert result.template_id == "auth-insecure-cookie-attributes"
    assert result.cwe_id == "CWE-614"
    assert result.cvss_score == 5.3
    assert result.severity == AuthBypassSeverity.MEDIUM.value
    assert "Secure" in result.description
    assert "HttpOnly" in result.description
    assert "SameSite" in result.description


def test_credential_stuffing_susceptibility():
    """Tests detection of distributed IP brute force susceptibility (per-IP rather than per-account rate limiting)."""
    analyzer = AuthBypassAnalyzer()
    probe = AuthBypassProbe(
        probe_id="cred_stuff_1",
        target_url="http://example.com/login",
        method="POST",
        vulnerability_type=AuthVulnerabilityType.CREDENTIAL_STUFFING,
        tested_parameter="X-Forwarded-For",
        metadata={"technique": "credential_stuffing_susceptible"},
    )

    burst_resps = [
        {"iteration": i, "status_code": 401, "elapsed": 0.05, "headers": {}, "body": "Bad password"}
        for i in range(10)
    ]
    response = AuthBypassProbeResponse(
        probe=probe,
        status_code=401,
        body="Bad password",
        burst_responses=burst_resps,
        rate_limit_headers={},
    )

    result = analyzer.evaluate_probe(probe, response, "http://example.com/login")
    assert result is not None
    assert result.template_id == "auth-credential-stuffing-susceptible"
    assert result.cwe_id == "CWE-307"
    assert result.cvss_score == 6.5
    assert result.severity == AuthBypassSeverity.MEDIUM.value


def test_sensitive_credential_leak_detection():
    """Tests detection of exposed JWTs, private keys, AWS keys, and password hashes in error responses."""
    analyzer = AuthBypassAnalyzer()
    probe = AuthBypassProbe(
        probe_id="leak_probe_1",
        target_url="http://example.com/api/debug",
        method="POST",
        vulnerability_type=AuthVulnerabilityType.BRUTE_FORCE,
    )

    # Response with JWT token and bcrypt hash
    body_with_leak = (
        "Internal Debug Dump: "
        "Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c "
        "UserHash: $2a$12$e8uqf91gK93GgCgV3a2iNe3W62F36P3KjYw9y6Z7m9T5i2.86W7qC"
    )
    response = AuthBypassProbeResponse(
        probe=probe,
        status_code=500,
        body=body_with_leak,
        headers={"Content-Type": "text/plain"},
    )

    result = analyzer.evaluate_probe(probe, response, "http://example.com/api/debug")
    assert result is not None
    assert result.template_id == "auth-credential-leakage"
    assert result.cwe_id == "CWE-522"
    assert result.severity == AuthBypassSeverity.HIGH.value
    assert "jwt_token" in result.description
    assert "bcrypt_hash" in result.description


def test_error_disclosure_stack_trace_detection():
    """Tests detection of stack traces and internal paths in authentication errors."""
    analyzer = AuthBypassAnalyzer()

    # Python traceback
    py_body = "Traceback (most recent call last):\n  File '/app/auth.py', line 45, in authenticate\nValueError: invalid user"
    assert analyzer.detect_error_disclosure(py_body) is not None
    assert "python_traceback" in analyzer.detect_error_disclosure(py_body)

    # Java exception
    java_body = "HTTP 500: java.lang.NullPointerException: Object reference is null at com.app.Auth"
    assert analyzer.detect_error_disclosure(java_body) is not None
    assert "java_exception" in analyzer.detect_error_disclosure(java_body)

    # SQL syntax error
    sql_body = "You have an error in your SQL syntax near 'admin'' at line 1 MySQL server"
    assert analyzer.detect_error_disclosure(sql_body) is not None
    assert "sql_syntax_error" in analyzer.detect_error_disclosure(sql_body)


# =============================================================================
# 5. Strict False Positive Rejection Tests
# =============================================================================

def test_false_positive_rejection_benign_probes():
    """Verifies that benign baseline probes are always suppressed."""
    analyzer = AuthBypassAnalyzer()
    probe = AuthBypassProbe(
        probe_id="p_benign",
        target_url="http://example.com/login",
        method="GET",
        is_benign=True,
    )
    response = AuthBypassProbeResponse(
        probe=probe,
        status_code=200,
        body="<html>Login Form</html>",
    )
    assert analyzer.is_false_positive(probe, response)
    assert analyzer.evaluate_probe(probe, response, "http://example.com/login") is None


def test_false_positive_rejection_connection_errors():
    """Verifies that connection errors or zero status codes are suppressed."""
    analyzer = AuthBypassAnalyzer()
    probe = AuthBypassProbe(
        probe_id="p_err",
        target_url="http://example.com/login",
        method="POST",
        vulnerability_type=AuthVulnerabilityType.DEFAULT_CREDENTIALS,
    )
    response = AuthBypassProbeResponse(
        probe=probe,
        status_code=0,
        error="Connection refused",
    )
    assert analyzer.is_false_positive(probe, response)
    assert analyzer.evaluate_probe(probe, response, "http://example.com/login") is None


def test_false_positive_rejection_standard_401_403():
    """Verifies that standard 401/403 rejections without data leakage are suppressed."""
    analyzer = AuthBypassAnalyzer()
    probe = AuthBypassProbe(
        probe_id="p_auth_rej",
        target_url="http://example.com/api/admin",
        method="GET",
        vulnerability_type=AuthVulnerabilityType.JWT_MANIPULATION,
    )
    response = AuthBypassProbeResponse(
        probe=probe,
        status_code=401,
        body='{"error": "Unauthorized"}',
        headers={"Content-Type": "application/json"},
    )
    assert analyzer.is_false_positive(probe, response)
    assert analyzer.evaluate_probe(probe, response, "http://example.com/api/admin") is None


def test_false_positive_rejection_rate_limited_429():
    """Verifies that properly rate-limited 429 responses are suppressed."""
    analyzer = AuthBypassAnalyzer()
    probe = AuthBypassProbe(
        probe_id="p_throttled",
        target_url="http://example.com/login",
        method="POST",
        vulnerability_type=AuthVulnerabilityType.BRUTE_FORCE,
    )
    response = AuthBypassProbeResponse(
        probe=probe,
        status_code=429,
        body="Too Many Requests",
        headers={"Retry-After": "60"},
    )
    assert analyzer.is_false_positive(probe, response)
    assert analyzer.evaluate_probe(probe, response, "http://example.com/login") is None


def test_false_positive_rejection_explicit_failure_in_200_body():
    """Verifies that 200 OK responses with explicit failure messages (generic error page) are suppressed."""
    analyzer = AuthBypassAnalyzer()
    probe = AuthBypassProbe(
        probe_id="p_soft_fail",
        target_url="http://example.com/login",
        method="POST",
        vulnerability_type=AuthVulnerabilityType.DEFAULT_CREDENTIALS,
        metadata={"username": "admin", "password": "password"},
    )
    response = AuthBypassProbeResponse(
        probe=probe,
        status_code=200,
        body="<html><body><h1>Login Failed: Invalid username or password</h1></body></html>",
    )
    assert analyzer.is_false_positive(probe, response)
    assert analyzer.evaluate_probe(probe, response, "http://example.com/login") is None


# =============================================================================
# 6. AuthBypassCollector Lifecycle & Candidate Discovery Tests
# =============================================================================

def test_collector_candidate_endpoint_discovery_hierarchy():
    """Verifies candidate endpoint discovery across all 5 tiers of the discovery hierarchy."""
    collector = AuthBypassCollector()

    # Tier 1: mission.inputs
    mission_inputs = Mission(target="http://example.com")
    mission_inputs.inputs = {"endpoints": ["http://example.com/login", "http://example.com/api/auth"]}
    assert collector._discover_candidate_endpoints(mission_inputs) == [
        "http://example.com/login",
        "http://example.com/api/auth",
    ]

    # Tier 2: raw_mission.endpoints
    mission_eps = Mission(target="http://example.com")
    mission_eps.endpoints = [{"url": "http://example.com/admin/login"}, {"path": "http://example.com/oauth/token"}]
    assert collector._discover_candidate_endpoints(mission_eps) == [
        "http://example.com/admin/login",
        "http://example.com/oauth/token",
    ]

    # Tier 3: raw_mission.live_hosts
    mission_hosts = Mission(target="http://example.com")
    mission_hosts.live_hosts = [{"url": "http://sub.example.com"}, "http://api.example.com"]
    assert collector._discover_candidate_endpoints(mission_hosts) == [
        "http://sub.example.com",
        "http://api.example.com",
    ]

    # Tier 4: raw_mission.target
    mission_target = Mission(target="http://target.example.com")
    assert collector._discover_candidate_endpoints(mission_target) == [
        "http://target.example.com",
    ]

    # Tier 5: raw_mission.evidence
    mission_ev = Mission(target="")
    mission_ev.evidence = EvidenceStore()
    ev = Evidence(
        category="recon",
        value="found_url",
        source="crawler",
        metadata={"url": "http://discovered.example.com/portal"},
    )
    mission_ev.evidence.add(ev)
    assert collector._discover_candidate_endpoints(mission_ev) == [
        "http://discovered.example.com/portal",
    ]


def test_collector_quadruple_state_publishing():
    """Verifies Quadruple State Publishing: evidence, vulnerabilities, knowledge graph, and publish_finding."""
    mock_http = MockAuthHttpClient()
    # Route for valid default credentials
    mock_http.set_route(
        "user:admin:admin",
        200,
        '{"status": "authenticated", "role": "admin"}',
        headers={"Content-Type": "application/json"},
    )

    collector = AuthBypassCollector(http_client=mock_http)

    mission = Mission(target="http://portal.example.com/login")
    mission.attack_surface_graph = KnowledgeGraph()
    published_findings: List[Tuple[str, Evidence]] = []
    mission.publish_finding = lambda fid, fev: published_findings.append((fid, fev))

    evidence_items = collector.collect(mission)
    assert len(evidence_items) >= 1

    # 1. raw_mission.evidence
    all_ev = mission.evidence.all()
    assert any(e.category == "auth_bypass" for e in all_ev)

    # 2. raw_mission.vulnerabilities
    assert len(mission.vulnerabilities) >= 1
    assert any(
        "default_credentials" in v.get("technique", "") or "auth-default-credentials" in v.get("template_id", "")
        for v in mission.vulnerabilities
    )

    # 3. Knowledge Graph
    graph = mission.attack_surface_graph
    assert len(graph.nodes) >= 3
    lh_nodes = [n for n in graph.nodes.values() if n.type == "live_host"]
    ep_nodes = [n for n in graph.nodes.values() if n.type == "endpoint"]
    vuln_nodes = [n for n in graph.nodes.values() if n.type == "vulnerability"]
    assert len(lh_nodes) >= 1
    assert len(ep_nodes) >= 1
    assert len(vuln_nodes) >= 1

    # Check edges
    has_ep_edge = any(e.type == "HAS_ENDPOINT" for e in graph.edges)
    has_vuln_edge = any(e.type == "HAS_VULNERABILITY" for e in graph.edges)
    assert has_ep_edge
    assert has_vuln_edge

    # 4. publish_finding
    assert len(published_findings) >= 1
    assert published_findings[0][1].category == "auth_bypass"


def test_collector_execute_alias():
    """Verifies that execute(mission) delegates cleanly to collect(mission)."""
    mock_http = MockAuthHttpClient()
    collector = AuthBypassCollector(http_client=mock_http)
    mission = Mission(target="http://example.com/test")
    res = collector.execute(mission)
    assert isinstance(res, list)
