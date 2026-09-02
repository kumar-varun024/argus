"""
Adversarial and Edge Case test suite for Authentication Bypass & Credential Attack Detection Module.
Tests Unicode homoglyphs, fullwidth ASCII, zero-width characters, token permutations, key confusion,
timing jitter, high concurrency bursts, malformed inputs, and network fault tolerance.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import json
import time
import unicodedata
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
from argus.evidence.model import Evidence
from argus.graph.graph import KnowledgeGraph
from argus.http.client import HttpResponse
from argus.runtime.mission import Mission


# =============================================================================
# Mock HTTP Client for Adversarial Scenarios
# =============================================================================

class MockAdversarialHttpClient:
    """Configurable HTTP client supporting latency jitter, exceptions, and malformed responses."""

    def __init__(self):
        self.handlers: List[Tuple[Any, Any]] = []
        self.call_count: int = 0
        self.requested_probes: List[Dict[str, Any]] = []

    def add_handler(self, matcher: Any, response_factory: Any) -> None:
        self.handlers.append((matcher, response_factory))

    def request(self, *args: Any, **kwargs: Any) -> HttpResponse:
        self.call_count += 1
        method = (args[1] if len(args) > 1 and not isinstance(args[0], str) else args[0] if args else "GET").upper()
        url = args[2] if len(args) > 2 else (args[1] if len(args) > 1 and isinstance(args[0], str) else kwargs.get("url", ""))

        headers = kwargs.get("headers") or {}
        json_data = kwargs.get("json")
        data = kwargs.get("data")

        self.requested_probes.append({
            "method": method,
            "url": url,
            "headers": headers,
            "json": json_data,
            "data": data,
        })

        for matcher, factory in self.handlers:
            if callable(matcher):
                if matcher(method, str(url), headers, json_data, data):
                    return factory(method, str(url), headers, json_data, data)
            elif isinstance(matcher, str):
                if matcher in str(url) or matcher in json.dumps(json_data or {}) or matcher in str(headers):
                    return factory(method, str(url), headers, json_data, data)

        # Default clean 401 response
        return HttpResponse(
            success=False,
            status_code=401,
            raw_body='{"error": "Unauthorized"}',
            body='{"error": "Unauthorized"}',
            headers={"Content-Type": "application/json"},
            url=str(url),
            elapsed=0.02,
        )

    def get(self, *args: Any, **kwargs: Any) -> HttpResponse:
        return self.request("GET", *args, **kwargs)

    def post(self, *args: Any, **kwargs: Any) -> HttpResponse:
        return self.request("POST", *args, **kwargs)


# =============================================================================
# 1. Unicode Homoglyphs & Normalization Attacks
# =============================================================================

def test_adversarial_cyrillic_homoglyphs_in_usernames():
    """Validates probe generation and evaluation with Cyrillic homoglyph characters."""
    gen = AuthBypassPayloadGenerator()
    analyzer = AuthBypassAnalyzer()

    # Latin "admin" vs Cyrillic "аdmin" (Cyrillic Small Letter A: U+0430)
    # Cyrillic "о" (U+043E), Cyrillic "е" (U+0435), Cyrillic "с" (U+0441), Cyrillic "р" (U+0440)
    latin_user = "administrator"
    probe = AuthBypassProbe(
        probe_id="homoglyph_p1",
        target_url="http://example.com/api/login",
        method="POST",
        vulnerability_type=AuthVulnerabilityType.BRUTE_FORCE,
        json_data={"username": latin_user, "password": "TargetPassword123!"},
    )

    mutated = gen.apply_unicode_normalization_mutation(probe)
    mutated_user = mutated.json_data["username"]

    # Ensure character substitution took place
    assert mutated_user != latin_user
    assert "\u0430" in mutated_user or "\u043e" in mutated_user

    # Normalize NFKD/NFC to verify compatibility
    nfkc_user = unicodedata.normalize("NFKC", mutated_user)
    assert len(nfkc_user) == len(latin_user)


def test_adversarial_fullwidth_ascii_and_nfkd_bypass():
    """Validates handling of Fullwidth ASCII characters (e.g. ａｄｍｉｎ)."""
    # Fullwidth "admin": ａ(U+FF41) ｄ(U+FF44) ｍ(U+FF4D) ｉ(U+FF49) ｎ(U+FF4E)
    fullwidth_admin = "\uff41\uff44\uff4d\uff49\uff4e"
    normalized = unicodedata.normalize("NFKC", fullwidth_admin)
    assert normalized == "admin"

    analyzer = AuthBypassAnalyzer()
    probe = AuthBypassProbe(
        probe_id="fw_probe",
        target_url="http://example.com/login",
        method="POST",
        vulnerability_type=AuthVulnerabilityType.DEFAULT_CREDENTIALS,
        metadata={"technique": "default_credentials", "username": fullwidth_admin, "password": "password"},
    )
    resp = AuthBypassProbeResponse(
        probe=probe,
        status_code=200,
        body='{"authenticated": true, "user": "admin"}',
        headers={"Content-Type": "application/json"},
    )

    result = analyzer.evaluate_probe(probe, resp, "http://example.com/login")
    assert result is not None
    assert result.severity == AuthBypassSeverity.CRITICAL.value


def test_adversarial_zero_width_space_injection():
    """Validates injection of Zero-Width Spaces (U+200B, U+200C, U+200D, U+FEFF) into usernames and headers."""
    zw_space = "\u200b"
    zw_non_joiner = "\u200c"
    bom = "\ufeff"

    tainted_user = f"adm{zw_space}in{zw_non_joiner}istrator{bom}"
    clean_user = tainted_user.replace("\u200b", "").replace("\u200c", "").replace("\ufeff", "")
    assert clean_user == "administrator"

    gen = AuthBypassPayloadGenerator()
    probe = AuthBypassProbe(
        probe_id="zw_probe",
        target_url="http://example.com/login",
        method="POST",
        json_data={"username": tainted_user, "password": "password"},
    )
    assert tainted_user in probe.json_data["username"]


# =============================================================================
# 2. JWT Key Confusion & Algorithm Permutations
# =============================================================================

def test_adversarial_jwt_none_algorithm_casing_matrix():
    """Validates all casing permutations of alg: none (none, None, NONE, nOnE)."""
    gen = AuthBypassPayloadGenerator()
    probes = gen.generate_jwt_manipulation_probes("http://example.com/api/admin")

    alg_none_probes = [p for p in probes if "jwt_alg_none" in p.metadata.get("technique", "")]
    assert len(alg_none_probes) >= 4

    algs_tested = [p.metadata.get("alg") for p in alg_none_probes]
    assert "none" in algs_tested
    assert "None" in algs_tested
    assert "NONE" in algs_tested
    assert "nOnE" in algs_tested

    # Verify each probe has a validly formed token without trailing signature
    for p in alg_none_probes:
        auth_hdr = p.headers.get("Authorization", "")
        assert auth_hdr.startswith("Bearer ")
        tok = auth_hdr[7:]
        parts = tok.split(".")
        assert len(parts) in (2, 3)
        # Header should decode to alg
        hdr_json = json.loads(base64.urlsafe_b64decode(parts[0] + "==").decode("utf-8"))
        assert hdr_json["alg"] in ("none", "None", "NONE", "nOnE")


def test_adversarial_jwt_key_confusion_public_key_as_hmac_secret():
    """Validates JWT RS256 -> HS256 key confusion attack using RSA public key as HMAC secret."""
    # Simulated RSA Public Key in PEM format (PKCS#1 and PKCS#8)
    sample_pkcs8_pubkey = (
        "-----BEGIN PUBLIC KEY-----\n"
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzV1d6gH1K\n"
        "-----END PUBLIC KEY-----\n"
    )

    def b64url(b: bytes) -> str:
        return base64.urlsafe_b64encode(b).decode("utf-8").rstrip("=")

    header = json.dumps({"alg": "HS256", "typ": "JWT"}).encode("utf-8")
    payload = json.dumps({"sub": "admin", "role": "admin", "iat": int(time.time())}).encode("utf-8")

    unsigned_token = f"{b64url(header)}.{b64url(payload)}"

    # Sign using HMAC-SHA256 with the public key PEM string as the secret
    signature = hmac.new(sample_pkcs8_pubkey.encode("utf-8"), unsigned_token.encode("utf-8"), hashlib.sha256).digest()
    forged_token = f"{unsigned_token}.{b64url(signature)}"

    analyzer = AuthBypassAnalyzer()
    probe = AuthBypassProbe(
        probe_id="jwt_key_confusion",
        target_url="http://example.com/api/admin",
        method="GET",
        vulnerability_type=AuthVulnerabilityType.JWT_MANIPULATION,
        headers={"Authorization": f"Bearer {forged_token}"},
        metadata={"technique": "jwt_key_confusion_rs256_hs256"},
    )

    resp = AuthBypassProbeResponse(
        probe=probe,
        status_code=200,
        body='{"admin": true, "access": "granted"}',
        headers={"Content-Type": "application/json"},
    )

    result = analyzer.evaluate_probe(probe, resp, "http://example.com/api/admin")
    assert result is not None
    assert result.severity == AuthBypassSeverity.CRITICAL.value
    assert result.cwe_id == "CWE-345"


def test_adversarial_jwt_empty_hmac_key_and_whitespace_padding():
    """Validates JWT manipulation with empty HMAC secret and whitespace padding variations."""
    def b64url(b: bytes) -> str:
        return base64.urlsafe_b64encode(b).decode("utf-8").rstrip("=")

    header = json.dumps({"alg": "HS256", "typ": "JWT"}).encode("utf-8")
    payload = json.dumps({"sub": "admin", "role": "admin"}).encode("utf-8")
    unsigned = f"{b64url(header)}.{b64url(payload)}"

    # Signature with empty key b""
    empty_sig = hmac.new(b"", unsigned.encode("utf-8"), hashlib.sha256).digest()
    token = f"{unsigned}.{b64url(empty_sig)}"

    gen = AuthBypassPayloadGenerator()
    probe = AuthBypassProbe(
        probe_id="empty_key_p",
        target_url="http://example.com/api",
        method="GET",
        headers={"Authorization": f"Bearer {token}"},
    )

    # Apply token format mutation (multi-space, lowercase bearer)
    mutated = gen.apply_token_format_mutation(probe)
    assert mutated.headers["Authorization"].startswith("bearer  ")


# =============================================================================
# 3. Timing Jitter & Latency Differential Stress Tests
# =============================================================================

def test_adversarial_timing_jitter_in_brute_force_probing():
    """Validates timing analysis resilience when individual request latencies fluctuate under network jitter."""
    analyzer = AuthBypassAnalyzer()
    probe = AuthBypassProbe(
        probe_id="jitter_probe",
        target_url="http://example.com/login",
        method="POST",
        vulnerability_type=AuthVulnerabilityType.BRUTE_FORCE,
        tested_parameter="username",
        metadata={"technique": "username_enumeration_timing"},
    )

    # Responses with simulated network jitter: 1.1s, 0.9s, 1.4s, 1.2s, 1.0s
    burst_resps = [
        {"iteration": 1, "status_code": 401, "elapsed": 1.15, "headers": {}, "body": "Auth failed"},
        {"iteration": 2, "status_code": 401, "elapsed": 0.95, "headers": {}, "body": "Auth failed"},
        {"iteration": 3, "status_code": 401, "elapsed": 1.35, "headers": {}, "body": "Auth failed"},
        {"iteration": 4, "status_code": 401, "elapsed": 1.20, "headers": {}, "body": "Auth failed"},
        {"iteration": 5, "status_code": 401, "elapsed": 1.05, "headers": {}, "body": "Auth failed"},
    ]

    resp = AuthBypassProbeResponse(
        probe=probe,
        status_code=401,
        body="Auth failed",
        burst_responses=burst_resps,
    )

    result = analyzer.evaluate_probe(probe, resp, "http://example.com/login")
    assert result is not None
    assert result.template_id == "auth-username-enumeration-timing"
    assert "Average response latency" in result.evidence_snippet


# =============================================================================
# 4. High Burst Concurrency & IP Subnet Rotation
# =============================================================================

def test_adversarial_high_burst_execution_and_ip_rotation():
    """Validates rapid burst execution and automated IP rotation across 50 consecutive requests."""
    mock_http = MockAdversarialHttpClient()

    # Echo back client IP from X-Forwarded-For
    def handler(method: str, url: str, headers: Dict[str, str], json_data: Any, data: Any) -> HttpResponse:
        client_ip = headers.get("X-Forwarded-For", "127.0.0.1")
        return HttpResponse(
            success=False,
            status_code=401,
            raw_body=f'{{"status":"unauthorized", "ip":"{client_ip}"}}',
            body=f'{{"status":"unauthorized", "ip":"{client_ip}"}}',
            headers={"Content-Type": "application/json"},
            url=url,
            elapsed=0.01,
        )

    mock_http.add_handler(lambda m, u, h, j, d: True, handler)

    prober = AuthBypassProber(http_client=mock_http)
    probe = AuthBypassProbe(
        probe_id="burst_stress",
        target_url="http://example.com/api/login",
        method="POST",
        vulnerability_type=AuthVulnerabilityType.CREDENTIAL_STUFFING,
        json_data={"username": "victim@example.com", "password": "password"},
    )

    burst_results = prober.execute_burst_sequence(None, "http://example.com/api/login", probe, count=25)
    assert len(burst_results) == 25

    # Verify IP rotation across distinct subnets from echoed response body
    ips = [r["json_body"]["ip"] for r in burst_results if r["json_body"]]
    assert len(set(ips)) == 25
    assert "10.0.0.1" in ips
    assert "10.0.0.25" in ips

    # Also verify request headers in HTTP client history
    req_ips = [req["headers"].get("X-Forwarded-For") for req in mock_http.requested_probes]
    assert len(set(req_ips)) == 25


# =============================================================================
# 5. Malformed Inputs, JSON Errors, & Crash Resilience
# =============================================================================

def test_adversarial_malformed_json_and_circular_structures():
    """Validates that malformed JSON responses, HTML error pages, and nested types do not crash analyzer."""
    analyzer = AuthBypassAnalyzer()
    probe = AuthBypassProbe(
        probe_id="malformed_json_probe",
        target_url="http://example.com/api/auth",
        method="POST",
        vulnerability_type=AuthVulnerabilityType.MFA_BYPASS,
    )

    malformed_bodies = [
        "",  # Empty body
        "{ malformed json string without closing",
        '{"nested": {"deep": {"array": [1, 2, 3, null, true]}}}',
        "<html><head><title>500 Internal Server Error</title></head><body>Crash</body></html>",
        "\x00\x01\x02\x03\xff\xfe binary payload dump",
        '{"error": ' + ("A" * 10000) + '}',  # Oversized response body
    ]

    for body in malformed_bodies:
        resp = AuthBypassProbeResponse(
            probe=probe,
            status_code=500,
            body=body,
            headers={"Content-Type": "text/html"},
        )
        # Should execute safely without raising unhandled exceptions
        res = analyzer.evaluate_probe(probe, resp, "http://example.com/api/auth")
        assert res is None or isinstance(res, AuthBypassResult)


def test_adversarial_network_exceptions_and_gateway_failures():
    """Validates prober resilience under network connection timeouts, 502/503/504 gateways, and DNS errors."""
    mock_http = MockAdversarialHttpClient()

    def gateway_timeout(m: str, u: str, h: Dict[str, str], j: Any, d: Any) -> HttpResponse:
        return HttpResponse(
            success=False,
            status_code=504,
            raw_body="<html><body>504 Gateway Time-out</body></html>",
            body="<html><body>504 Gateway Time-out</body></html>",
            headers={"Content-Type": "text/html"},
            url=u,
            elapsed=10.0,
            error="Gateway Timeout",
        )

    mock_http.add_handler("http://timeout.example.com", gateway_timeout)

    prober = AuthBypassProber(http_client=mock_http)
    probe = AuthBypassProbe(
        probe_id="timeout_p",
        target_url="http://timeout.example.com/login",
        method="POST",
        vulnerability_type=AuthVulnerabilityType.BRUTE_FORCE,
    )

    resp = prober.execute_probe(None, "http://timeout.example.com/login", probe)
    assert resp.status_code == 504
    assert resp.error == "Gateway Timeout"

    # Analyzer should cleanly suppress connection/gateway timeouts as false positives
    analyzer = AuthBypassAnalyzer()
    finding = analyzer.evaluate_probe(probe, resp, "http://timeout.example.com/login")
    assert finding is None


def test_adversarial_differential_identity_probe_execution():
    """Validates execution of differential identity probes to verify authorization boundaries."""
    mock_http = MockAdversarialHttpClient()

    class TestIdentity:
        def __init__(self, token: str):
            self.token = token

        def get_auth_headers(self) -> Dict[str, str]:
            return {"Authorization": f"Bearer {self.token}"}

    prober = AuthBypassProber(http_client=mock_http)
    probe = AuthBypassProbe(
        probe_id="diff_id_p",
        target_url="http://example.com/admin/settings",
        method="GET",
    )

    id_admin = TestIdentity("admin_token_jwt_999")
    id_victim = TestIdentity("user_token_jwt_111")

    resp = prober.execute_differential_identity_probe(
        mission=None,
        target_url="http://example.com/admin/settings",
        probe=probe,
        primary_identity=id_admin,
        secondary_identity=id_victim,
    )
    assert resp is not None
    # Check that auth header was applied to requested history
    assert len(mock_http.requested_probes) >= 1
    last_req = mock_http.requested_probes[-1]
    assert last_req["headers"]["Authorization"] == "Bearer admin_token_jwt_999"
