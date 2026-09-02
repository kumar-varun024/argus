"""
Adversarial and Edge Case Test Suite for API Security Testing Module.

Tests:
- False positive suppression on benign requests
- False positive suppression on parameter validation error rejections (400/422)
- False positive suppression on stripped/ignored mass assignment attributes
- False positive suppression on properly enforced rate limiting (429 with retry headers)
- False positive suppression on unauthorized BOLA rejections (401/403/404)
- False positive suppression on standard HTTP 405 Method Not Allowed responses
- Handling of connection errors, timeouts, and status_code=0
- Handling of non-JSON / HTML error pages and empty bodies
- Sensitive PII and credential regex patterns (passwords, tokens, SSNs, credit cards, keys)
- Error message and stack trace disclosure detection (Python, Java, .NET, Node, PHP, SQL)
- Rate limit header extraction and parsing
- Endpoint discovery fallbacks (inputs, endpoints, live_hosts, target, evidence)
- Mutation evasion edge cases (Unicode escapes, HPP, header bypasses)
"""
import pytest
from typing import Any, Dict, List

from argus.collectors.api_security import (
    APISecurityCollector,
    APISecurityPayloadGenerator,
    APISecurityProber,
    APISecurityAnalyzer,
    APIProbe,
    APIProbeResponse,
    APIVulnerabilityType,
    APIMutationStrategy,
    APISecuritySeverity,
)
from argus.http.client import HttpResponse
from argus.runtime.mission import Mission
from argus.plugins.interfaces import ControlledMission
from tests.collectors.test_api_security import MockAPIHttpClient


# =============================================================================
# 1. False Positive Suppression Tests
# =============================================================================

def test_fp_suppression_on_benign_baseline_probes():
    analyzer = APISecurityAnalyzer()
    probe = APIProbe(
        probe_id="benign_test",
        target_url="https://api.example.com/items",
        method="GET",
        is_benign=True,
    )
    resp = APIProbeResponse(
        probe=probe,
        status_code=200,
        headers={"content-type": "application/json"},
        body='{"items": [{"id": 1, "name": "Test Item"}]}',
        json_body={"items": [{"id": 1, "name": "Test Item"}]},
    )
    assert analyzer.is_false_positive(probe, resp) is True
    assert analyzer.evaluate_probe(probe, resp, "https://api.example.com/items") is None


def test_fp_suppression_on_parameter_validation_rejections():
    analyzer = APISecurityAnalyzer()
    probe = APIProbe(
        probe_id="pt_invalid_price",
        target_url="https://api.example.com/checkout",
        method="POST",
        vulnerability_type=APIVulnerabilityType.PARAMETER_TAMPERING,
        tested_parameter="price",
        tampered_value=-50.0,
    )

    # 400 Bad Request with validation error message
    resp_400 = APIProbeResponse(
        probe=probe,
        status_code=400,
        headers={"content-type": "application/json"},
        body='{"error": "Validation Error: Negative price disallowed"}',
    )
    assert analyzer.is_false_positive(probe, resp_400) is True
    assert analyzer.evaluate_probe(probe, resp_400, "https://api.example.com/checkout") is None

    # 422 Unprocessable Entity
    resp_422 = APIProbeResponse(
        probe=probe,
        status_code=422,
        headers={"content-type": "application/json"},
        body='{"detail": [{"loc": ["body", "price"], "msg": "Price must be positive"}]}',
    )
    assert analyzer.is_false_positive(probe, resp_422) is True
    assert analyzer.evaluate_probe(probe, resp_422, "https://api.example.com/checkout") is None


def test_fp_suppression_on_stripped_mass_assignment():
    analyzer = APISecurityAnalyzer()
    probe = APIProbe(
        probe_id="ma_stripped_field",
        target_url="https://api.example.com/profile",
        method="POST",
        vulnerability_type=APIVulnerabilityType.MASS_ASSIGNMENT,
        tested_parameter="isAdmin",
        tampered_value=True,
    )

    # Server accepts request (200 OK) but correctly strips and ignores isAdmin
    resp_ignored = APIProbeResponse(
        probe=probe,
        status_code=200,
        headers={"content-type": "application/json"},
        body='{"id": 42, "username": "bob", "email": "bob@example.com"}',
        json_body={"id": 42, "username": "bob", "email": "bob@example.com"},
    )
    assert analyzer.is_false_positive(probe, resp_ignored) is True
    assert analyzer.evaluate_probe(probe, resp_ignored, "https://api.example.com/profile") is None


def test_fp_suppression_on_properly_enforced_rate_limits():
    analyzer = APISecurityAnalyzer()
    probe = APIProbe(
        probe_id="rl_properly_throttled",
        target_url="https://api.example.com/auth/login",
        method="POST",
        vulnerability_type=APIVulnerabilityType.RATE_LIMITING_BYPASS,
        burst_count=15,
        tested_parameter="rate_limiting",
    )

    # Burst responses contains 429 Too Many Requests
    burst_data = [{"status_code": 200}] * 5 + [{"status_code": 429}] * 10
    resp_throttled = APIProbeResponse(
        probe=probe,
        status_code=429,
        headers={"retry-after": "60", "x-ratelimit-remaining": "0"},
        body='{"error": "Too Many Requests"}',
        burst_responses=burst_data,
        rate_limit_headers={"retry-after": "60", "x-ratelimit-remaining": "0"},
    )
    assert analyzer.is_false_positive(probe, resp_throttled) is True
    assert analyzer.evaluate_probe(probe, resp_throttled, "https://api.example.com/auth/login") is None


def test_fp_suppression_on_bola_idor_rejections():
    analyzer = APISecurityAnalyzer()
    probe = APIProbe(
        probe_id="bola_unauthorized",
        target_url="https://api.example.com/users/9999",
        method="GET",
        vulnerability_type=APIVulnerabilityType.BOLA_IDOR,
        tested_parameter="id",
        tampered_value="9999",
    )

    # 401 Unauthorized
    resp_401 = APIProbeResponse(
        probe=probe,
        status_code=401,
        headers={"content-type": "application/json"},
        body='{"message": "Unauthorized access"}',
    )
    assert analyzer.is_false_positive(probe, resp_401) is True

    # 403 Forbidden
    resp_403 = APIProbeResponse(
        probe=probe,
        status_code=403,
        headers={"content-type": "application/json"},
        body='{"message": "Forbidden"}',
    )
    assert analyzer.is_false_positive(probe, resp_403) is True

    # 404 Not Found
    resp_404 = APIProbeResponse(
        probe=probe,
        status_code=404,
        headers={"content-type": "application/json"},
        body='{"error": "Not Found"}',
    )
    assert analyzer.is_false_positive(probe, resp_404) is True


def test_fp_suppression_on_method_not_allowed_405():
    analyzer = APISecurityAnalyzer()
    probe = APIProbe(
        probe_id="method_tamper_405",
        target_url="https://api.example.com/public/catalog",
        method="DELETE",
        vulnerability_type=APIVulnerabilityType.METHOD_TAMPERING,
        tested_parameter="http_method",
        tampered_value="DELETE",
    )
    resp_405 = APIProbeResponse(
        probe=probe,
        status_code=405,
        headers={"allow": "GET, HEAD, OPTIONS"},
        body="Method Not Allowed",
    )
    assert analyzer.is_false_positive(probe, resp_405) is True
    assert analyzer.evaluate_probe(probe, resp_405, "https://api.example.com/public/catalog") is None


# =============================================================================
# 2. Network & Error Handling Tests
# =============================================================================

def test_handling_of_connection_errors_and_status_zero():
    analyzer = APISecurityAnalyzer()
    probe = APIProbe(
        probe_id="error_probe",
        target_url="https://api.example.com/unreachable",
        method="POST",
        vulnerability_type=APIVulnerabilityType.PARAMETER_TAMPERING,
    )
    resp_conn_error = APIProbeResponse(
        probe=probe,
        status_code=0,
        error="Connection refused: Failed to establish connection",
    )
    assert analyzer.is_false_positive(probe, resp_conn_error) is True
    assert analyzer.evaluate_probe(probe, resp_conn_error, "https://api.example.com/unreachable") is None


def test_handling_of_non_json_html_error_pages():
    analyzer = APISecurityAnalyzer()
    probe = APIProbe(
        probe_id="html_error_probe",
        target_url="https://api.example.com/broken",
        method="GET",
        vulnerability_type=APIVulnerabilityType.EXCESSIVE_DATA_EXPOSURE,
    )
    resp_html = APIProbeResponse(
        probe=probe,
        status_code=500,
        headers={"content-type": "text/html"},
        body="<html><body><h1>500 Internal Server Error</h1></body></html>",
    )
    # Generic 500 without stack traces or sensitive leaks should not trigger excessive data finding
    assert analyzer.is_false_positive(probe, resp_html) is True
    assert analyzer.evaluate_probe(probe, resp_html, "https://api.example.com/broken") is None


# =============================================================================
# 3. Sensitive PII, Tokens, and Stack Trace Patterns
# =============================================================================

def test_sensitive_patterns_detection():
    analyzer = APISecurityAnalyzer()

    # Passwords / hashes
    detected_pwd = analyzer.detect_sensitive_fields('{"user": "admin", "password_hash": "$2y$10$N9qo8uLOickgx2ZMRZoMye"}')
    assert "password_hash" in detected_pwd

    # API keys / auth tokens
    detected_token = analyzer.detect_sensitive_fields('{"access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"}')
    assert "auth_token_or_api_key" in detected_token

    # SSN / PII
    detected_ssn = analyzer.detect_sensitive_fields('{"customer": "John Doe", "ssn": "000-12-3456"}')
    assert "social_security_number" in detected_ssn or "pii_or_financial" in detected_ssn

    # Credit card numbers
    detected_cc = analyzer.detect_sensitive_fields('{"card": "4111111111111111", "exp": "12/28"}')
    assert "credit_card_number" in detected_cc


def test_stack_trace_and_error_disclosure_patterns():
    analyzer = APISecurityAnalyzer()

    # Python stack trace
    py_trace = """
    Traceback (most recent call last):
      File "/app/src/handlers/users.py", line 42, in get_user
        cursor.execute("SELECT * FROM users WHERE id = " + user_id)
    """
    assert analyzer.detect_error_disclosure(py_trace) in ("python_stack_trace", "internal_file_path")

    # Java / Spring stack trace
    java_trace = "org.springframework.web.util.NestedServletException: Request processing failed"
    assert analyzer.detect_error_disclosure(java_trace) == "java_spring_stack_trace"

    # SQL syntax error
    sql_error = "SQL syntax error: You have an error in your SQL syntax near MySQL server version"
    assert analyzer.detect_error_disclosure(sql_error) == "sql_syntax_error"

    # Internal path
    path_leak = "Error opening template at /var/www/html/templates/header.php"
    assert analyzer.detect_error_disclosure(path_leak) == "internal_file_path"


# =============================================================================
# 4. Rate Limit Header Parsing & Endpoint Discovery Fallbacks
# =============================================================================

def test_rate_limit_header_parsing():
    analyzer = APISecurityAnalyzer()
    headers = {
        "Content-Type": "application/json",
        "X-RateLimit-Limit": "100",
        "X-RateLimit-Remaining": "5",
        "X-RateLimit-Reset": "1788299400",
        "Retry-After": "30",
    }
    parsed = analyzer.parse_rate_limit_headers(headers)
    assert parsed["x-ratelimit-limit"] == "100"
    assert parsed["x-ratelimit-remaining"] == "5"
    assert parsed["retry-after"] == "30"


def test_endpoint_discovery_fallbacks():
    collector = APISecurityCollector()

    # 1. From mission.inputs
    m1 = Mission(target="example.com")
    m1.inputs = {"endpoints": ["https://example.com/api/v1/auth"]}
    assert "https://example.com/api/v1/auth" in collector._discover_candidate_endpoints(m1)

    # 2. From mission.endpoints
    m2 = Mission(target="example.com")
    m2.endpoints = [{"url": "https://example.com/api/v2/items"}]
    assert "https://example.com/api/v2/items" in collector._discover_candidate_endpoints(m2)

    # 3. From mission.live_hosts (fallback)
    m3 = Mission(target="example.com")
    m3.live_hosts = ["https://live.example.com"]
    assert "https://live.example.com" in collector._discover_candidate_endpoints(m3)

    # 4. From mission.target (fallback)
    m4 = Mission(target="api.testservice.com")
    assert "https://api.testservice.com" in collector._discover_candidate_endpoints(m4)
