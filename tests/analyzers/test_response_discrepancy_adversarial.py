"""
Adversarial and Edge-Case Tests for ResponseDiscrepancyAnalyzer.
Empirically tests:
1. Malformed JSON payloads (truncated, non-dict, deeply nested, invalid syntax).
2. Huge response bodies (10MB) for performance, memory, and timeout bounds.
3. Unicode, RTL, multi-byte, null bytes, and regex special characters in identity attributes.
4. Unicode JSON escape sequences (\\uXXXX) in response bodies.
5. Degenerate, empty, and generic identity values ("admin", "user", "test", "").
6. Zero-length, blank, and 204 No Content responses.
7. Soft-403 error variations ("PermissionDenied", "AccessDenied", "You do not have access", etc.).
8. False positive suppression across horizontal, vertical, and header bypass vectors.
"""
import json
import time
import pytest

from argus.analyzers.response_discrepancy import ResponseDiscrepancyAnalyzer, DiscrepancyVerdict
from argus.http.client import HttpResponse
from argus.models.test_identity import TestIdentity, AuthType


@pytest.fixture
def analyzer():
    return ResponseDiscrepancyAnalyzer()


def test_malformed_json_resilience(analyzer):
    """
    Adversarial Challenge:
    Ensure analyzer never crashes or raises unhandled JSONDecodeError / AttributeError
    when receiving malformed, truncated, or non-dict JSON responses.
    """
    alice = TestIdentity(id="alice_123", name="Alice Smith", role="user")
    bob = TestIdentity(id="bob_456", name="Bob Jones", role="user")

    malformed_payloads = [
        "{\"user\": \"alice\", \"truncated\": ",
        "{id: 123, invalid_json: true}",
        "{\"key\": undefined}",
        "NaN",
        "{\"trailing_comma\": 123,}",
        "[\"array_item_1\", \"array_item_2\"]",
        "\"raw string literal without object\"",
        "987654321",
        "true",
        "null",
        "{" + "\"nest\": {" * 40 + "\"key\": \"val\"" + "}" * 40 + "}",
        "\x00\x01\x02\x03\x04\x05",
    ]

    for payload in malformed_payloads:
        resp = HttpResponse(success=True, status_code=200, raw_body=payload, body=payload)
        # 1. is_error_or_login_response should handle gracefully without exception
        is_err = analyzer.is_error_or_login_response(resp)
        assert isinstance(is_err, bool)

        # 2. extract_identity_leakage should handle gracefully
        leak = analyzer.extract_identity_leakage(alice, payload, bob)
        assert isinstance(leak, dict)
        assert "has_leakage" in leak

        # 3. analyze_horizontal should evaluate safely
        verdict_h = analyzer.analyze_horizontal(resp, resp, alice, bob)
        assert isinstance(verdict_h, DiscrepancyVerdict)

        # 4. analyze_vertical should evaluate safely
        verdict_v = analyzer.analyze_vertical(resp, resp, None, bob, "/admin/api")
        assert isinstance(verdict_v, DiscrepancyVerdict)


def test_huge_response_body_stress_and_performance(analyzer):
    """
    Adversarial Challenge:
    Ensure 10MB payloads do not trigger exponential difflib slowdowns, Regex DoS, or OOM crashes.
    Execution must complete within sub-second thresholds.
    """
    alice = TestIdentity(id="alice_target", name="Alice Target", role="user")
    bob = TestIdentity(id="bob_attacker", name="Bob Attacker", role="user")

    # 10 Megabyte payloads
    huge_payload_a = "DATA_PREFIX_" + ("A" * (10 * 1024 * 1024))
    huge_payload_b = "DATA_PREFIX_" + ("B" * (10 * 1024 * 1024))

    resp_a = HttpResponse(success=True, status_code=200, raw_body=huge_payload_a, body=huge_payload_a)
    resp_b = HttpResponse(success=True, status_code=200, raw_body=huge_payload_b, body=huge_payload_b)

    t0 = time.time()
    is_err = analyzer.is_error_or_login_response(resp_a)
    t1 = time.time()
    assert (t1 - t0) < 0.5, f"is_error_or_login_response took too long on 10MB payload: {t1 - t0:.4f}s"

    leak = analyzer.extract_identity_leakage(alice, huge_payload_a, bob)
    t2 = time.time()
    assert (t2 - t1) < 0.5, f"extract_identity_leakage took too long on 10MB payload: {t2 - t1:.4f}s"

    verdict_h = analyzer.analyze_horizontal(resp_a, resp_b, alice, bob)
    t3 = time.time()
    assert (t3 - t2) < 0.5, f"analyze_horizontal took too long on 10MB payload: {t3 - t2:.4f}s"
    assert verdict_h.is_vulnerable is False


def test_unicode_and_regex_special_characters_handling(analyzer):
    """
    Adversarial Challenge:
    Identities containing regex metacharacters, Cyrillic, Chinese, Arabic, emojis,
    and null bytes must not crash or bypass leakage extraction.
    """
    # 1. Regex metacharacters in identity credentials
    regex_ident = TestIdentity(
        id="user.*+?[]^$()|{}\\test",
        name="Alice [Corp] + (VIP) * ^ $ ?",
        credentials={"email": "alice+regex?*[]@target.corp", "token": "tok.*+?^${}()|[]\\"},
        metadata={"dept": "R&D [Sec] + (Prod)"},
    )
    bob = TestIdentity(id="bob_456", name="Bob", role="user")

    leaked_body = "Exposed user details: Alice [Corp] + (VIP) * ^ $ ? with email alice+regex?*[]@target.corp"
    leak = analyzer.extract_identity_leakage(regex_ident, leaked_body, bob)
    assert leak["has_leakage"] is True
    assert "name" in leak["leaked_fields"]
    assert "credential.email" in leak["leaked_fields"]

    # 2. Unicode and emoji identities in raw UTF-8
    unicode_ident = TestIdentity(
        id="пользователь_123",
        name="张伟 👑 (VIP)",
        credentials={"email": "zhang.wei@公司.cn", "bio": "مرحبا بالعالم \x00 nullbyte"},
        metadata={"role_desc": "高级管理员 🚀"},
    )
    unicode_body = json.dumps({
        "user": "张伟 👑 (VIP)",
        "email": "zhang.wei@公司.cn",
        "bio": "مرحبا بالعالم \x00 nullbyte",
    }, ensure_ascii=False)
    leak_u = analyzer.extract_identity_leakage(unicode_ident, unicode_body, bob)
    assert leak_u["has_leakage"] is True
    assert "name" in leak_u["leaked_fields"]
    assert "credential.email" in leak_u["leaked_fields"]


def test_empty_degenerate_and_generic_identity_filtering(analyzer):
    """
    Adversarial Challenge:
    Empty strings, single-character values, and generic terms like 'user', 'admin',
    'true', 'null', 'test' must never cause false positive IDOR flags on public content.
    """
    empty_ident = TestIdentity(id="", name="", credentials={}, metadata={})
    generic_ident = TestIdentity(
        id="user",
        name="admin",
        credentials={"key": "test", "token": "true", "mode": "null", "empty": ""},
        metadata={"role": None, "": ""},
    )
    short_ident = TestIdentity(id="1", name="a", credentials={"t": "x"})

    public_html = """
    <html>
        <body>
            <h1>Welcome to the System Portal</h1>
            <p>Role: admin, User: default, Status: true, Key: test, Null: none</p>
        </body>
    </html>
    """
    bob = TestIdentity(id="bob_normal", name="Bob", role="user")

    # None of these degenerate identities should claim data leakage on public page
    assert analyzer.extract_identity_leakage(empty_ident, public_html, bob)["has_leakage"] is False
    assert analyzer.extract_identity_leakage(generic_ident, public_html, bob)["has_leakage"] is False
    assert analyzer.extract_identity_leakage(short_ident, public_html, bob)["has_leakage"] is False


def test_zero_length_blank_and_empty_responses(analyzer):
    """
    Adversarial Challenge:
    Zero-length, blank, or near-empty responses must be treated as soft-errors/empty
    and must not produce false positive IDOR or vertical privilege escalation.
    """
    alice = TestIdentity(id="alice", role="user")
    bob = TestIdentity(id="bob", role="user")

    empty_bodies = ["", "   ", "\n\t", "{}", "[]", None]

    for empty_body in empty_bodies:
        resp = HttpResponse(success=True, status_code=200, raw_body=empty_body, body=empty_body)
        assert analyzer.is_error_or_login_response(resp) is True

        # Horizontal comparison against empty response
        resp_auth = HttpResponse(success=True, status_code=200, raw_body='{"id": "alice", "data": "secret"}')
        verdict = analyzer.analyze_horizontal(resp_auth, resp, alice, bob)
        assert verdict.is_vulnerable is False

        # Vertical comparison against empty response
        verdict_v = analyzer.analyze_vertical(None, resp, None, bob, "/admin/api")
        assert verdict_v.is_vulnerable is False


def test_soft_403_standard_phrases_detection(analyzer):
    """
    Adversarial Challenge:
    Test standard and non-standard soft-403 error variations:
    1. Standard space-separated phrases ("Access Denied", "Forbidden", "You do not have permission").
    2. Explicit failure JSON ({"success": false}, {"status": "error"}).
    3. Soft-403 HTML and JSON error envelopes.
    """
    soft_403_samples = [
        # JSON standard errors
        '{"status": "error", "message": "Access denied"}',
        '{"success": false, "error": "Unauthorized request"}',
        '{"status": "forbidden", "detail": "User is unauthenticated"}',
        '{"status": "failed", "reason": "Session expired"}',
        '{"errors": [{"message": "Access Denied"}]}',
        # Text/HTML standard errors
        '<html><body><h1>403 Forbidden</h1><p>Access Denied</p></body></html>',
        '<html><body><div>Authentication Required. Please log in to continue.</div></body></html>',
        'Invalid session or credentials. Please sign in to continue.',
        'You do not have permission to access this resource.',
    ]

    for sample in soft_403_samples:
        resp = HttpResponse(success=True, status_code=200, raw_body=sample, body=sample)
        assert analyzer.is_error_or_login_response(resp) is True, f"Failed to detect soft error: {sample}"


def test_soft_403_edge_case_variations(analyzer):
    """
    Adversarial Challenge:
    Test soft-403 variations with alternative naming conventions:
    - camelCase 'PermissionDenied' and 'AccessDenied'
    - 'You do not have access' / 'Access is restricted'
    """
    # JSON with status=error and PermissionDenied
    resp_json_err = HttpResponse(
        success=True,
        status_code=200,
        raw_body='{"status": "error", "message": "PermissionDenied"}',
        body='{"status": "error", "message": "PermissionDenied"}',
    )
    assert analyzer.is_error_or_login_response(resp_json_err) is True

    # JSON with success=false and custom access denied message
    resp_success_false = HttpResponse(
        success=True,
        status_code=200,
        raw_body='{"success": false, "error": "You do not have access to this resource"}',
        body='{"success": false, "error": "You do not have access to this resource"}',
    )
    assert analyzer.is_error_or_login_response(resp_success_false) is True

    # Plain text / unwrapped JSON variations
    plain_samples = [
        "PermissionDenied: Invalid role",
        "AccessDenied: Restricted area",
        "access_denied: token revoked",
        "permission_denied: missing scope",
        '{"detail": "You do not have access"}',
        '{"detail": "You don\'t have permission"}',
        '{"detail": "insufficient_privileges"}',
        '{"detail": "access restricted"}',
    ]
    for sample in plain_samples:
        resp = HttpResponse(success=True, status_code=200, raw_body=sample, body=sample)
        assert analyzer.is_error_or_login_response(resp) is True, f"Failed on sample: {sample}"


def test_unicode_escaped_json_identity_leakage(analyzer):
    """
    Verifies that extract_identity_leakage correctly unescapes \\uXXXX in JSON bodies
    to match international character identities (e.g. René Müller).
    """
    alice = TestIdentity(
        id="user_rene",
        name="René Müller",
        credentials={"email": "rene.müller@corp.de", "city": "München"},
    )
    bob = TestIdentity(id="user_bob", role="user")

    # JSON with standard ASCII Unicode escapes (\u00e9, \u00fc)
    escaped_json_body = json.dumps({
        "name": "René Müller",
        "email": "rene.müller@corp.de",
        "city": "München",
    }, ensure_ascii=True)

    assert r"\u00e9" in escaped_json_body or r"\u00fc" in escaped_json_body

    leak = analyzer.extract_identity_leakage(alice, escaped_json_body, bob)
    assert leak["has_leakage"] is True
    assert "name" in leak["leaked_fields"]
    assert "credential.email" in leak["leaked_fields"]
    assert "credential.city" in leak["leaked_fields"]

