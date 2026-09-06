"""oauth: Response analysis."""
from __future__ import annotations

import re
import urllib.parse
from typing import Any, Dict, List, Optional

from argus.http.client import HttpResponse
from argus.collectors.oauth.models import SESSION_COOKIE_NAMES_REGEX


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
        if status is not None and 300 <= status < 400 and location:
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
        if status is not None and 300 <= status < 400 and ("code=" in location or "access_token=" in location or "id_token=" in location):
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
        if status is not None and 200 <= status < 300:
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

        if status is not None and 200 <= status < 300:
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

        if status is not None and 200 <= status < 300:
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

        if status is not None and 200 <= status < 300:
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

        if status is not None and 200 <= status < 300:
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
        if status is not None and 200 <= status < 300:
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
