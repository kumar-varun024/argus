"""oauth: Data models, enums, and constants."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from typing import Any, Dict, Union


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
