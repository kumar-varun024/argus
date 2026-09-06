"""OAuth/OIDC Token Testing & Stateful Authentication Validation Collector.

Split into a sub-package; all public names re-exported for import-path compatibility.
"""
from argus.collectors.oauth.models import (
    DEFAULT_LOGOUT_ROUTES,
    DEFAULT_OAUTH_PROBE_ROUTES,
    DEFAULT_PROTECTED_API_ROUTES,
    DEFAULT_TOKEN_PROBE_ROUTES,
    LOGIN_ROUTE_PATTERNS,
    LOGOUT_ROUTE_PATTERNS,
    OAUTH_AUTH_ROUTE_PATTERNS,
    OAUTH_TOKEN_ROUTE_PATTERNS,
    PROTECTED_API_PATTERNS,
    SESSION_COOKIE_NAMES_REGEX,
    b64url_decode,
    b64url_encode,
    create_hs256_jwt,
    create_mock_jwt,
)
from argus.collectors.oauth.payloads import (
    OAuthPayloadGenerator,
)
from argus.collectors.oauth.analyzer import (
    OAuthAnalyzer,
    SessionSecurityAnalyzer,
    TokenValidationAnalyzer,
)
from argus.collectors.oauth.collector import (
    OAuthCollector,
)
__all__ = [
    "DEFAULT_LOGOUT_ROUTES",
    "DEFAULT_OAUTH_PROBE_ROUTES",
    "DEFAULT_PROTECTED_API_ROUTES",
    "DEFAULT_TOKEN_PROBE_ROUTES",
    "LOGIN_ROUTE_PATTERNS",
    "LOGOUT_ROUTE_PATTERNS",
    "OAUTH_AUTH_ROUTE_PATTERNS",
    "OAUTH_TOKEN_ROUTE_PATTERNS",
    "OAuthAnalyzer",
    "OAuthCollector",
    "OAuthPayloadGenerator",
    "PROTECTED_API_PATTERNS",
    "SESSION_COOKIE_NAMES_REGEX",
    "SessionSecurityAnalyzer",
    "TokenValidationAnalyzer",
    "b64url_decode",
    "b64url_encode",
    "create_hs256_jwt",
    "create_mock_jwt",
]
