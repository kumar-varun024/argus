"""auth_bypass: Data models, enums, and constants."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Union

from argus.collectors.toolkit.enums import Severity
from argus.http.client import HttpResponse


AuthBypassSeverity = Severity

AuthSeverity = AuthBypassSeverity

Severity = AuthBypassSeverity

AuthBypassSeverity.CRIT = AuthBypassSeverity.CRITICAL  # type: ignore[attr-defined]

class AuthVulnerabilityType(str, Enum):
    """Enumeration of Authentication vulnerability detection modes."""
    BRUTE_FORCE = "brute_force"
    PASSWORD_RESET = "password_reset"
    MFA_BYPASS = "mfa_bypass"
    SESSION_FIXATION = "session_fixation"
    JWT_MANIPULATION = "jwt_manipulation"
    DEFAULT_CREDENTIALS = "default_credentials"
    SESSION_TOKEN_ANALYSIS = "session_token_analysis"
    CREDENTIAL_STUFFING = "credential_stuffing"
    EVASION = "evasion"

AuthVulnerabilityType.ACCOUNT_LOCKOUT_MISSING = AuthVulnerabilityType.BRUTE_FORCE  # type: ignore[attr-defined]

AuthVulnerabilityType.PASSWORD_RESET_ABUSE = AuthVulnerabilityType.PASSWORD_RESET  # type: ignore[attr-defined]

AuthVulnerabilityType.TWO_FACTOR_BYPASS = AuthVulnerabilityType.MFA_BYPASS  # type: ignore[attr-defined]

AuthVulnerabilityType.JWT_BYPASS = AuthVulnerabilityType.JWT_MANIPULATION  # type: ignore[attr-defined]

AuthVulnerabilityType.DEFAULT_CREDS = AuthVulnerabilityType.DEFAULT_CREDENTIALS  # type: ignore[attr-defined]

AuthVulnerabilityType.SESSION_SECURITY = AuthVulnerabilityType.SESSION_TOKEN_ANALYSIS  # type: ignore[attr-defined]

AuthBypassTechnique = AuthVulnerabilityType

AuthTechnique = AuthVulnerabilityType

class AuthMutationStrategy(str, Enum):
    """Enumeration of Authentication probe mutation and evasion strategies."""
    CASE_SENSITIVITY = "case_sensitivity"
    UNICODE_NORMALIZATION = "unicode_normalization"
    AUTH_HEADER_MANIPULATION = "auth_header_manipulation"
    TOKEN_FORMAT_MANIPULATION = "token_format_manipulation"
    RESPONSE_MANIPULATION = "response_manipulation"
    STANDARD = "standard"

AuthBypassMutationStrategy = AuthMutationStrategy

AuthStrategy = AuthMutationStrategy

AuthMutationStrategy.CASE_VARIATION = AuthMutationStrategy.CASE_SENSITIVITY  # type: ignore[attr-defined]

AuthMutationStrategy.HOMOGLYPH = AuthMutationStrategy.UNICODE_NORMALIZATION  # type: ignore[attr-defined]

AuthMutationStrategy.HEADER_SPOOFING = AuthMutationStrategy.AUTH_HEADER_MANIPULATION  # type: ignore[attr-defined]

AuthMutationStrategy.TOKEN_FORMAT = AuthMutationStrategy.TOKEN_FORMAT_MANIPULATION  # type: ignore[attr-defined]

AuthMutationStrategy.METHOD_OVERRIDE = AuthMutationStrategy.RESPONSE_MANIPULATION  # type: ignore[attr-defined]

@dataclass
class AuthBypassProbe:
    """Represents a targeted authentication bypass probe attempt."""
    probe_id: str
    target_url: str
    method: str = "GET"
    vulnerability_type: Union[AuthVulnerabilityType, str] = AuthVulnerabilityType.BRUTE_FORCE
    strategy: Union[AuthMutationStrategy, str] = AuthMutationStrategy.STANDARD
    headers: Dict[str, str] = field(default_factory=dict)
    params: Dict[str, Any] = field(default_factory=dict)
    json_data: Optional[Any] = None
    data: Optional[Any] = None
    canary_token: str = ""
    tested_parameter: str = ""
    original_value: Any = None
    tampered_value: Any = None
    is_auth_required: bool = False
    secondary_identity: Optional[Any] = None
    burst_count: int = 1
    is_benign: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class AuthBypassProbeResponse:
    """Captures the response outcome and metadata from an authentication probe execution."""
    probe: AuthBypassProbe
    status_code: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    json_body: Optional[Any] = None
    elapsed: float = 0.0
    error: Optional[str] = None
    raw_http_response: Optional[HttpResponse] = None
    burst_responses: List[Dict[str, Any]] = field(default_factory=list)
    rate_limit_headers: Dict[str, str] = field(default_factory=dict)
    sensitive_fields_detected: List[str] = field(default_factory=list)
    error_disclosure_detected: Optional[str] = None
    is_persisted: bool = False
    is_unauthorized_access: bool = False

@dataclass
class AuthBypassResult:
    """Represents an evaluated and confirmed authentication security finding."""
    template_id: str
    technique: str
    vulnerability_type: Union[AuthVulnerabilityType, str]
    mutation_strategy: str
    endpoint_url: str
    severity: str
    cwe_id: str
    cvss_score: float
    description: str
    evidence_snippet: str = ""
    parameter: str = ""
    status_code: int = 200
    confidence: float = 0.95
    is_valid_finding: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)
