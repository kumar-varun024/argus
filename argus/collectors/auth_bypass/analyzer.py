"""auth_bypass: Response analysis."""
from __future__ import annotations

import math
import re
import time
from typing import Dict, List, Optional

from argus.collectors.auth_bypass.models import AuthBypassProbe, AuthBypassProbeResponse, AuthBypassResult, AuthBypassSeverity, AuthVulnerabilityType


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
