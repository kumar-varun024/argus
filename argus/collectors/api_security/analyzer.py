"""api_security: Response analysis."""
from __future__ import annotations

import re
from typing import Dict, List, Optional

from argus.collectors.api_security.models import APIProbe, APIProbeResponse, APISecurityResult, APISecuritySeverity, APIVulnerabilityType


class APISecurityAnalyzer:
    """
    Evaluates API responses, analyzes sensitive data disclosures, parses rate limit headers,
    and applies strict false positive suppression.
    """

    # Sensitive PII, credential, key, and secret detection patterns
    SENSITIVE_PATTERNS = [
        (re.compile(r'"(?:password|passwd|pwd|password_hash|secret_key)"\s*:\s*"([^"]+)"', re.IGNORECASE), "password_hash"),
        (re.compile(r'"(?:access_token|refresh_token|auth_token|api_key|secret)"\s*:\s*"([A-Za-z0-9_\-\.]{12,})"', re.IGNORECASE), "auth_token_or_api_key"),
        (re.compile(r'"(?:ssn|social_security|credit_card|card_number|cvv|pin)"\s*:\s*"([^"]+)"', re.IGNORECASE), "pii_or_financial"),
        (re.compile(r'"(?:internal_ip|db_connection|aws_secret|private_key)"\s*:\s*"([^"]+)"', re.IGNORECASE), "internal_secret"),
        (re.compile(r'-----BEGIN (?:RSA )?PRIVATE KEY-----', re.IGNORECASE), "private_rsa_key"),
        (re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b'), "credit_card_number"),
        (re.compile(r'\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b'), "social_security_number"),
    ]

    # Error message, debug info, and stack trace disclosure patterns
    ERROR_PATTERNS = [
        (re.compile(r'Traceback \(most recent call last\):', re.IGNORECASE), "python_stack_trace"),
        (re.compile(r'org\.springframework\.web|NullPointerException|ServletException', re.IGNORECASE), "java_spring_stack_trace"),
        (re.compile(r'System\.Web\.HttpException|System\.NullReferenceException', re.IGNORECASE), "dotnet_stack_trace"),
        (re.compile(r'at (?:Object\.<anonymous>|Module\._compile|Function\.Module\._load)\s*\(', re.IGNORECASE), "nodejs_stack_trace"),
        (re.compile(r'Fatal error: Uncaught|Stack trace:\s*#0', re.IGNORECASE), "php_stack_trace"),
        (re.compile(r'SQL syntax.*MySQL|ORA-\d{5}|PostgreSQL.*ERROR|SQLite3::SQLException', re.IGNORECASE), "sql_syntax_error"),
        (re.compile(r'/(?:var/www|app/src|home/[a-z0-9_]+|opt/app)/[a-zA-Z0-9_\-\./]+', re.IGNORECASE), "internal_file_path"),
        (re.compile(r'[a-zA-Z]:\\(?:inetpub|Users|Windows)\\[a-zA-Z0-9_\-\.\\]+', re.IGNORECASE), "windows_file_path"),
    ]

    def detect_sensitive_fields(self, body: str) -> List[str]:
        """Detects sensitive attributes, tokens, and PII in response body."""
        if not body:
            return []
        detected: List[str] = []
        for pattern, label in self.SENSITIVE_PATTERNS:
            if pattern.search(body):
                detected.append(label)
        return list(set(detected))

    def detect_error_disclosure(self, body: str) -> Optional[str]:
        """Detects stack traces, database errors, and internal paths in response body."""
        if not body:
            return None
        for pattern, label in self.ERROR_PATTERNS:
            if pattern.search(body):
                return label
        return None

    def parse_rate_limit_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Parses and extracts standard rate limiting and retry headers."""
        parsed: Dict[str, str] = {}
        for k, v in headers.items():
            k_lower = k.lower()
            if "ratelimit" in k_lower or "retry-after" in k_lower or "x-rate-limit" in k_lower:
                parsed[k_lower] = str(v)
        return parsed

    def is_false_positive(self, probe: APIProbe, response: APIProbeResponse) -> bool:
        """
        Applies strict false positive suppression rules:
        1. Suppresses benign baseline probes.
        2. Suppresses connection failures (status == 0).
        3. Suppresses standard 400/401/403/404/405/422 responses unless sensitive data / stack trace is leaked.
        4. For Parameter Tampering: suppresses responses with explicit validation error messages.
        5. For Mass Assignment: suppresses responses that do not reflect or persist the injected field.
        6. For Rate Limiting: suppresses properly throttled endpoints (returns 429 and does not allow bypass).
        7. For BOLA/IDOR: suppresses 401/403/404 rejections or generic unauthenticated catalog data.
        8. For Method Tampering: suppresses standard 405 Method Not Allowed responses.
        """
        # 1. Benign baselines are never vulnerabilities
        if probe.is_benign:
            return True

        # 2. Connection failure
        if response.status_code == 0 or response.error:
            return True

        body_lower = (response.body or "").lower()

        # Check if error message disclosure is present
        error_leak = self.detect_error_disclosure(response.body)
        sensitive_leaks = self.detect_sensitive_fields(response.body)

        # 3. Standard rejection status codes without information leak
        if response.status_code in (400, 401, 403, 404, 405, 415, 422):
            if not error_leak and not sensitive_leaks:
                return True

        # 4. Mode-specific false positive validation
        vtype = probe.vulnerability_type

        if vtype == APIVulnerabilityType.PARAMETER_TAMPERING:
            # If server explicitly rejected with validation message
            rejection_indicators = [
                "invalid price", "negative price disallowed", "price must be positive",
                "invalid quantity", "negative quantity", "validation error",
                "invalid parameter", "unprocessable", "bad request",
            ]
            if any(ind in body_lower for ind in rejection_indicators):
                return True
            if response.status_code not in (200, 201, 204):
                return True

        elif vtype == APIVulnerabilityType.MASS_ASSIGNMENT:
            # Must verify that injected field is present in updated JSON response
            tested_param = probe.tested_parameter
            if response.status_code not in (200, 201, 204):
                return True
            if response.json_body and isinstance(response.json_body, dict):
                # If field was stripped and not present in response, it was properly ignored
                if tested_param not in response.json_body:
                    # Check nested objects
                    found_nested = False
                    for val in response.json_body.values():
                        if isinstance(val, dict) and tested_param in val:
                            found_nested = True
                            break
                    if not found_nested:
                        return True
            elif tested_param not in body_lower:
                return True

        elif vtype == APIVulnerabilityType.RATE_LIMITING_BYPASS:
            # If burst sequence was properly throttled (contains 429) and header bypass did not work
            bursts = response.burst_responses
            if bursts:
                status_codes = [b.get("status_code", 0) for b in bursts]
                # If all requests were 429 after threshold and rotation did not give 200s, it's properly rate-limited
                has_429 = any(sc == 429 for sc in status_codes)
                if has_429 and not probe.metadata.get("rotate_ip"):
                    return True
                # If rotated IP burst also got 429s throughout, bypass failed -> false positive
                if probe.metadata.get("rotate_ip") and status_codes[-1] == 429:
                    return True

        elif vtype == APIVulnerabilityType.BOLA_IDOR:
            # If resource access was rejected or returned empty object without sensitive data
            if response.status_code in (401, 403, 404):
                return True
            if response.status_code not in (200, 201):
                return True
            # If response is empty or generic catalog
            if not response.body or len(response.body.strip()) < 10:
                return True

        elif vtype == APIVulnerabilityType.EXCESSIVE_DATA_EXPOSURE:
            # Must have detected sensitive fields or error leak
            if not sensitive_leaks and not error_leak:
                return True

        elif vtype == APIVulnerabilityType.METHOD_TAMPERING:
            if response.status_code == 405:
                return True
            if response.status_code not in (200, 201, 204) and not error_leak:
                return True

        return False

    def evaluate_probe(
        self, probe: APIProbe, response: APIProbeResponse, target_url: str
    ) -> Optional[APISecurityResult]:
        """
        Evaluates an API probe response, verifies finding validity, and constructs an APISecurityResult.
        """
        # Run false positive filter
        if self.is_false_positive(probe, response):
            return None

        vtype = probe.vulnerability_type
        strategy_str = str(probe.strategy.value if hasattr(probe.strategy, "value") else probe.strategy)
        tested_param = probe.tested_parameter or "api_endpoint"

        # Check for sensitive data or error disclosure
        sensitive_fields = self.detect_sensitive_fields(response.body)
        error_disclosure = self.detect_error_disclosure(response.body)
        response.sensitive_fields_detected = sensitive_fields
        response.error_disclosure_detected = error_disclosure

        # Severity calibration, CWE, and CVSS assignment per requirement
        if vtype == APIVulnerabilityType.BOLA_IDOR:
            template_id = f"api-bola-idor-{tested_param}"
            technique = "bola_idor"
            severity = APISecuritySeverity.HIGH.value
            cwe_id = "CWE-639"
            cvss_score = 8.5
            description = (
                f"Broken Object Level Authorization (BOLA/IDOR) detected on {target_url}. "
                f"Accessing resource with modified entity parameter '{tested_param}' (tampered: {probe.tampered_value}) "
                f"returned unauthorized data (HTTP {response.status_code})."
            )

        elif vtype == APIVulnerabilityType.MASS_ASSIGNMENT:
            template_id = f"api-mass-assignment-{tested_param}"
            technique = "mass_assignment"
            severity = APISecuritySeverity.HIGH.value
            cwe_id = "CWE-915"
            cvss_score = 8.1
            description = (
                f"Mass Assignment vulnerability detected on {target_url}. "
                f"API accepted unauthorized privileged field '{tested_param}' with value '{probe.tampered_value}' "
                f"in request body and reflected/persisted it in response (HTTP {response.status_code})."
            )

        elif vtype == APIVulnerabilityType.PARAMETER_TAMPERING:
            template_id = f"api-parameter-tampering-{tested_param}"
            technique = "parameter_tampering"
            severity = APISecuritySeverity.HIGH.value
            cwe_id = "CWE-602"
            cvss_score = 8.5
            description = (
                f"Client-Side Parameter Tampering vulnerability detected on {target_url}. "
                f"API accepted modified parameter '{tested_param}' (tampered value: {probe.tampered_value}) "
                f"without server-side validation (HTTP {response.status_code})."
            )

        elif vtype == APIVulnerabilityType.RATE_LIMITING_BYPASS:
            template_id = "api-rate-limiting-bypass"
            technique = "rate_limiting_bypass"
            severity = APISecuritySeverity.MEDIUM.value
            cwe_id = "CWE-770"
            cvss_score = 5.3
            if probe.metadata.get("rotate_ip"):
                description = (
                    f"Rate Limiting Header Bypass detected on {target_url}. "
                    f"Throttling was bypassed by rotating client IP headers (X-Forwarded-For) during burst requests."
                )
            else:
                description = (
                    f"Missing API Rate Limiting detected on {target_url}. "
                    f"API allowed rapid burst sequence of {probe.burst_count} requests without throttling or rate limit headers."
                )

        elif vtype == APIVulnerabilityType.EXCESSIVE_DATA_EXPOSURE:
            template_id = "api-excessive-data-exposure"
            technique = "excessive_data_exposure"
            severity = APISecuritySeverity.MEDIUM.value
            cwe_id = "CWE-200"
            cvss_score = 5.3
            leaks_str = ", ".join(sensitive_fields) if sensitive_fields else "sensitive internal data"
            description = (
                f"Excessive Data Exposure detected on {target_url}. "
                f"API response exposed sensitive internal attributes: {leaks_str}."
            )

        elif vtype == APIVulnerabilityType.METHOD_TAMPERING:
            template_id = f"api-method-tampering-{probe.tampered_value or probe.method}"
            technique = "method_tampering"
            severity = APISecuritySeverity.HIGH.value
            cwe_id = "CWE-650"
            cvss_score = 7.5
            description = (
                f"HTTP Method Tampering vulnerability detected on {target_url}. "
                f"Endpoint responded favorably to unexpected HTTP method/override '{probe.tampered_value or probe.method}' "
                f"(HTTP {response.status_code})."
            )

        else:
            template_id = f"api-security-{tested_param}"
            technique = "api_security"
            severity = APISecuritySeverity.HIGH.value
            cwe_id = "CWE-639"
            cvss_score = 8.1
            description = f"API Security finding detected on {target_url}."

        # If error stack trace disclosure was detected alongside the finding
        if error_disclosure:
            description += f" Internal error disclosure detected: {error_disclosure}."

        evidence_snippet = (response.body or "")[:300]

        return APISecurityResult(
            template_id=template_id,
            technique=technique,
            vulnerability_type=vtype,
            mutation_strategy=strategy_str,
            endpoint_url=target_url,
            severity=severity,
            cwe_id=cwe_id,
            cvss_score=cvss_score,
            description=description,
            evidence_snippet=evidence_snippet,
            parameter=tested_param,
            status_code=response.status_code,
            confidence=0.95,
            is_valid_finding=True,
            metadata={
                "strategy": strategy_str,
                "tested_parameter": tested_param,
                "tampered_value": str(probe.tampered_value),
                "sensitive_fields": sensitive_fields,
                "error_disclosure": error_disclosure,
                "burst_count": probe.burst_count,
            },
        )
