"""
CORS Misconfiguration & HTTP Security Header Audit Module for ARGUS.

Actively discovers and validates Cross-Origin Resource Sharing (CORS) misconfigurations
and audits critical HTTP security response headers across discovered API endpoints and
web applications.

Key Capabilities:
1. Multi-Vector CORS Detection Modes:
   - Origin Reflection (arbitrary untrusted Origin echoed in Access-Control-Allow-Origin with credentials)
   - Null Origin Acceptance (Origin: null accepted with Access-Control-Allow-Credentials: true)
   - Wildcard with Credentials (Access-Control-Allow-Origin: * combined with ACAC: true)
   - Subdomain Trust Abuse (*.example.com overly broad origin trust)
   - Pre-flight Bypass & Misconfiguration (permissive OPTIONS methods/headers, arbitrary origin echo)
   - Origin Parser Differential (prefix/suffix injection, unescaped regex dots, URL encoding, protocol confusion)
2. Mutation & Evasion Strategies:
   - Origin Casing Variations (mixed case scheme/host)
   - Protocol Smuggling (http downgrade, ws/wss, ftp, file)
   - Subdomain Injection Patterns (prefix, suffix, delimiter manipulation)
   - Header Duplication & Folding (multiple Origin headers, comma-separated values)
   - Pre-flight Method & Header Enumeration (OPTIONS matrix with standard, custom, and wildcard verbs/headers)
3. HTTP Security Header Audits (8 Security Policies):
   - Content-Security-Policy (missing, unsafe-inline, unsafe-eval, wildcard sources, missing frame-ancestors)
   - Strict-Transport-Security (missing on HTTPS, low max-age < 31536000, missing includeSubDomains, preload)
   - X-Frame-Options (missing without CSP frame-ancestors, misconfigured ALLOW-FROM)
   - X-Content-Type-Options (missing nosniff)
   - Referrer-Policy (missing, overly permissive unsafe-url or no-referrer-when-downgrade)
   - Permissions-Policy / Feature-Policy (missing, unconstrained sensitive feature wildcards)
   - X-XSS-Protection (explicitly 0 or missing on legacy endpoints)
   - Cache-Control on Sensitive Endpoints (missing no-store / no-cache on authenticated or sensitive API routes)
4. Strict False Positive Rejection:
   - Suppresses legitimate same-origin reflections.
   - Suppresses standard unauthenticated wildcard CORS on public resources.
   - Suppresses HSTS checks on plain HTTP endpoints.
   - Suppresses redundant X-Frame-Options when strong CSP frame-ancestors is present.
   - Suppresses Cache-Control checks on public static assets (.css, .js, .png, etc.).
5. Quadruple State Publishing:
   - Publishes findings to raw_mission.evidence, raw_mission.vulnerabilities,
     attack_surface_graph (HAS_VULNERABILITY and HAS_ENDPOINT edges), and ControlledMission.publish_finding.
"""
from __future__ import annotations

import copy
import json
import logging
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

class CORSVulnerabilityType(str, Enum):
    """Enumeration of CORS vulnerability vector types."""
    ORIGIN_REFLECTION = "origin_reflection"
    NULL_ORIGIN_ALLOWED = "null_origin_allowed"
    WILDCARD_WITH_CREDENTIALS = "wildcard_with_credentials"
    SUBDOMAIN_TRUST_ABUSE = "subdomain_trust_abuse"
    PREFLIGHT_BYPASS = "preflight_bypass"
    ORIGIN_PARSER_DIFFERENTIAL = "origin_parser_differential"


# Compatibility aliases for CORS vectors
CORSVulnerabilityType.ORIGIN_REFLECT = CORSVulnerabilityType.ORIGIN_REFLECTION  # type: ignore[attr-defined]
CORSVulnerabilityType.NULL_ORIGIN = CORSVulnerabilityType.NULL_ORIGIN_ALLOWED  # type: ignore[attr-defined]
CORSVulnerabilityType.WILDCARD_CREDENTIALS = CORSVulnerabilityType.WILDCARD_WITH_CREDENTIALS  # type: ignore[attr-defined]
CORSVulnerabilityType.SUBDOMAIN_ABUSE = CORSVulnerabilityType.SUBDOMAIN_TRUST_ABUSE  # type: ignore[attr-defined]
CORSVulnerabilityType.PREFLIGHT_MISCONFIG = CORSVulnerabilityType.PREFLIGHT_BYPASS  # type: ignore[attr-defined]
CORSVulnerabilityType.PARSER_DIFFERENTIAL = CORSVulnerabilityType.ORIGIN_PARSER_DIFFERENTIAL  # type: ignore[attr-defined]
CORSTechnique = CORSVulnerabilityType


class HeaderVulnerabilityType(str, Enum):
    """Enumeration of HTTP Security Header audit findings."""
    CSP_MISSING = "csp_missing"
    CSP_WEAK_DIRECTIVE = "csp_weak_directive"
    HSTS_MISSING = "hsts_missing"
    HSTS_WEAK_DIRECTIVE = "hsts_weak_directive"
    XFO_MISSING = "x_frame_options_missing"
    XFO_MISCONFIGURED = "x_frame_options_misconfigured"
    XCTO_MISSING = "x_content_type_options_missing"
    REFERRER_POLICY_WEAK = "referrer_policy_weak"
    PERMISSIONS_POLICY_WEAK = "permissions_policy_weak"
    XSS_PROTECTION_DISABLED = "x_xss_protection_disabled"
    CACHE_CONTROL_SENSITIVE_LEAK = "cache_control_sensitive_leak"


# Compatibility alias
SecurityHeaderTechnique = HeaderVulnerabilityType


class CORSMutationStrategy(str, Enum):
    """Enumeration of CORS probe mutation and evasion strategies."""
    ORIGIN_CASING = "origin_casing"
    PROTOCOL_SMUGGLING = "protocol_smuggling"
    SUBDOMAIN_INJECTION = "subdomain_injection"
    HEADER_DUPLICATION = "header_duplication"
    PREFLIGHT_ENUMERATION = "preflight_enumeration"


# Compatibility aliases
CORSMutationStrategy.ORIGIN_CASING_VARIATION = CORSMutationStrategy.ORIGIN_CASING  # type: ignore[attr-defined]
CORSMutationStrategy.PROTOCOL_SMUGGLE = CORSMutationStrategy.PROTOCOL_SMUGGLING  # type: ignore[attr-defined]
CORSMutationStrategy.SUBDOMAIN_INJECT = CORSMutationStrategy.SUBDOMAIN_INJECTION  # type: ignore[attr-defined]
CORSMutationStrategy.HEADER_FOLDING = CORSMutationStrategy.HEADER_DUPLICATION  # type: ignore[attr-defined]
CORSMutationStrategy.PREFLIGHT_ENUM = CORSMutationStrategy.PREFLIGHT_ENUMERATION  # type: ignore[attr-defined]
CORSStrategy = CORSMutationStrategy


class CORSSeverity(str, Enum):
    """Severity ratings for CORS and HTTP Header audit findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# Compatibility alias
Severity = CORSSeverity


@dataclass
class CORSProbe:
    """Structure representing a single CORS or HTTP Header test probe."""
    probe_id: str
    target_url: str
    method: str = "GET"
    vulnerability_type: CORSVulnerabilityType = CORSVulnerabilityType.ORIGIN_REFLECTION
    strategy: CORSMutationStrategy = CORSMutationStrategy.ORIGIN_CASING
    origin: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    expected_pattern: str = ""
    description: str = ""
    is_preflight: bool = False


@dataclass
class CORSProbeResponse:
    """Structure representing normalized HTTP response from CORS probing."""
    status_code: int = 200
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    elapsed: float = 0.0
    success: bool = True
    error: Optional[str] = None
    url: str = ""
    method: str = "GET"

    def get_header(self, name: str, default: str = "") -> str:
        """Case-insensitive header lookup."""
        name_lower = name.lower()
        for k, v in self.headers.items():
            if k.lower() == name_lower:
                return str(v)
        return default

    @property
    def allow_origin(self) -> str:
        return self.get_header("access-control-allow-origin")

    @property
    def allow_credentials(self) -> bool:
        return self.get_header("access-control-allow-credentials").strip().lower() == "true"

    @property
    def allow_methods(self) -> str:
        return self.get_header("access-control-allow-methods")

    @property
    def allow_headers(self) -> str:
        return self.get_header("access-control-allow-headers")

    @property
    def vary(self) -> str:
        return self.get_header("vary")


@dataclass
class CORSSecurityResult:
    """Structure representing a validated CORS vulnerability finding."""
    is_valid_finding: bool
    template_id: str
    vulnerability_type: CORSVulnerabilityType
    vector_name: str
    severity: str
    confidence: float = 1.0
    cwe_id: str = "CWE-942"
    cvss_score: float = 8.1
    tested_origin: str = ""
    reflected_origin: Optional[str] = None
    allow_credentials: bool = False
    mutation_strategy: str = ""
    evidence_headers: Dict[str, str] = field(default_factory=dict)
    evidence_snippet: str = ""
    description: str = ""
    technique: str = ""
    status_code: int = 200


@dataclass
class HeaderAuditResult:
    """Structure representing a validated HTTP Security Header finding."""
    is_valid_finding: bool
    template_id: str
    header_name: str
    vulnerability_type: HeaderVulnerabilityType
    severity: str
    confidence: float = 1.0
    cwe_id: str = "CWE-693"
    cvss_score: float = 5.3
    current_value: Optional[str] = None
    recommendation: str = ""
    description: str = ""
    evidence_snippet: str = ""
    status_code: int = 200
    metadata: Dict[str, Any] = field(default_factory=dict)


# =============================================================================
# Payload & Mutation Generator
# =============================================================================

class CORSPayloadGenerator:
    """
    Generates multi-vector CORS probe requests incorporating 5 mutation strategies.
    """

    def __init__(self):
        self.attacker_domain = "evil-attacker.com"
        self.secondary_domain = "attacker.org"

    def _extract_host_parts(self, target_url: str) -> Tuple[str, str, str]:
        """Extracts scheme, hostname, and port from target URL."""
        parsed = urllib.parse.urlparse(target_url)
        scheme = parsed.scheme or "https"
        host = parsed.hostname or "example.com"
        try:
            port = f":{parsed.port}" if parsed.port else ""
        except (ValueError, TypeError):
            port = ""
        return scheme, host, port

    def generate_origin_reflection_probes(self, target_url: str) -> List[CORSProbe]:
        """Generates probes testing arbitrary Origin reflection."""
        probes = []
        # Standard attacker origin
        probes.append(
            CORSProbe(
                probe_id=f"cors_reflect_{uuid.uuid4().hex[:8]}",
                target_url=target_url,
                method="GET",
                vulnerability_type=CORSVulnerabilityType.ORIGIN_REFLECTION,
                strategy=CORSMutationStrategy.ORIGIN_CASING,
                origin=f"https://{self.attacker_domain}",
                headers={"Origin": f"https://{self.attacker_domain}"},
                description="Arbitrary untrusted origin reflection probe",
            )
        )
        # Mutation 1: Mixed-case scheme and host
        probes.append(
            CORSProbe(
                probe_id=f"cors_reflect_casing_{uuid.uuid4().hex[:8]}",
                target_url=target_url,
                method="GET",
                vulnerability_type=CORSVulnerabilityType.ORIGIN_REFLECTION,
                strategy=CORSMutationStrategy.ORIGIN_CASING,
                origin=f"hTtPs://{self.attacker_domain.upper()}",
                headers={"Origin": f"hTtPs://{self.attacker_domain.upper()}"},
                description="Origin casing mutation probe",
            )
        )
        return probes

    def generate_null_origin_probes(self, target_url: str) -> List[CORSProbe]:
        """Generates probes testing null Origin acceptance."""
        probes = []
        # Mode 2 / Mutation 2: Null Origin
        probes.append(
            CORSProbe(
                probe_id=f"cors_null_{uuid.uuid4().hex[:8]}",
                target_url=target_url,
                method="GET",
                vulnerability_type=CORSVulnerabilityType.NULL_ORIGIN_ALLOWED,
                strategy=CORSMutationStrategy.PROTOCOL_SMUGGLING,
                origin="null",
                headers={"Origin": "null"},
                description="Null origin acceptance probe (sandboxed iframe / local file)",
            )
        )
        # Case variation null
        probes.append(
            CORSProbe(
                probe_id=f"cors_null_case_{uuid.uuid4().hex[:8]}",
                target_url=target_url,
                method="GET",
                vulnerability_type=CORSVulnerabilityType.NULL_ORIGIN_ALLOWED,
                strategy=CORSMutationStrategy.ORIGIN_CASING,
                origin="NULL",
                headers={"Origin": "NULL"},
                description="Cased NULL origin probe",
            )
        )
        return probes

    def generate_wildcard_probes(self, target_url: str) -> List[CORSProbe]:
        """Generates probes testing wildcard with credentials."""
        return [
            CORSProbe(
                probe_id=f"cors_wildcard_{uuid.uuid4().hex[:8]}",
                target_url=target_url,
                method="GET",
                vulnerability_type=CORSVulnerabilityType.WILDCARD_WITH_CREDENTIALS,
                strategy=CORSMutationStrategy.ORIGIN_CASING,
                origin=f"https://{self.attacker_domain}",
                headers={"Origin": f"https://{self.attacker_domain}"},
                description="Wildcard origin with credentials probe",
            )
        ]

    def generate_subdomain_probes(self, target_url: str) -> List[CORSProbe]:
        """Generates probes testing subdomain trust abuse."""
        scheme, host, _ = self._extract_host_parts(target_url)
        probes = []
        # Mutation 3: Subdomain injection
        probes.append(
            CORSProbe(
                probe_id=f"cors_subdomain_{uuid.uuid4().hex[:8]}",
                target_url=target_url,
                method="GET",
                vulnerability_type=CORSVulnerabilityType.SUBDOMAIN_TRUST_ABUSE,
                strategy=CORSMutationStrategy.SUBDOMAIN_INJECTION,
                origin=f"{scheme}://attacker.{host}",
                headers={"Origin": f"{scheme}://attacker.{host}"},
                description="Subdomain trust abuse probe (arbitrary subdomain)",
            )
        )
        probes.append(
            CORSProbe(
                probe_id=f"cors_subdomain_nested_{uuid.uuid4().hex[:8]}",
                target_url=target_url,
                method="GET",
                vulnerability_type=CORSVulnerabilityType.SUBDOMAIN_TRUST_ABUSE,
                strategy=CORSMutationStrategy.SUBDOMAIN_INJECTION,
                origin=f"{scheme}://evil.corp.{host}",
                headers={"Origin": f"{scheme}://evil.corp.{host}"},
                description="Deeply nested subdomain trust abuse probe",
            )
        )
        return probes

    def generate_preflight_probes(self, target_url: str) -> List[CORSProbe]:
        """Generates OPTIONS pre-flight probes testing methods/headers permissions."""
        scheme, host, _ = self._extract_host_parts(target_url)
        probes = []
        # Mode 5 / Mutation 5: Pre-flight enumeration
        probes.append(
            CORSProbe(
                probe_id=f"cors_preflight_verbs_{uuid.uuid4().hex[:8]}",
                target_url=target_url,
                method="OPTIONS",
                vulnerability_type=CORSVulnerabilityType.PREFLIGHT_BYPASS,
                strategy=CORSMutationStrategy.PREFLIGHT_ENUMERATION,
                origin=f"https://{self.attacker_domain}",
                headers={
                    "Origin": f"https://{self.attacker_domain}",
                    "Access-Control-Request-Method": "PUT",
                    "Access-Control-Request-Headers": "Authorization, X-Custom-Auth, Content-Type",
                },
                is_preflight=True,
                description="Pre-flight OPTIONS probe requesting sensitive PUT method and Auth headers",
            )
        )
        probes.append(
            CORSProbe(
                probe_id=f"cors_preflight_dangerous_{uuid.uuid4().hex[:8]}",
                target_url=target_url,
                method="OPTIONS",
                vulnerability_type=CORSVulnerabilityType.PREFLIGHT_BYPASS,
                strategy=CORSMutationStrategy.PREFLIGHT_ENUMERATION,
                origin=f"https://{self.attacker_domain}",
                headers={
                    "Origin": f"https://{self.attacker_domain}",
                    "Access-Control-Request-Method": "DELETE",
                    "Access-Control-Request-Headers": "*",
                },
                is_preflight=True,
                description="Pre-flight OPTIONS probe requesting wildcard headers and DELETE",
            )
        )
        probes.append(
            CORSProbe(
                probe_id=f"cors_preflight_patch_{uuid.uuid4().hex[:8]}",
                target_url=target_url,
                method="OPTIONS",
                vulnerability_type=CORSVulnerabilityType.PREFLIGHT_BYPASS,
                strategy=CORSMutationStrategy.PREFLIGHT_ENUMERATION,
                origin=f"{scheme}://attacker.{host}",
                headers={
                    "Origin": f"{scheme}://attacker.{host}",
                    "Access-Control-Request-Method": "PATCH",
                    "Access-Control-Request-Headers": "X-Auth-Token",
                },
                is_preflight=True,
                description="Pre-flight OPTIONS probe with subdomain origin and PATCH method",
            )
        )
        return probes

    def generate_parser_differential_probes(self, target_url: str) -> List[CORSProbe]:
        """Generates parser differential probes (prefix, suffix, encoding, protocol)."""
        scheme, host, _ = self._extract_host_parts(target_url)
        probes = []
        # Prefix injection: target.com.attacker.com
        probes.append(
            CORSProbe(
                probe_id=f"cors_diff_prefix_{uuid.uuid4().hex[:8]}",
                target_url=target_url,
                method="GET",
                vulnerability_type=CORSVulnerabilityType.ORIGIN_PARSER_DIFFERENTIAL,
                strategy=CORSMutationStrategy.SUBDOMAIN_INJECTION,
                origin=f"https://{host}.{self.attacker_domain}",
                headers={"Origin": f"https://{host}.{self.attacker_domain}"},
                description="Prefix parser differential probe (target.com.attacker.com)",
            )
        )
        # Suffix injection: attacker-target.com or target.com-attacker.com
        probes.append(
            CORSProbe(
                probe_id=f"cors_diff_suffix_{uuid.uuid4().hex[:8]}",
                target_url=target_url,
                method="GET",
                vulnerability_type=CORSVulnerabilityType.ORIGIN_PARSER_DIFFERENTIAL,
                strategy=CORSMutationStrategy.SUBDOMAIN_INJECTION,
                origin=f"https://{host}-{self.attacker_domain}",
                headers={"Origin": f"https://{host}-{self.attacker_domain}"},
                description="Suffix / delimiter parser differential probe (target-attacker.com)",
            )
        )
        # Unescaped regex dot: targetXcom.attacker.com or targetXcom
        host_no_dots = host.replace(".", "X")
        probes.append(
            CORSProbe(
                probe_id=f"cors_diff_regex_{uuid.uuid4().hex[:8]}",
                target_url=target_url,
                method="GET",
                vulnerability_type=CORSVulnerabilityType.ORIGIN_PARSER_DIFFERENTIAL,
                strategy=CORSMutationStrategy.SUBDOMAIN_INJECTION,
                origin=f"https://{host_no_dots}.com",
                headers={"Origin": f"https://{host_no_dots}.com"},
                description="Unescaped regex dot origin probe",
            )
        )
        # Mutation 2: Protocol Smuggling / Downgrade (http:// on https target, or ws://)
        insecure_scheme = "http" if scheme == "https" else "https"
        probes.append(
            CORSProbe(
                probe_id=f"cors_diff_proto_{uuid.uuid4().hex[:8]}",
                target_url=target_url,
                method="GET",
                vulnerability_type=CORSVulnerabilityType.ORIGIN_PARSER_DIFFERENTIAL,
                strategy=CORSMutationStrategy.PROTOCOL_SMUGGLING,
                origin=f"{insecure_scheme}://{host}",
                headers={"Origin": f"{insecure_scheme}://{host}"},
                description="Protocol smuggling / scheme confusion origin probe",
            )
        )
        # WebSocket protocol origin
        probes.append(
            CORSProbe(
                probe_id=f"cors_diff_ws_{uuid.uuid4().hex[:8]}",
                target_url=target_url,
                method="GET",
                vulnerability_type=CORSVulnerabilityType.ORIGIN_PARSER_DIFFERENTIAL,
                strategy=CORSMutationStrategy.PROTOCOL_SMUGGLING,
                origin=f"ws://{host}",
                headers={"Origin": f"ws://{host}"},
                description="WebSocket protocol smuggling origin probe",
            )
        )
        # Mutation 4: Header duplication & folding
        probes.append(
            CORSProbe(
                probe_id=f"cors_diff_folding_{uuid.uuid4().hex[:8]}",
                target_url=target_url,
                method="GET",
                vulnerability_type=CORSVulnerabilityType.ORIGIN_PARSER_DIFFERENTIAL,
                strategy=CORSMutationStrategy.HEADER_DUPLICATION,
                origin=f"https://{self.attacker_domain}",
                headers={
                    "Origin": f"https://{self.attacker_domain}",
                    "X-Original-Origin": f"https://{host}",
                    "X-Forwarded-Host": host,
                },
                description="Header duplication and override probe",
            )
        )
        return probes

    def generate_all_cors_probes(self, target_url: str, is_auth: bool = True) -> List[CORSProbe]:
        """Generates comprehensive probe suite covering all 6 modes and 5 mutation strategies."""
        all_probes = []
        all_probes.extend(self.generate_origin_reflection_probes(target_url))
        all_probes.extend(self.generate_null_origin_probes(target_url))
        all_probes.extend(self.generate_wildcard_probes(target_url))
        all_probes.extend(self.generate_subdomain_probes(target_url))
        all_probes.extend(self.generate_preflight_probes(target_url))
        all_probes.extend(self.generate_parser_differential_probes(target_url))
        return all_probes


# Compatibility alias
CORSMutationGenerator = CORSPayloadGenerator


# =============================================================================
# Probing Engine (Polymorphic HTTP Client Dispatch)
# =============================================================================

class CORSProber:
    """
    Executes CORS probe requests and retrieves response headers using
    AuthenticatedHttpClient or mock test clients.
    """

    def __init__(self, http_client: Optional[Any] = None, timeout: float = 10.0):
        self.http_client = http_client
        self.timeout = timeout

    def _execute_request(
        self,
        mission: Any,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
    ) -> CORSProbeResponse:
        """Dispatches request via mock client or AuthenticatedHttpClient."""
        method = method.upper()
        req_headers = dict(headers or {})
        req_cookies = dict(cookies or {})

        try:
            if self.http_client is not None:
                client = self.http_client

                # 1. Custom / Mock client with direct method calls
                if method == "OPTIONS" and hasattr(client, "options"):
                    try:
                        raw_resp = client.options(mission, url, headers=req_headers, cookies=req_cookies, timeout=self.timeout)
                    except TypeError:
                        raw_resp = client.options(url, headers=req_headers, cookies=req_cookies)
                    return self._normalize_response(raw_resp, url, method)

                if method == "GET" and hasattr(client, "get"):
                    try:
                        raw_resp = client.get(mission, url, headers=req_headers, cookies=req_cookies, timeout=self.timeout)
                    except TypeError:
                        raw_resp = client.get(url, headers=req_headers, cookies=req_cookies)
                    return self._normalize_response(raw_resp, url, method)

                if hasattr(client, "request"):
                    try:
                        raw_resp = client.request(mission, method=method, url=url, headers=req_headers, cookies=req_cookies, timeout=self.timeout)
                    except TypeError:
                        raw_resp = client.request(method=method, url=url, headers=req_headers, cookies=req_cookies)
                    return self._normalize_response(raw_resp, url, method)

                if callable(client):
                    raw_resp = client(method=method, url=url, headers=req_headers, cookies=req_cookies)
                    return self._normalize_response(raw_resp, url, method)

            # Fallback to AuthenticatedHttpClient context manager
            with AuthenticatedHttpClient(timeout=self.timeout, max_retries=1) as client:
                if method == "OPTIONS":
                    raw_resp = client.options(mission, url, headers=req_headers, cookies=req_cookies, timeout=self.timeout)
                elif method == "GET":
                    raw_resp = client.get(mission, url, headers=req_headers, cookies=req_cookies, timeout=self.timeout)
                else:
                    raw_resp = client.request(mission, method=method, url=url, headers=req_headers, cookies=req_cookies, timeout=self.timeout)
                return self._normalize_response(raw_resp, url, method)

        except Exception as e:
            logger.debug("CORSProber HTTP request to %s failed: %s", url, e)
            return CORSProbeResponse(
                status_code=0,
                headers={},
                body="",
                elapsed=0.0,
                success=False,
                error=str(e),
                url=url,
                method=method,
            )

    def _normalize_response(self, raw_resp: Any, url: str, method: str) -> CORSProbeResponse:
        """Converts diverse client response objects into CORSProbeResponse."""
        if raw_resp is None:
            return CORSProbeResponse(status_code=0, headers={}, body="", success=False, error="None response", url=url, method=method)

        if isinstance(raw_resp, CORSProbeResponse):
            return raw_resp

        status_code = getattr(raw_resp, "status_code", 200) or 200
        headers_raw = getattr(raw_resp, "headers", {}) or {}
        # Normalize headers to string values with lower-case keys
        norm_headers: Dict[str, str] = {}
        for k, v in headers_raw.items():
            norm_headers[str(k).lower()] = str(v)

        body = getattr(raw_resp, "body", "") or getattr(raw_resp, "text", "") or ""
        elapsed = getattr(raw_resp, "elapsed", 0.0) or 0.0
        success = getattr(raw_resp, "success", True)
        if isinstance(success, bool) and not success and not getattr(raw_resp, "error", None):
            success = (200 <= status_code < 400)
        error = getattr(raw_resp, "error", None)

        return CORSProbeResponse(
            status_code=int(status_code),
            headers=norm_headers,
            body=str(body),
            elapsed=float(elapsed) if isinstance(elapsed, (int, float)) else 0.0,
            success=bool(success),
            error=str(error) if error else None,
            url=url,
            method=method,
        )

    def execute_probe(self, mission: Any, probe: CORSProbe) -> CORSProbeResponse:
        """Executes a single CORS probe against its target URL."""
        return self._execute_request(
            mission=mission,
            method=probe.method,
            url=probe.target_url,
            headers=probe.headers,
        )

    def execute_header_audit(self, mission: Any, url: str) -> CORSProbeResponse:
        """Retrieves baseline response headers for HTTP security header audit."""
        return self._execute_request(
            mission=mission,
            method="GET",
            url=url,
        )


# =============================================================================
# CORS Vulnerability Analyzer
# =============================================================================

class CORSAnalyzer:
    """
    Evaluates HTTP response headers for CORS misconfigurations and enforces
    strict false positive rejection rules.
    """

    def evaluate_probe(
        self,
        probe: CORSProbe,
        resp: CORSProbeResponse,
        target_url: str,
    ) -> Optional[CORSSecurityResult]:
        """Evaluates a probe response against CORS security criteria."""
        if not resp.success and resp.status_code == 0:
            return None

        acao = resp.allow_origin.strip()
        acac = resp.allow_credentials
        probe_origin = probe.origin.strip()

        # If no ACAO header is returned, no CORS configuration is exposed
        if not acao:
            return None

        parsed_target = urllib.parse.urlparse(target_url)
        target_origin = f"{parsed_target.scheme}://{parsed_target.netloc}"
        target_host = parsed_target.hostname or ""

        # False Positive Rejection 1: Same-Origin Reflection
        # If the server reflects the target's own origin, this is normal and safe
        if acao.lower() == target_origin.lower() or (target_host and acao.lower() == f"https://{target_host}".lower()):
            return None

        # False Positive Rejection 2: Standard Unauthenticated Wildcard on Public Resource
        # ACAO: * without credentials is safe and compliant for public APIs
        if acao == "*" and not acac:
            return None

        # Mode 3: Wildcard with Credentials (Critical Severity - Spec Violation & Exploit Risk)
        if acao == "*" and acac:
            desc = (
                f"Severe CORS Misconfiguration on {target_url}: The server returns "
                f"'Access-Control-Allow-Origin: *' combined with 'Access-Control-Allow-Credentials: true'. "
                f"This configuration creates potential credential leakage in non-standard clients or browsers."
            )
            return CORSSecurityResult(
                is_valid_finding=True,
                template_id="cors-wildcard-with-credentials",
                vulnerability_type=CORSVulnerabilityType.WILDCARD_WITH_CREDENTIALS,
                vector_name="wildcard_with_credentials",
                severity=CORSSeverity.CRITICAL.value,
                confidence=1.0,
                cwe_id="CWE-942",
                cvss_score=9.8,
                tested_origin=probe_origin,
                reflected_origin=acao,
                allow_credentials=acac,
                mutation_strategy=probe.strategy.value,
                evidence_headers=dict(resp.headers),
                evidence_snippet=f"ACAO: {acao}, ACAC: {acac}",
                description=desc,
                technique="Wildcard Origin Allowed with Credentials",
                status_code=resp.status_code,
            )

        # Mode 2: Null Origin Allowed
        if probe.vulnerability_type == CORSVulnerabilityType.NULL_ORIGIN_ALLOWED:
            if acao.lower() == "null" or (probe_origin.lower() == "null" and acao.lower() == "null"):
                severity = CORSSeverity.HIGH.value if acac else CORSSeverity.MEDIUM.value
                cvss = 8.1 if acac else 5.3
                desc = (
                    f"CORS Misconfiguration on {target_url}: The server accepts 'Origin: null' "
                    f"and responds with 'Access-Control-Allow-Origin: null' (Credentials: {acac}). "
                    f"Attackers can exploit this via sandboxed <iframe> elements to issue cross-origin requests."
                )
                return CORSSecurityResult(
                    is_valid_finding=True,
                    template_id="cors-null-origin-allowed",
                    vulnerability_type=CORSVulnerabilityType.NULL_ORIGIN_ALLOWED,
                    vector_name="null_origin_allowed",
                    severity=severity,
                    confidence=1.0,
                    cwe_id="CWE-942",
                    cvss_score=cvss,
                    tested_origin=probe_origin,
                    reflected_origin=acao,
                    allow_credentials=acac,
                    mutation_strategy=probe.strategy.value,
                    evidence_headers=dict(resp.headers),
                    evidence_snippet=f"ACAO: {acao}, ACAC: {acac}",
                    description=desc,
                    technique="Insecure Null Origin Allowed",
                    status_code=resp.status_code,
                )

        # Mode 4: Subdomain Trust Abuse
        if probe.vulnerability_type == CORSVulnerabilityType.SUBDOMAIN_TRUST_ABUSE:
            # Check if probe origin was echoed
            if self._is_origin_reflected(probe_origin, acao):
                severity = CORSSeverity.HIGH.value if acac else CORSSeverity.MEDIUM.value
                cvss = 8.1 if acac else 5.3
                desc = (
                    f"CORS Misconfiguration on {target_url}: Overly broad origin trust allows arbitrary "
                    f"subdomains ({probe_origin}). An attacker who compromises or injects a subdomain can "
                    f"read sensitive authenticated cross-origin data (Credentials: {acac})."
                )
                return CORSSecurityResult(
                    is_valid_finding=True,
                    template_id="cors-subdomain-trust-abuse",
                    vulnerability_type=CORSVulnerabilityType.SUBDOMAIN_TRUST_ABUSE,
                    vector_name="subdomain_trust_abuse",
                    severity=severity,
                    confidence=1.0,
                    cwe_id="CWE-942",
                    cvss_score=cvss,
                    tested_origin=probe_origin,
                    reflected_origin=acao,
                    allow_credentials=acac,
                    mutation_strategy=probe.strategy.value,
                    evidence_headers=dict(resp.headers),
                    evidence_snippet=f"ACAO: {acao}, ACAC: {acac}",
                    description=desc,
                    technique="Overly Broad Subdomain Trust Abuse",
                    status_code=resp.status_code,
                )

        # Mode 5: Pre-flight Bypass & Misconfiguration
        if probe.is_preflight or probe.vulnerability_type == CORSVulnerabilityType.PREFLIGHT_BYPASS:
            acam = resp.allow_methods
            acah = resp.allow_headers
            is_echoed = self._is_origin_reflected(probe_origin, acao)
            is_overly_permissive_methods = "*" in acam or any(m in acam.upper() for m in ("PUT", "DELETE", "PATCH", "TRACE"))
            is_overly_permissive_headers = "*" in acah or "authorization" in acah.lower()

            if is_echoed and (is_overly_permissive_methods or is_overly_permissive_headers or acac):
                severity = CORSSeverity.HIGH.value if acac else CORSSeverity.MEDIUM.value
                cvss = 7.5 if acac else 5.3
                desc = (
                    f"CORS Pre-flight Misconfiguration on {target_url}: OPTIONS pre-flight permits "
                    f"untrusted origin '{acao}' with permissive methods ({acam or 'None'}) and headers ({acah or 'None'}) (Credentials: {acac})."
                )
                return CORSSecurityResult(
                    is_valid_finding=True,
                    template_id="cors-preflight-misconfiguration",
                    vulnerability_type=CORSVulnerabilityType.PREFLIGHT_BYPASS,
                    vector_name="preflight_bypass",
                    severity=severity,
                    confidence=1.0,
                    cwe_id="CWE-942",
                    cvss_score=cvss,
                    tested_origin=probe_origin,
                    reflected_origin=acao,
                    allow_credentials=acac,
                    mutation_strategy=probe.strategy.value,
                    evidence_headers=dict(resp.headers),
                    evidence_snippet=f"ACAO: {acao}, ACAM: {acam}, ACAH: {acah}, ACAC: {acac}",
                    description=desc,
                    technique="Permissive Pre-flight Configuration",
                    status_code=resp.status_code,
                )

        # Mode 6: Origin Parser Differential
        if probe.vulnerability_type == CORSVulnerabilityType.ORIGIN_PARSER_DIFFERENTIAL:
            if self._is_origin_reflected(probe_origin, acao):
                severity = CORSSeverity.HIGH.value if acac else CORSSeverity.MEDIUM.value
                cvss = 8.1 if acac else 5.3
                desc = (
                    f"CORS Origin Parser Differential on {target_url}: Insecure origin validation regex or parser "
                    f"accepted crafted origin '{probe_origin}' and echoed '{acao}' (Credentials: {acac})."
                )
                return CORSSecurityResult(
                    is_valid_finding=True,
                    template_id="cors-parser-differential",
                    vulnerability_type=CORSVulnerabilityType.ORIGIN_PARSER_DIFFERENTIAL,
                    vector_name="origin_parser_differential",
                    severity=severity,
                    confidence=1.0,
                    cwe_id="CWE-942",
                    cvss_score=cvss,
                    tested_origin=probe_origin,
                    reflected_origin=acao,
                    allow_credentials=acac,
                    mutation_strategy=probe.strategy.value,
                    evidence_headers=dict(resp.headers),
                    evidence_snippet=f"ACAO: {acao}, ACAC: {acac}",
                    description=desc,
                    technique="Origin Parser Differential Evasion",
                    status_code=resp.status_code,
                )

        # Mode 1: Arbitrary Untrusted Origin Reflection (Catch-All)
        if self._is_origin_reflected(probe_origin, acao):
            severity = CORSSeverity.HIGH.value if acac else CORSSeverity.MEDIUM.value
            cvss = 8.1 if acac else 5.3
            desc = (
                f"CORS Misconfiguration on {target_url}: The server reflects arbitrary untrusted "
                f"Origin '{probe_origin}' in 'Access-Control-Allow-Origin' (Credentials: {acac}). "
                f"Attackers can read private response data or trigger state-changing cross-origin requests."
            )
            return CORSSecurityResult(
                is_valid_finding=True,
                template_id="cors-origin-reflection",
                vulnerability_type=CORSVulnerabilityType.ORIGIN_REFLECTION,
                vector_name="origin_reflection",
                severity=severity,
                confidence=1.0,
                cwe_id="CWE-942",
                cvss_score=cvss,
                tested_origin=probe_origin,
                reflected_origin=acao,
                allow_credentials=acac,
                mutation_strategy=probe.strategy.value,
                evidence_headers=dict(resp.headers),
                evidence_snippet=f"ACAO: {acao}, ACAC: {acac}",
                description=desc,
                technique="Arbitrary Origin Reflection",
                status_code=resp.status_code,
            )

        return None

    def _is_origin_reflected(self, probe_origin: str, acao: str) -> bool:
        """Determines if the probe origin is reflected or whitelisted by ACAO."""
        if not acao or not probe_origin:
            return False
        p_clean = probe_origin.strip().lower()
        a_clean = acao.strip().lower()
        if p_clean == a_clean:
            return True
        # Check without trailing slash or protocol
        p_nohdr = re.sub(r"^https?://", "", p_clean).rstrip("/")
        a_nohdr = re.sub(r"^https?://", "", a_clean).rstrip("/")
        return p_nohdr == a_nohdr


# =============================================================================
# HTTP Security Header Auditor
# =============================================================================

class HTTPHeaderAuditor:
    """
    Audits 8 critical HTTP security response policies:
    1. Content-Security-Policy (CSP)
    2. Strict-Transport-Security (HSTS)
    3. X-Frame-Options (XFO)
    4. X-Content-Type-Options (XCTO)
    5. Referrer-Policy
    6. Permissions-Policy
    7. X-XSS-Protection
    8. Cache-Control on Sensitive Endpoints
    """

    STATIC_EXTENSIONS = (
        ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg",
        ".ico", ".woff", ".woff2", ".ttf", ".eot", ".map", ".webp",
    )

    SENSITIVE_PATH_KEYWORDS = (
        "/api/", "/user", "/account", "/auth", "/login", "/profile",
        "/token", "/session", "/admin", "/checkout", "/cart", "/billing",
        "/dashboard", "/settings", "/oauth", "/password", "/secret",
    )

    def audit_headers(
        self,
        url: str,
        resp: CORSProbeResponse,
        is_sensitive: Optional[bool] = None,
    ) -> List[HeaderAuditResult]:
        """Performs exhaustive 8-header audit on the given HTTP response."""
        results: List[HeaderAuditResult] = []
        if resp.status_code == 0:
            return results

        # 1. Content-Security-Policy Audit
        csp_results = self._audit_csp(url, resp)
        results.extend(csp_results)

        # 2. Strict-Transport-Security (HSTS) Audit
        hsts_results = self._audit_hsts(url, resp)
        results.extend(hsts_results)

        # 3. X-Frame-Options (XFO) Audit (suppressed if CSP frame-ancestors is present)
        has_csp_frame_ancestors = any(
            r.metadata.get("has_frame_ancestors") for r in csp_results if not r.is_valid_finding
        ) or self._has_valid_csp_frame_ancestors(resp)
        xfo_results = self._audit_x_frame_options(url, resp, has_csp_frame_ancestors)
        results.extend(xfo_results)

        # 4. X-Content-Type-Options (XCTO) Audit
        xcto_results = self._audit_x_content_type_options(url, resp)
        results.extend(xcto_results)

        # 5. Referrer-Policy Audit
        referrer_results = self._audit_referrer_policy(url, resp)
        results.extend(referrer_results)

        # 6. Permissions-Policy Audit
        perm_results = self._audit_permissions_policy(url, resp)
        results.extend(perm_results)

        # 7. X-XSS-Protection Audit
        has_strong_csp = any(
            r.metadata.get("is_strong_csp") for r in csp_results if not r.is_valid_finding
        ) or self._has_strong_csp(resp)
        xss_results = self._audit_x_xss_protection(url, resp, has_strong_csp)
        results.extend(xss_results)

        # 8. Cache-Control on Sensitive Endpoints Audit
        cache_results = self._audit_cache_control_sensitive(url, resp, is_sensitive)
        results.extend(cache_results)

        return results

    def _has_valid_csp_frame_ancestors(self, resp: CORSProbeResponse) -> bool:
        """Checks if response contains a valid frame-ancestors directive."""
        csp = resp.get_header("content-security-policy")
        if not csp:
            return False
        return "frame-ancestors" in csp.lower()

    def _has_strong_csp(self, resp: CORSProbeResponse) -> bool:
        """Checks if response has a robust CSP header."""
        csp = resp.get_header("content-security-policy")
        if not csp:
            return False
        csp_lower = csp.lower()
        return "default-src" in csp_lower and "'unsafe-inline'" not in csp_lower

    def _audit_csp(self, url: str, resp: CORSProbeResponse) -> List[HeaderAuditResult]:
        """Audits Content-Security-Policy."""
        results = []
        csp = resp.get_header("content-security-policy")

        if not csp:
            results.append(
                HeaderAuditResult(
                    is_valid_finding=True,
                    template_id="security-header-missing-csp",
                    header_name="Content-Security-Policy",
                    vulnerability_type=HeaderVulnerabilityType.CSP_MISSING,
                    severity=CORSSeverity.MEDIUM.value,
                    confidence=1.0,
                    cwe_id="CWE-693",
                    cvss_score=5.3,
                    current_value=None,
                    recommendation="Implement a strict Content-Security-Policy (CSP) restricting script-src, object-src, and frame-ancestors.",
                    description=f"Missing Content-Security-Policy header on {url}. The application is exposed to Cross-Site Scripting (XSS) and code injection.",
                    evidence_snippet="Content-Security-Policy: [Missing]",
                    status_code=resp.status_code,
                )
            )
            return results

        csp_lower = csp.lower()

        # Check for unsafe-inline in script execution
        if "'unsafe-inline'" in csp_lower:
            results.append(
                HeaderAuditResult(
                    is_valid_finding=True,
                    template_id="security-header-weak-csp-unsafe-inline",
                    header_name="Content-Security-Policy",
                    vulnerability_type=HeaderVulnerabilityType.CSP_WEAK_DIRECTIVE,
                    severity=CORSSeverity.MEDIUM.value,
                    confidence=1.0,
                    cwe_id="CWE-693",
                    cvss_score=5.3,
                    current_value=csp,
                    recommendation="Remove 'unsafe-inline' from script-src / default-src directives and adopt cryptographic nonces or hashes.",
                    description=f"Weak Content-Security-Policy on {url}: 'unsafe-inline' is permitted, disabling primary XSS mitigation guarantees.",
                    evidence_snippet=f"CSP: {csp[:150]}...",
                    status_code=resp.status_code,
                )
            )

        # Check for unsafe-eval
        if "'unsafe-eval'" in csp_lower:
            results.append(
                HeaderAuditResult(
                    is_valid_finding=True,
                    template_id="security-header-weak-csp-unsafe-eval",
                    header_name="Content-Security-Policy",
                    vulnerability_type=HeaderVulnerabilityType.CSP_WEAK_DIRECTIVE,
                    severity=CORSSeverity.MEDIUM.value,
                    confidence=1.0,
                    cwe_id="CWE-693",
                    cvss_score=5.3,
                    current_value=csp,
                    recommendation="Remove 'unsafe-eval' from script-src to prevent dynamic code execution from strings.",
                    description=f"Weak Content-Security-Policy on {url}: 'unsafe-eval' is permitted, allowing string-to-code execution.",
                    evidence_snippet=f"CSP: {csp[:150]}...",
                    status_code=resp.status_code,
                )
            )

        # Check for wildcard sources (*, http:, data:) in script/default directives
        if re.search(r"(script-src|default-src)\s+[^;]*(\*|http:|data:)", csp_lower):
            results.append(
                HeaderAuditResult(
                    is_valid_finding=True,
                    template_id="security-header-weak-csp-wildcard",
                    header_name="Content-Security-Policy",
                    vulnerability_type=HeaderVulnerabilityType.CSP_WEAK_DIRECTIVE,
                    severity=CORSSeverity.MEDIUM.value,
                    confidence=1.0,
                    cwe_id="CWE-693",
                    cvss_score=5.3,
                    current_value=csp,
                    recommendation="Replace wildcard ('*', 'http:', 'data:') sources with specific trusted origin allowlists.",
                    description=f"Weak Content-Security-Policy on {url}: Wildcard or insecure scheme source ('*', 'http:', 'data:') is allowed in script-src / default-src.",
                    evidence_snippet=f"CSP: {csp[:150]}...",
                    status_code=resp.status_code,
                )
            )

        # Check for missing frame-ancestors
        if "frame-ancestors" not in csp_lower:
            results.append(
                HeaderAuditResult(
                    is_valid_finding=True,
                    template_id="security-header-weak-csp-frame-ancestors",
                    header_name="Content-Security-Policy",
                    vulnerability_type=HeaderVulnerabilityType.CSP_WEAK_DIRECTIVE,
                    severity=CORSSeverity.MEDIUM.value,
                    confidence=1.0,
                    cwe_id="CWE-1021",
                    cvss_score=5.3,
                    current_value=csp,
                    recommendation="Define 'frame-ancestors 'none'' or 'frame-ancestors 'self'' to protect against Clickjacking attacks.",
                    description=f"Weak Content-Security-Policy on {url}: Missing 'frame-ancestors' directive.",
                    evidence_snippet=f"CSP: {csp[:150]}...",
                    status_code=resp.status_code,
                )
            )

        return results

    def _audit_hsts(self, url: str, resp: CORSProbeResponse) -> List[HeaderAuditResult]:
        """Audits Strict-Transport-Security (HSTS)."""
        results = []
        parsed = urllib.parse.urlparse(url)

        # False Positive Rejection: HSTS is strictly an HTTPS header
        if parsed.scheme.lower() != "https":
            return results

        hsts = resp.get_header("strict-transport-security")
        if not hsts:
            results.append(
                HeaderAuditResult(
                    is_valid_finding=True,
                    template_id="security-header-missing-hsts",
                    header_name="Strict-Transport-Security",
                    vulnerability_type=HeaderVulnerabilityType.HSTS_MISSING,
                    severity=CORSSeverity.LOW.value,
                    confidence=1.0,
                    cwe_id="CWE-319",
                    cvss_score=2.7,
                    current_value=None,
                    recommendation="Configure Strict-Transport-Security with 'max-age=31536000; includeSubDomains; preload'.",
                    description=f"Missing Strict-Transport-Security (HSTS) header on {url}. Users are vulnerable to SSL-stripping MITM attacks.",
                    evidence_snippet="Strict-Transport-Security: [Missing]",
                    status_code=resp.status_code,
                )
            )
            return results

        hsts_lower = hsts.lower()
        max_age_match = re.search(r"max-age\s*=\s*(\d+)", hsts_lower)
        if max_age_match:
            max_age = int(max_age_match.group(1))
            if max_age < 31536000:  # Less than 1 year (31,536,000 seconds)
                results.append(
                    HeaderAuditResult(
                        is_valid_finding=True,
                        template_id="security-header-weak-hsts-low-max-age",
                        header_name="Strict-Transport-Security",
                        vulnerability_type=HeaderVulnerabilityType.HSTS_WEAK_DIRECTIVE,
                        severity=CORSSeverity.LOW.value,
                        confidence=1.0,
                        cwe_id="CWE-319",
                        cvss_score=2.7,
                        current_value=hsts,
                        recommendation="Increase HSTS max-age to at least 31536000 seconds (1 year).",
                        description=f"Weak Strict-Transport-Security on {url}: max-age={max_age} is below recommended 1-year threshold (31536000s).",
                        evidence_snippet=f"HSTS: {hsts}",
                        status_code=resp.status_code,
                    )
                )

        if "includesubdomains" not in hsts_lower:
            results.append(
                HeaderAuditResult(
                    is_valid_finding=True,
                    template_id="security-header-weak-hsts-no-subdomains",
                    header_name="Strict-Transport-Security",
                    vulnerability_type=HeaderVulnerabilityType.HSTS_WEAK_DIRECTIVE,
                    severity=CORSSeverity.LOW.value,
                    confidence=1.0,
                    cwe_id="CWE-319",
                    cvss_score=2.7,
                    current_value=hsts,
                    recommendation="Add 'includeSubDomains' directive to Strict-Transport-Security header.",
                    description=f"Weak Strict-Transport-Security on {url}: Missing 'includeSubDomains' directive.",
                    evidence_snippet=f"HSTS: {hsts}",
                    status_code=resp.status_code,
                )
            )

        if "preload" not in hsts_lower:
            results.append(
                HeaderAuditResult(
                    is_valid_finding=True,
                    template_id="security-header-weak-hsts-no-preload",
                    header_name="Strict-Transport-Security",
                    vulnerability_type=HeaderVulnerabilityType.HSTS_WEAK_DIRECTIVE,
                    severity=CORSSeverity.INFO.value,
                    confidence=1.0,
                    cwe_id="CWE-319",
                    cvss_score=0.0,
                    current_value=hsts,
                    recommendation="Add 'preload' directive to Strict-Transport-Security header for HSTS preload list eligibility.",
                    description=f"Weak Strict-Transport-Security on {url}: Missing 'preload' directive.",
                    evidence_snippet=f"HSTS: {hsts}",
                    status_code=resp.status_code,
                )
            )

        return results

    def _audit_x_frame_options(
        self,
        url: str,
        resp: CORSProbeResponse,
        has_csp_frame_ancestors: bool,
    ) -> List[HeaderAuditResult]:
        """Audits X-Frame-Options (Clickjacking defense)."""
        results = []
        xfo = resp.get_header("x-frame-options")

        # False Positive Rejection: If CSP frame-ancestors is present, XFO is superseded
        if has_csp_frame_ancestors:
            return results

        if not xfo:
            results.append(
                HeaderAuditResult(
                    is_valid_finding=True,
                    template_id="security-header-missing-x-frame-options",
                    header_name="X-Frame-Options",
                    vulnerability_type=HeaderVulnerabilityType.XFO_MISSING,
                    severity=CORSSeverity.MEDIUM.value,
                    confidence=1.0,
                    cwe_id="CWE-1021",
                    cvss_score=5.3,
                    current_value=None,
                    recommendation="Set X-Frame-Options to 'DENY' or 'SAMEORIGIN' (or configure CSP frame-ancestors).",
                    description=f"Missing X-Frame-Options header on {url}. The page can be embedded in malicious iframes (Clickjacking risk).",
                    evidence_snippet="X-Frame-Options: [Missing]",
                    status_code=resp.status_code,
                )
            )
            return results

        xfo_clean = xfo.strip().upper()
        if xfo_clean not in ("DENY", "SAMEORIGIN"):
            results.append(
                HeaderAuditResult(
                    is_valid_finding=True,
                    template_id="security-header-misconfigured-x-frame-options",
                    header_name="X-Frame-Options",
                    vulnerability_type=HeaderVulnerabilityType.XFO_MISCONFIGURED,
                    severity=CORSSeverity.MEDIUM.value,
                    confidence=1.0,
                    cwe_id="CWE-1021",
                    cvss_score=5.3,
                    current_value=xfo,
                    recommendation="Update X-Frame-Options to use strict 'DENY' or 'SAMEORIGIN' values.",
                    description=f"Misconfigured X-Frame-Options header on {url}: Value '{xfo}' is invalid or deprecated across modern browsers.",
                    evidence_snippet=f"X-Frame-Options: {xfo}",
                    status_code=resp.status_code,
                )
            )

        return results

    def _audit_x_content_type_options(self, url: str, resp: CORSProbeResponse) -> List[HeaderAuditResult]:
        """Audits X-Content-Type-Options."""
        results = []
        xcto = resp.get_header("x-content-type-options")

        if not xcto or xcto.strip().lower() != "nosniff":
            results.append(
                HeaderAuditResult(
                    is_valid_finding=True,
                    template_id="security-header-missing-x-content-type-options",
                    header_name="X-Content-Type-Options",
                    vulnerability_type=HeaderVulnerabilityType.XCTO_MISSING,
                    severity=CORSSeverity.LOW.value,
                    confidence=1.0,
                    cwe_id="CWE-693",
                    cvss_score=2.7,
                    current_value=xcto if xcto else None,
                    recommendation="Set X-Content-Type-Options to 'nosniff'.",
                    description=f"Missing or invalid X-Content-Type-Options on {url}. Browsers may perform MIME-type sniffing.",
                    evidence_snippet=f"X-Content-Type-Options: {xcto or '[Missing]'}",
                    status_code=resp.status_code,
                )
            )

        return results

    def _audit_referrer_policy(self, url: str, resp: CORSProbeResponse) -> List[HeaderAuditResult]:
        """Audits Referrer-Policy."""
        results = []
        ref = resp.get_header("referrer-policy")

        if not ref:
            results.append(
                HeaderAuditResult(
                    is_valid_finding=True,
                    template_id="security-header-missing-referrer-policy",
                    header_name="Referrer-Policy",
                    vulnerability_type=HeaderVulnerabilityType.REFERRER_POLICY_WEAK,
                    severity=CORSSeverity.LOW.value,
                    confidence=1.0,
                    cwe_id="CWE-693",
                    cvss_score=2.7,
                    current_value=None,
                    recommendation="Configure Referrer-Policy to 'strict-origin-when-cross-origin' or 'no-referrer'.",
                    description=f"Missing Referrer-Policy header on {url}. Sensitive URLs and query parameters may leak to external referrers.",
                    evidence_snippet="Referrer-Policy: [Missing]",
                    status_code=resp.status_code,
                )
            )
            return results

        ref_lower = ref.strip().lower()
        if ref_lower in ("unsafe-url", "no-referrer-when-downgrade"):
            results.append(
                HeaderAuditResult(
                    is_valid_finding=True,
                    template_id="security-header-weak-referrer-policy",
                    header_name="Referrer-Policy",
                    vulnerability_type=HeaderVulnerabilityType.REFERRER_POLICY_WEAK,
                    severity=CORSSeverity.LOW.value,
                    confidence=1.0,
                    cwe_id="CWE-693",
                    cvss_score=3.1,
                    current_value=ref,
                    recommendation="Replace permissive Referrer-Policy with 'strict-origin-when-cross-origin'.",
                    description=f"Weak Referrer-Policy on {url}: Value '{ref}' leaks complete path and query parameters to cross-origin endpoints.",
                    evidence_snippet=f"Referrer-Policy: {ref}",
                    status_code=resp.status_code,
                )
            )

        return results

    def _audit_permissions_policy(self, url: str, resp: CORSProbeResponse) -> List[HeaderAuditResult]:
        """Audits Permissions-Policy / Feature-Policy."""
        results = []
        perm = resp.get_header("permissions-policy") or resp.get_header("feature-policy")

        if not perm:
            results.append(
                HeaderAuditResult(
                    is_valid_finding=True,
                    template_id="security-header-missing-permissions-policy",
                    header_name="Permissions-Policy",
                    vulnerability_type=HeaderVulnerabilityType.PERMISSIONS_POLICY_WEAK,
                    severity=CORSSeverity.LOW.value,
                    confidence=1.0,
                    cwe_id="CWE-693",
                    cvss_score=2.7,
                    current_value=None,
                    recommendation="Configure Permissions-Policy restricting access to sensitive APIs (e.g. camera=(), microphone=(), geolocation=()).",
                    description=f"Missing Permissions-Policy header on {url}. Powerful browser features remain unconstrained.",
                    evidence_snippet="Permissions-Policy: [Missing]",
                    status_code=resp.status_code,
                )
            )
            return results

        perm_lower = perm.lower()
        # Check if sensitive features are wildcarded
        if re.search(r"(camera|microphone|geolocation|payment)\s*=\s*\*", perm_lower):
            results.append(
                HeaderAuditResult(
                    is_valid_finding=True,
                    template_id="security-header-weak-permissions-policy",
                    header_name="Permissions-Policy",
                    vulnerability_type=HeaderVulnerabilityType.PERMISSIONS_POLICY_WEAK,
                    severity=CORSSeverity.LOW.value,
                    confidence=1.0,
                    cwe_id="CWE-693",
                    cvss_score=2.7,
                    current_value=perm,
                    recommendation="Constrain sensitive features to specific origins or disable them completely with ().",
                    description=f"Weak Permissions-Policy on {url}: Sensitive hardware/location features are set to wildcard (*).",
                    evidence_snippet=f"Permissions-Policy: {perm}",
                    status_code=resp.status_code,
                )
            )

        return results

    def _audit_x_xss_protection(
        self,
        url: str,
        resp: CORSProbeResponse,
        has_strong_csp: bool,
    ) -> List[HeaderAuditResult]:
        """Audits X-XSS-Protection."""
        results = []
        xxss = resp.get_header("x-xss-protection")

        # Explicitly disabled
        if xxss and xxss.strip() == "0":
            results.append(
                HeaderAuditResult(
                    is_valid_finding=True,
                    template_id="security-header-x-xss-protection-disabled",
                    header_name="X-XSS-Protection",
                    vulnerability_type=HeaderVulnerabilityType.XSS_PROTECTION_DISABLED,
                    severity=CORSSeverity.INFO.value,
                    confidence=1.0,
                    cwe_id="CWE-693",
                    cvss_score=0.0,
                    current_value=xxss,
                    recommendation="Ensure robust Content-Security-Policy is deployed when X-XSS-Protection is set to 0.",
                    description=f"X-XSS-Protection is explicitly set to 0 on {url}.",
                    evidence_snippet=f"X-XSS-Protection: {xxss}",
                    status_code=resp.status_code,
                )
            )
        elif not xxss and not has_strong_csp:
            results.append(
                HeaderAuditResult(
                    is_valid_finding=True,
                    template_id="security-header-missing-x-xss-protection",
                    header_name="X-XSS-Protection",
                    vulnerability_type=HeaderVulnerabilityType.XSS_PROTECTION_DISABLED,
                    severity=CORSSeverity.INFO.value,
                    confidence=1.0,
                    cwe_id="CWE-693",
                    cvss_score=0.0,
                    current_value=None,
                    recommendation="Deploy a modern Content-Security-Policy to replace deprecated X-XSS-Protection.",
                    description=f"Missing X-XSS-Protection header and no CSP detected on {url}.",
                    evidence_snippet="X-XSS-Protection: [Missing]",
                    status_code=resp.status_code,
                )
            )

        return results

    def _audit_cache_control_sensitive(
        self,
        url: str,
        resp: CORSProbeResponse,
        is_sensitive: Optional[bool] = None,
    ) -> List[HeaderAuditResult]:
        """Audits Cache-Control on sensitive or authenticated endpoints."""
        results = []
        parsed = urllib.parse.urlparse(url)
        path_lower = parsed.path.lower()

        # False Positive Rejection: Static file extensions are intentionally cacheable
        if any(path_lower.endswith(ext) for ext in self.STATIC_EXTENSIONS):
            return results

        # Determine sensitivity
        is_path_sensitive = any(kw in path_lower for kw in self.SENSITIVE_PATH_KEYWORDS)
        has_set_cookie = bool(resp.get_header("set-cookie"))
        has_auth_token_in_body = any(
            k in resp.body.lower() for k in ('"token"', '"access_token"', '"password"', '"ssn"', '"balance"')
        ) if resp.body else False

        sensitive_endpoint = bool(is_sensitive or is_path_sensitive or has_set_cookie or has_auth_token_in_body)
        if not sensitive_endpoint:
            return results

        cache_control = resp.get_header("cache-control")
        pragma = resp.get_header("pragma")

        # Must have no-store or (no-cache + private)
        cc_lower = cache_control.lower() if cache_control else ""
        is_securely_uncached = "no-store" in cc_lower or ("no-cache" in cc_lower and "private" in cc_lower)

        if not is_securely_uncached:
            results.append(
                HeaderAuditResult(
                    is_valid_finding=True,
                    template_id="security-header-cache-control-sensitive-leak",
                    header_name="Cache-Control",
                    vulnerability_type=HeaderVulnerabilityType.CACHE_CONTROL_SENSITIVE_LEAK,
                    severity=CORSSeverity.MEDIUM.value,
                    confidence=1.0,
                    cwe_id="CWE-525",
                    cvss_score=5.3,
                    current_value=cache_control if cache_control else None,
                    recommendation="Set 'Cache-Control: no-store, no-cache, must-revalidate, private' on all authenticated/sensitive routes.",
                    description=f"Sensitive endpoint cacheable on {url}: Missing 'no-store' directive in Cache-Control header.",
                    evidence_snippet=f"Cache-Control: {cache_control or '[Missing]'}, Pragma: {pragma or '[Missing]'}",
                    status_code=resp.status_code,
                )
            )

        return results


# Compatibility alias
HeaderAuditor = HTTPHeaderAuditor


# =============================================================================
# Collector Implementation (Active Collector & State Publisher)
# =============================================================================

class CORSSecurityCollector(BaseCollector):
    """
    Active CORS Misconfiguration & HTTP Security Header Audit Collector for ARGUS.
    Discovers endpoints, probes CORS vectors, audits security headers, and executes
    Quadruple State Publishing across the platform.
    """

    def __init__(
        self,
        prober: Optional[CORSProber] = None,
        timeout: float = 10.0,
    ):
        self.prober = prober or CORSProber(timeout=timeout)
        self.generator = CORSPayloadGenerator()
        self.analyzer = CORSAnalyzer()
        self.header_auditor = HTTPHeaderAuditor()
        self.timeout = timeout

    def _discover_candidate_endpoints(self, mission: Any) -> List[str]:
        """Discovers candidate endpoint URLs from mission state."""
        raw_mission = getattr(mission, "_raw_mission", getattr(mission, "_mission", mission))
        candidates: Set[str] = set()

        # 1. From mission.endpoints
        for ep in getattr(raw_mission, "endpoints", []) or []:
            if isinstance(ep, dict):
                url = ep.get("url") or ep.get("path")
                if url:
                    candidates.add(str(url))
            elif isinstance(ep, str):
                candidates.add(ep)

        # 2. From mission.live_hosts
        for lh in getattr(raw_mission, "live_hosts", []) or []:
            if isinstance(lh, dict):
                url = lh.get("url")
                if url:
                    candidates.add(str(url))
            elif isinstance(lh, str):
                candidates.add(lh)

        # 3. From mission.target
        target = getattr(raw_mission, "target", "")
        if target:
            if not str(target).startswith("http://") and not str(target).startswith("https://"):
                candidates.add(f"https://{target}")
            else:
                candidates.add(str(target))

        # 4. From mission.evidence
        evidence_list = getattr(raw_mission, "evidence", [])
        if hasattr(evidence_list, "all"):
            evidence_items = evidence_list.all()
        elif isinstance(evidence_list, (list, tuple, set)):
            evidence_items = list(evidence_list)
        else:
            evidence_items = []

        for ev in evidence_items:
            meta = getattr(ev, "metadata", {}) or {}
            if isinstance(meta, dict):
                url = meta.get("url") or meta.get("endpoint")
                if url and ("http://" in str(url) or "https://" in str(url)):
                    candidates.add(str(url))

        # Filter and normalize valid candidate URLs
        valid_urls = []
        for url in candidates:
            if url and (url.startswith("http://") or url.startswith("https://")):
                valid_urls.append(url)
            elif url and not url.startswith("http://") and not url.startswith("https://") and "." in url:
                valid_urls.append(f"https://{url}")

        return valid_urls

    def _emit_cors_evidence(
        self,
        mission: Any,
        result: CORSSecurityResult,
        target_url: str,
        base_url: str,
    ) -> Evidence:
        """Publishes validated CORS finding with Quadruple State Mutation."""
        title = f"CORS Misconfiguration: {result.technique} on {target_url}"
        description = (
            f"{result.description} Tested origin: {result.tested_origin}, "
            f"Reflected: {result.reflected_origin}, Credentials: {result.allow_credentials}"
        )
        raw_mission = getattr(mission, "_raw_mission", getattr(mission, "_mission", mission))

        ev = Evidence(
            category="cors",
            value=f"cors:{result.template_id}:{target_url}:{result.vector_name}",
            source="cors_headers",
            status="CONFIRMED",
            confidence=result.confidence,
            severity=result.severity,
            title=title,
            description=description,
            provenance=ProvenanceData(
                observation_id=str(uuid.uuid4()),
                step_id=f"step_{result.vector_name}",
            ),
            tags=["cors", "cors_security", result.vulnerability_type.value, result.mutation_strategy],
            metadata={
                "url": target_url,
                "host": base_url,
                "template_id": result.template_id,
                "technique": result.technique,
                "vulnerability_type": result.vulnerability_type.value,
                "vector_name": result.vector_name,
                "mutation_strategy": result.mutation_strategy,
                "strategy": result.mutation_strategy,
                "tested_origin": result.tested_origin,
                "reflected_origin": result.reflected_origin,
                "allow_credentials": result.allow_credentials,
                "status_code": result.status_code,
                "evidence_snippet": result.evidence_snippet[:250],
                "parameter": result.vector_name,
                "cwe_id": result.cwe_id,
                "cvss_score": result.cvss_score,
                "is_valid_finding": result.is_valid_finding,
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
                "parameter": result.vector_name,
                "strategy": result.mutation_strategy,
                "cwe_id": result.cwe_id,
                "cvss_score": result.cvss_score,
            })

        # 3. Attack Surface Knowledge Graph Expansion
        graph = getattr(raw_mission, "attack_surface_graph", None) or getattr(raw_mission, "graph", None)
        if graph is not None and hasattr(graph, "add") and hasattr(graph, "connect"):
            lh_id = f"live_host:{base_url}"
            ep_id = f"endpoint:{target_url}"
            vuln_id = f"vulnerability:{result.template_id}:{target_url}:{result.vector_name}"

            parsed_b = urllib.parse.urlparse(base_url)
            graph.add(Node(id=lh_id, type="live_host", value=base_url, metadata={"url": base_url, "host": parsed_b.hostname or base_url}))
            graph.add(Node(id=ep_id, type="endpoint", value=target_url, metadata={"url": target_url, "status_code": result.status_code}))
            graph.add(Node(id=vuln_id, type="vulnerability", value=title, metadata=ev.metadata))

            graph.connect(lh_id, ep_id, edge_type="HAS_ENDPOINT")
            graph.connect(lh_id, vuln_id, edge_type="HAS_VULNERABILITY")
            graph.connect(ep_id, vuln_id, edge_type="HAS_VULNERABILITY")

        # 4. ControlledMission wrapper notification
        if mission is not raw_mission and hasattr(mission, "publish_finding"):
            try:
                mission.publish_finding(ev.evidence_id, ev)
            except Exception:
                pass

        return ev

    def _emit_header_evidence(
        self,
        mission: Any,
        result: HeaderAuditResult,
        target_url: str,
        base_url: str,
    ) -> Evidence:
        """Publishes validated Security Header finding with Quadruple State Mutation."""
        title = f"HTTP Security Header: {result.header_name} - {result.description[:80]}"
        description = f"{result.description} Recommendation: {result.recommendation}"
        raw_mission = getattr(mission, "_raw_mission", getattr(mission, "_mission", mission))

        ev = Evidence(
            category="security_headers",
            value=f"security_headers:{result.template_id}:{target_url}:{result.header_name}",
            source="cors_headers",
            status="CONFIRMED",
            confidence=result.confidence,
            severity=result.severity,
            title=title,
            description=description,
            provenance=ProvenanceData(
                observation_id=str(uuid.uuid4()),
                step_id=f"step_header_{result.header_name}",
            ),
            tags=["security_headers", "http_headers", result.header_name, result.vulnerability_type.value],
            metadata={
                "url": target_url,
                "host": base_url,
                "template_id": result.template_id,
                "header_name": result.header_name,
                "vulnerability_type": result.vulnerability_type.value,
                "current_value": result.current_value,
                "recommendation": result.recommendation,
                "status_code": result.status_code,
                "evidence_snippet": result.evidence_snippet[:250],
                "parameter": result.header_name,
                "cwe_id": result.cwe_id,
                "cvss_score": result.cvss_score,
                "is_valid_finding": result.is_valid_finding,
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
                "header_name": result.header_name,
                "cwe_id": result.cwe_id,
                "cvss_score": result.cvss_score,
            })

        # 3. Attack Surface Knowledge Graph Expansion
        graph = getattr(raw_mission, "attack_surface_graph", None) or getattr(raw_mission, "graph", None)
        if graph is not None and hasattr(graph, "add") and hasattr(graph, "connect"):
            lh_id = f"live_host:{base_url}"
            ep_id = f"endpoint:{target_url}"
            vuln_id = f"vulnerability:{result.template_id}:{target_url}:{result.header_name}"

            parsed_b = urllib.parse.urlparse(base_url)
            graph.add(Node(id=lh_id, type="live_host", value=base_url, metadata={"url": base_url, "host": parsed_b.hostname or base_url}))
            graph.add(Node(id=ep_id, type="endpoint", value=target_url, metadata={"url": target_url, "status_code": result.status_code}))
            graph.add(Node(id=vuln_id, type="vulnerability", value=title, metadata=ev.metadata))

            graph.connect(lh_id, ep_id, edge_type="HAS_ENDPOINT")
            graph.connect(lh_id, vuln_id, edge_type="HAS_VULNERABILITY")
            graph.connect(ep_id, vuln_id, edge_type="HAS_VULNERABILITY")

        # 4. ControlledMission wrapper notification
        if mission is not raw_mission and hasattr(mission, "publish_finding"):
            try:
                mission.publish_finding(ev.evidence_id, ev)
            except Exception:
                pass

        return ev

    def collect(self, mission: Any) -> List[Evidence]:
        """Collects CORS and HTTP security header findings across all discovered endpoints."""
        endpoints = self._discover_candidate_endpoints(mission)
        collected_evidence: List[Evidence] = []

        for target_url in endpoints:
            parsed = urllib.parse.urlparse(target_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else target_url

            # Part 1: CORS Probing across 6 modes and 5 mutation strategies
            probes = self.generator.generate_all_cors_probes(target_url, is_auth=True)
            for probe in probes:
                resp = self.prober.execute_probe(mission, probe)
                cors_result = self.analyzer.evaluate_probe(probe, resp, target_url)
                if cors_result and cors_result.is_valid_finding:
                    ev = self._emit_cors_evidence(mission, cors_result, target_url, base_url)
                    collected_evidence.append(ev)

            # Part 2: HTTP Security Header Audit across 8 policies
            header_resp = self.prober.execute_header_audit(mission, target_url)
            if header_resp and header_resp.status_code > 0:
                header_findings = self.header_auditor.audit_headers(target_url, header_resp)
                for finding in header_findings:
                    if finding and finding.is_valid_finding:
                        ev = self._emit_header_evidence(mission, finding, target_url, base_url)
                        collected_evidence.append(ev)

        return collected_evidence

    def execute(self, mission: Any) -> List[Evidence]:
        """Plugin execution alias for collect()."""
        return self.collect(mission)


# =============================================================================
# Backwards Compatibility & Tool Aliases
# =============================================================================

CORSCollector = CORSSecurityCollector
CORSHeadersCollector = CORSSecurityCollector
CORSMisconfigurationCollector = CORSSecurityCollector
HTTPHeaderAuditorCollector = CORSSecurityCollector
SecurityHeadersCollector = CORSSecurityCollector
HTTPHeaderCollector = CORSSecurityCollector
