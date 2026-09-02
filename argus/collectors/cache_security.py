"""
Web Cache Poisoning & Cache Deception Detection Engine and Collector for ARGUS.

Actively discovers and validates Web Cache Poisoning (unkeyed headers, unkeyed query parameters,
parameter cloaking, FAT GET request bodies, method overrides, duplicate header folding) and
Web Cache Deception (path extensions, delimiter discrepancies, static file caching of authenticated PII)
across reverse proxies, CDNs (Cloudflare, CloudFront, Akamai, Fastly), web caches (Varnish, Nginx,
Apache Traffic Server), and application servers using AuthenticatedHttpClient, differential confirmation
probers, and heuristic CDN fingerprinting.

Key Capabilities:
1. Multi-Vector Detection Modes:
   - Unkeyed Header Poisoning (X-Forwarded-Host, X-Forwarded-Scheme, X-Original-URL, Forwarded, etc.)
   - Unkeyed Query Parameter Poisoning & Parameter Cloaking (utm_*, fbclid, callback, ?, ;, %26, %23)
   - Web Cache Deception (Static extension manipulation .css/.js/.png, delimiter matrix ;, %0A, %00, ..;/)
   - Cache Key Normalization Flaws (FAT GET request bodies, method override headers, duplicate headers)
   - Cache Lifecycle & CDN Engine Fingerprinting (CF-Cache-Status, X-Cache, X-Varnish, Age, Cache-Control)
2. Mutation & Evasion Strategies:
   - Dynamic Cache Buster Insertion (query string nonces, timestamp/UUID nonces)
   - Path Delimiter Variations (;, ..;/, %2e%2e%2f, #, %00, %0A)
   - Request Normalization Inversion (header/path casing, selective percent-encoding)
   - Header Parameterization & Cloaking (duplicate headers, comma separation, tab indirection)
   - Cache Rule Probe Variations (static extension matrix expansion, Accept header manipulation)
3. 4-Step Differential Confirmation Sequence:
   - Step 1: Baseline measurement (Nonce B0)
   - Step 2: Perturbation probe (Nonce B1)
   - Step 3: Replay verification probe without poisoning headers (Nonce B1)
   - Step 4: Isolation control probe (Nonce B2)
4. Strict False Positive Rejection:
   - Suppresses uncached reflections, unreflected headers, non-sensitive static assets,
     global dynamic echoes, and WAF rate limits.
5. Quadruple State Publishing:
   - Updates raw_mission.evidence, raw_mission.vulnerabilities, attack_surface_graph (HAS_VULNERABILITY),
     and ControlledMission.publish_finding.
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

class CacheVulnerabilityType(str, Enum):
    """Enumeration of web cache vulnerability vector types."""
    UNKEYED_HEADER_POISONING = "unkeyed_header_poisoning"
    UNKEYED_PARAM_POISONING = "unkeyed_param_poisoning"
    PARAMETER_CLOAKING = "parameter_cloaking"
    WEB_CACHE_DECEPTION = "web_cache_deception"
    CACHE_KEY_NORMALIZATION = "cache_key_normalization"
    FAT_GET_POISONING = "fat_get_poisoning"
    METHOD_OVERRIDE_POISONING = "method_override_poisoning"
    CACHE_LIFECYCLE_FINGERPRINT = "cache_lifecycle_fingerprint"


# Backwards compatibility aliases
CacheSecurityTechnique = CacheVulnerabilityType
CacheVulnerabilityType.UNKEYED_HEADER = CacheVulnerabilityType.UNKEYED_HEADER_POISONING  # type: ignore[attr-defined]
CacheVulnerabilityType.UNKEYED_PARAM = CacheVulnerabilityType.UNKEYED_PARAM_POISONING  # type: ignore[attr-defined]
CacheVulnerabilityType.CACHE_DECEPTION = CacheVulnerabilityType.WEB_CACHE_DECEPTION  # type: ignore[attr-defined]
CacheVulnerabilityType.FAT_GET = CacheVulnerabilityType.FAT_GET_POISONING  # type: ignore[attr-defined]
CacheVulnerabilityType.METHOD_OVERRIDE = CacheVulnerabilityType.METHOD_OVERRIDE_POISONING  # type: ignore[attr-defined]


class CacheEngineFamily(str, Enum):
    """Enumeration of supported CDN and reverse proxy cache engines."""
    CLOUDFLARE = "cloudflare"
    CLOUDFRONT = "cloudfront"
    AKAMAI = "akamai"
    FASTLY = "fastly"
    VARNISH = "varnish"
    NGINX = "nginx"
    APACHE_TRAFFIC_SERVER = "ats"
    GENERIC = "generic"


# Engine alias
CacheEngine = CacheEngineFamily


class CacheStatus(str, Enum):
    """Normalized cache lifecycle status."""
    HIT = "hit"
    MISS = "miss"
    BYPASS = "bypass"
    DYNAMIC = "dynamic"
    EXPIRED = "expired"
    STALE = "stale"
    UNKNOWN = "unknown"


class CacheMutationStrategy(str, Enum):
    """Enumeration of cache bypass and key perturbation strategies."""
    DYNAMIC_CACHE_BUSTER_INSERTION = "dynamic_cache_buster_insertion"
    PATH_DELIMITER_VARIATIONS = "path_delimiter_variations"
    REQUEST_NORMALIZATION_INVERSION = "request_normalization_inversion"
    HEADER_PARAMETERIZATION_CLOAKING = "header_parameterization_cloaking"
    CACHE_RULE_PROBE_VARIATIONS = "cache_rule_probe_variations"


# Alias
CacheSecurityMutationStrategy = CacheMutationStrategy
CacheMutationStrategy.DYNAMIC_CACHE_BUSTER = CacheMutationStrategy.DYNAMIC_CACHE_BUSTER_INSERTION  # type: ignore[attr-defined]
CacheMutationStrategy.PATH_DELIMITER = CacheMutationStrategy.PATH_DELIMITER_VARIATIONS  # type: ignore[attr-defined]
CacheMutationStrategy.NORMALIZATION_INVERSION = CacheMutationStrategy.REQUEST_NORMALIZATION_INVERSION  # type: ignore[attr-defined]
CacheMutationStrategy.HEADER_CLOAKING = CacheMutationStrategy.HEADER_PARAMETERIZATION_CLOAKING  # type: ignore[attr-defined]
CacheMutationStrategy.RULE_PROBE = CacheMutationStrategy.CACHE_RULE_PROBE_VARIATIONS  # type: ignore[attr-defined]


class CacheSecuritySeverity(str, Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# Compatibility alias
Severity = CacheSecuritySeverity


@dataclass
class CacheProbe:
    """Structure representing a single cache security test probe."""
    probe_id: str
    target_url: str
    vulnerability_type: CacheVulnerabilityType
    strategy: CacheMutationStrategy
    headers: Dict[str, str] = field(default_factory=dict)
    params: Dict[str, str] = field(default_factory=dict)
    path_suffix: str = ""
    method: str = "GET"
    body: Optional[str] = None
    canary: str = ""
    vector_name: str = ""
    payload_value: str = ""
    is_auth_required: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CacheProbeResponse:
    """Detailed response metadata captured from a cache probe."""
    probe: CacheProbe
    status_code: int
    headers: Dict[str, str]
    body: str
    raw_body: str
    elapsed: float
    cache_status: CacheStatus
    engine: CacheEngineFamily
    age: Optional[int] = None
    canary_in_body: bool = False
    canary_in_headers: bool = False
    pii_detected: bool = False
    pii_matches: List[str] = field(default_factory=list)
    location_header: Optional[str] = None


@dataclass
class CacheSecurityResult:
    """Confirmed cache vulnerability result data structure."""
    vulnerability_type: CacheVulnerabilityType
    engine: CacheEngineFamily
    strategy: CacheMutationStrategy
    severity: str
    confidence: float
    endpoint_url: str
    vector_name: str
    payload_value: str
    reflected_snippet: str
    cache_headers: Dict[str, str]
    status_code: int
    cwe_id: str
    cvss_score: float
    is_valid_finding: bool
    metadata: Dict[str, Any] = field(default_factory=dict)

    # Convenience properties for backwards compatibility & graph wiring
    @property
    def technique(self) -> str:
        return self.vulnerability_type.value if hasattr(self.vulnerability_type, "value") else str(self.vulnerability_type)

    @property
    def template_id(self) -> str:
        if self.vulnerability_type == CacheVulnerabilityType.WEB_CACHE_DECEPTION:
            return "web-cache-deception"
        return "web-cache-poisoning"

    @property
    def parameter(self) -> str:
        return self.vector_name

    @property
    def evidence_snippet(self) -> str:
        return self.reflected_snippet

    @property
    def mutation_strategy(self) -> str:
        return self.strategy.value if hasattr(self.strategy, "value") else str(self.strategy)

    @property
    def cache_engine(self) -> str:
        return self.engine.value if hasattr(self.engine, "value") else str(self.engine)

    @property
    def cache_status_header(self) -> str:
        return self.cache_headers.get("x-cache") or self.cache_headers.get("cf-cache-status") or "HIT"

    @property
    def payload(self) -> str:
        return self.payload_value

    @property
    def cache_buster(self) -> str:
        return self.metadata.get("cache_buster", "")


# =============================================================================
# Sensitive PII & Regex Catalogs
# =============================================================================

SENSITIVE_PII_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("email", re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')),
    ("jwt_token", re.compile(r'\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b')),
    ("api_key_json", re.compile(r'"(?:api[_-]?key|access[_-]?token|auth[_-]?token|secret|private[_-]?key|token)"\s*:\s*"[^"]{8,}"', re.IGNORECASE)),
    ("session_cookie", re.compile(r'(?:session[_-]?id|connect\.sid|PHPSESSID|JSESSIONID)["\s:=]+[a-zA-Z0-9_\-]{16,}', re.IGNORECASE)),
    ("credit_card", re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b')),
    ("user_credentials", re.compile(r'"(?:password|passwd|user_secret|pin)"\s*:\s*"[^"]+"', re.IGNORECASE)),
    ("user_profile_data", re.compile(r'"(?:first_name|last_name|ssn|dob|date_of_birth|phone_number|billing_address)"\s*:\s*"[^"]+"', re.IGNORECASE)),
]


# =============================================================================
# Payload Generator
# =============================================================================

class CacheSecurityPayloadGenerator:
    """
    Generates tailored payload vectors and applies mutation strategies
    for Web Cache Poisoning and Web Cache Deception auditing.
    """

    UNKEYED_HEADERS = [
        "X-Forwarded-Host",
        "X-Forwarded-Scheme",
        "X-Forwarded-Proto",
        "X-Original-URL",
        "X-Rewrite-URL",
        "X-Host",
        "Forwarded",
        "X-Forwarded-Prefix",
        "X-Forwarded-Port",
        "X-HTTP-Host-Override",
        "Base-Url",
    ]

    UNKEYED_PARAMS = [
        "utm_source",
        "utm_content",
        "utm_campaign",
        "utm_medium",
        "fbclid",
        "gclid",
        "_ga",
        "callback",
        "cb",
        "jsonp",
    ]

    WCD_EXTENSIONS = [
        ".css",
        ".js",
        ".png",
        ".svg",
        ".json",
        ".ico",
        ".woff2",
        ".avif",
        ".webp",
    ]

    WCD_DELIMITERS = [
        "/nonexistent.css",
        ";test.js",
        "/test.css",
        "%0A.css",
        "%00.js",
        "%23.css",
        "..;/static/style.css",
        "%2e%2e%2fstyle.css",
    ]

    def __init__(self, canary_domain_suffix: str = "argus-security.local"):
        self.canary_domain_suffix = canary_domain_suffix

    def generate_canary(self, prefix: str = "canary") -> str:
        """Generates a randomized canary token."""
        rand_str = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
        return f"{prefix}_{rand_str}"

    def build_unkeyed_header_probes(self, base_url: str, canary: Optional[str] = None) -> List[CacheProbe]:
        """Builds probes for unkeyed header injection."""
        token = canary or self.generate_canary("wcp_hdr")
        canary_host = f"{token}.{self.canary_domain_suffix}"
        probes: List[CacheProbe] = []

        # 1. X-Forwarded-Host
        probes.append(CacheProbe(
            probe_id=f"hdr_xfh_{token}",
            target_url=base_url,
            vulnerability_type=CacheVulnerabilityType.UNKEYED_HEADER_POISONING,
            strategy=CacheMutationStrategy.DYNAMIC_CACHE_BUSTER_INSERTION,
            headers={"X-Forwarded-Host": canary_host},
            canary=token,
            vector_name="X-Forwarded-Host",
            payload_value=canary_host,
        ))

        # 2. X-Forwarded-Scheme
        probes.append(CacheProbe(
            probe_id=f"hdr_xfs_{token}",
            target_url=base_url,
            vulnerability_type=CacheVulnerabilityType.UNKEYED_HEADER_POISONING,
            strategy=CacheMutationStrategy.DYNAMIC_CACHE_BUSTER_INSERTION,
            headers={"X-Forwarded-Scheme": "http"},
            canary="http://",
            vector_name="X-Forwarded-Scheme",
            payload_value="http",
        ))

        # 3. X-Forwarded-Proto
        probes.append(CacheProbe(
            probe_id=f"hdr_xfp_{token}",
            target_url=base_url,
            vulnerability_type=CacheVulnerabilityType.UNKEYED_HEADER_POISONING,
            strategy=CacheMutationStrategy.DYNAMIC_CACHE_BUSTER_INSERTION,
            headers={"X-Forwarded-Proto": "http"},
            canary="http://",
            vector_name="X-Forwarded-Proto",
            payload_value="http",
        ))

        # 4. X-Original-URL
        probes.append(CacheProbe(
            probe_id=f"hdr_xou_{token}",
            target_url=base_url,
            vulnerability_type=CacheVulnerabilityType.UNKEYED_HEADER_POISONING,
            strategy=CacheMutationStrategy.DYNAMIC_CACHE_BUSTER_INSERTION,
            headers={"X-Original-URL": f"/{token}_path"},
            canary=f"{token}_path",
            vector_name="X-Original-URL",
            payload_value=f"/{token}_path",
        ))

        # 5. X-Rewrite-URL
        probes.append(CacheProbe(
            probe_id=f"hdr_xru_{token}",
            target_url=base_url,
            vulnerability_type=CacheVulnerabilityType.UNKEYED_HEADER_POISONING,
            strategy=CacheMutationStrategy.DYNAMIC_CACHE_BUSTER_INSERTION,
            headers={"X-Rewrite-URL": f"/{token}_rewrite"},
            canary=f"{token}_rewrite",
            vector_name="X-Rewrite-URL",
            payload_value=f"/{token}_rewrite",
        ))

        # 6. X-Host
        probes.append(CacheProbe(
            probe_id=f"hdr_xh_{token}",
            target_url=base_url,
            vulnerability_type=CacheVulnerabilityType.UNKEYED_HEADER_POISONING,
            strategy=CacheMutationStrategy.DYNAMIC_CACHE_BUSTER_INSERTION,
            headers={"X-Host": canary_host},
            canary=token,
            vector_name="X-Host",
            payload_value=canary_host,
        ))

        # 7. Forwarded (RFC 7239)
        probes.append(CacheProbe(
            probe_id=f"hdr_fwd_{token}",
            target_url=base_url,
            vulnerability_type=CacheVulnerabilityType.UNKEYED_HEADER_POISONING,
            strategy=CacheMutationStrategy.DYNAMIC_CACHE_BUSTER_INSERTION,
            headers={"Forwarded": f"host={canary_host};proto=http"},
            canary=token,
            vector_name="Forwarded",
            payload_value=f"host={canary_host};proto=http",
        ))

        # 8. X-Forwarded-Prefix
        probes.append(CacheProbe(
            probe_id=f"hdr_xfprefix_{token}",
            target_url=base_url,
            vulnerability_type=CacheVulnerabilityType.UNKEYED_HEADER_POISONING,
            strategy=CacheMutationStrategy.DYNAMIC_CACHE_BUSTER_INSERTION,
            headers={"X-Forwarded-Prefix": f"//{canary_host}"},
            canary=token,
            vector_name="X-Forwarded-Prefix",
            payload_value=f"//{canary_host}",
        ))

        # 9. X-Forwarded-Port
        probes.append(CacheProbe(
            probe_id=f"hdr_xfport_{token}",
            target_url=base_url,
            vulnerability_type=CacheVulnerabilityType.UNKEYED_HEADER_POISONING,
            strategy=CacheMutationStrategy.DYNAMIC_CACHE_BUSTER_INSERTION,
            headers={"X-Forwarded-Port": "1337"},
            canary=":1337",
            vector_name="X-Forwarded-Port",
            payload_value="1337",
        ))

        # 10. X-HTTP-Host-Override
        probes.append(CacheProbe(
            probe_id=f"hdr_xhho_{token}",
            target_url=base_url,
            vulnerability_type=CacheVulnerabilityType.UNKEYED_HEADER_POISONING,
            strategy=CacheMutationStrategy.DYNAMIC_CACHE_BUSTER_INSERTION,
            headers={"X-HTTP-Host-Override": canary_host},
            canary=token,
            vector_name="X-HTTP-Host-Override",
            payload_value=canary_host,
        ))

        # 11. Base-Url
        probes.append(CacheProbe(
            probe_id=f"hdr_baseurl_{token}",
            target_url=base_url,
            vulnerability_type=CacheVulnerabilityType.UNKEYED_HEADER_POISONING,
            strategy=CacheMutationStrategy.DYNAMIC_CACHE_BUSTER_INSERTION,
            headers={"Base-Url": f"https://{canary_host}/"},
            canary=token,
            vector_name="Base-Url",
            payload_value=f"https://{canary_host}/",
        ))

        return probes

    def build_unkeyed_param_probes(self, base_url: str, canary: Optional[str] = None) -> List[CacheProbe]:
        """Builds probes for unkeyed query parameters and parameter cloaking."""
        token = canary or self.generate_canary("wcp_param")
        probes: List[CacheProbe] = []

        # 1. Standard unkeyed query parameters
        for param in ["utm_content", "utm_source", "fbclid", "gclid", "_ga"]:
            probes.append(CacheProbe(
                probe_id=f"param_{param}_{token}",
                target_url=base_url,
                vulnerability_type=CacheVulnerabilityType.UNKEYED_PARAM_POISONING,
                strategy=CacheMutationStrategy.DYNAMIC_CACHE_BUSTER_INSERTION,
                params={param: token},
                canary=token,
                vector_name=param,
                payload_value=token,
            ))

        # 2. Unkeyed JSONP callbacks
        for jsonp_param in ["callback", "cb", "jsonp"]:
            probes.append(CacheProbe(
                probe_id=f"jsonp_{jsonp_param}_{token}",
                target_url=base_url,
                vulnerability_type=CacheVulnerabilityType.UNKEYED_PARAM_POISONING,
                strategy=CacheMutationStrategy.DYNAMIC_CACHE_BUSTER_INSERTION,
                params={jsonp_param: f"alert_{token}"},
                canary=f"alert_{token}",
                vector_name=jsonp_param,
                payload_value=f"alert_{token}",
            ))

        # 3. Parameter Cloaking: Semicolon Delimiter (?k=1;u=2)
        probes.append(CacheProbe(
            probe_id=f"cloak_semi_{token}",
            target_url=base_url,
            vulnerability_type=CacheVulnerabilityType.PARAMETER_CLOAKING,
            strategy=CacheMutationStrategy.HEADER_PARAMETERIZATION_CLOAKING,
            params={"k": f"1;utm_content={token}"},
            canary=token,
            vector_name="parameter_cloaking_semicolon",
            payload_value=f"k=1;utm_content={token}",
        ))

        # 4. Parameter Cloaking: Double Question Mark (?k=1?u=2)
        probes.append(CacheProbe(
            probe_id=f"cloak_qmark_{token}",
            target_url=base_url,
            vulnerability_type=CacheVulnerabilityType.PARAMETER_CLOAKING,
            strategy=CacheMutationStrategy.HEADER_PARAMETERIZATION_CLOAKING,
            params={"k": f"1?utm_content={token}"},
            canary=token,
            vector_name="parameter_cloaking_qmark",
            payload_value=f"k=1?utm_content={token}",
        ))

        # 5. Parameter Cloaking: URL-encoded Delimiter (%26)
        probes.append(CacheProbe(
            probe_id=f"cloak_encamp_{token}",
            target_url=base_url,
            vulnerability_type=CacheVulnerabilityType.PARAMETER_CLOAKING,
            strategy=CacheMutationStrategy.REQUEST_NORMALIZATION_INVERSION,
            params={"k": f"1%26utm_content={token}"},
            canary=token,
            vector_name="parameter_cloaking_encoded_amp",
            payload_value=f"k=1%26utm_content={token}",
        ))

        # 6. Parameter Cloaking: Hash Delimiter (%23)
        probes.append(CacheProbe(
            probe_id=f"cloak_hash_{token}",
            target_url=base_url,
            vulnerability_type=CacheVulnerabilityType.PARAMETER_CLOAKING,
            strategy=CacheMutationStrategy.PATH_DELIMITER_VARIATIONS,
            params={"utm_content": f"{token}%23k=1"},
            canary=token,
            vector_name="parameter_cloaking_hash",
            payload_value=f"utm_content={token}%23k=1",
        ))

        # 7. HTTP Parameter Pollution (HPP)
        probes.append(CacheProbe(
            probe_id=f"cloak_hpp_{token}",
            target_url=base_url,
            vulnerability_type=CacheVulnerabilityType.PARAMETER_CLOAKING,
            strategy=CacheMutationStrategy.HEADER_PARAMETERIZATION_CLOAKING,
            params={"p": "clean", "p_canary": token},
            canary=token,
            vector_name="http_parameter_pollution",
            payload_value=f"p=clean&p={token}",
            metadata={"hpp_param": "p", "hpp_canary": token},
        ))

        return probes

    def build_cache_deception_probes(self, base_url: str, is_auth: bool = True) -> List[CacheProbe]:
        """Builds probes for Web Cache Deception (path extensions and delimiter variations)."""
        probes: List[CacheProbe] = []

        # Standard static extension variations
        for ext in self.WCD_EXTENSIONS:
            suffix = f"/nonexistent{ext}"
            probes.append(CacheProbe(
                probe_id=f"wcd_ext_{ext.strip('.')}",
                target_url=base_url,
                vulnerability_type=CacheVulnerabilityType.WEB_CACHE_DECEPTION,
                strategy=CacheMutationStrategy.CACHE_RULE_PROBE_VARIATIONS,
                path_suffix=suffix,
                vector_name=f"wcd_extension_{ext}",
                payload_value=suffix,
                is_auth_required=is_auth,
                metadata={"extension": ext},
            ))

        # Delimiter matrix probes
        for delim in self.WCD_DELIMITERS:
            clean_name = delim.replace("/", "_").replace(".", "_").replace(";", "_").replace("%", "_")
            probes.append(CacheProbe(
                probe_id=f"wcd_delim_{clean_name}",
                target_url=base_url,
                vulnerability_type=CacheVulnerabilityType.WEB_CACHE_DECEPTION,
                strategy=CacheMutationStrategy.PATH_DELIMITER_VARIATIONS,
                path_suffix=delim,
                vector_name=f"wcd_delimiter_{delim}",
                payload_value=delim,
                is_auth_required=is_auth,
                metadata={"delimiter": delim},
            ))

        return probes

    def build_normalization_flaw_probes(self, base_url: str, canary: Optional[str] = None) -> List[CacheProbe]:
        """Builds probes for cache key normalization flaws (FAT GET, method override, folded headers)."""
        token = canary or self.generate_canary("norm_canary")
        probes: List[CacheProbe] = []

        # 1. FAT GET: Form URL-encoded body
        probes.append(CacheProbe(
            probe_id=f"fat_get_form_{token}",
            target_url=base_url,
            vulnerability_type=CacheVulnerabilityType.FAT_GET_POISONING,
            strategy=CacheMutationStrategy.REQUEST_NORMALIZATION_INVERSION,
            method="GET",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=f"utm_content={token}&x=1",
            canary=token,
            vector_name="FAT_GET_urlencoded",
            payload_value=f"utm_content={token}&x=1",
        ))

        # 2. FAT GET: JSON body
        probes.append(CacheProbe(
            probe_id=f"fat_get_json_{token}",
            target_url=base_url,
            vulnerability_type=CacheVulnerabilityType.FAT_GET_POISONING,
            strategy=CacheMutationStrategy.REQUEST_NORMALIZATION_INVERSION,
            method="GET",
            headers={"Content-Type": "application/json"},
            body=json.dumps({"canary": token, "utm_source": token}),
            canary=token,
            vector_name="FAT_GET_json",
            payload_value=json.dumps({"canary": token}),
        ))

        # 3. Method Override: X-HTTP-Method-Override
        probes.append(CacheProbe(
            probe_id=f"method_override_xhmo_{token}",
            target_url=base_url,
            vulnerability_type=CacheVulnerabilityType.METHOD_OVERRIDE_POISONING,
            strategy=CacheMutationStrategy.REQUEST_NORMALIZATION_INVERSION,
            method="GET",
            headers={"X-HTTP-Method-Override": "POST", "Content-Type": "application/json"},
            body=json.dumps({"override_token": token}),
            canary=token,
            vector_name="X-HTTP-Method-Override",
            payload_value="POST",
        ))

        # 4. Method Override: X-Method-Override
        probes.append(CacheProbe(
            probe_id=f"method_override_xmo_{token}",
            target_url=base_url,
            vulnerability_type=CacheVulnerabilityType.METHOD_OVERRIDE_POISONING,
            strategy=CacheMutationStrategy.REQUEST_NORMALIZATION_INVERSION,
            method="GET",
            headers={"X-Method-Override": "POST"},
            canary="POST",
            vector_name="X-Method-Override",
            payload_value="POST",
        ))

        # 5. Method Override: _method query parameter
        probes.append(CacheProbe(
            probe_id=f"method_override_param_{token}",
            target_url=base_url,
            vulnerability_type=CacheVulnerabilityType.METHOD_OVERRIDE_POISONING,
            strategy=CacheMutationStrategy.REQUEST_NORMALIZATION_INVERSION,
            params={"_method": "POST"},
            canary=token,
            vector_name="_method_param",
            payload_value="POST",
        ))

        # 6. Duplicate folded headers: X-Forwarded-Host
        canary_host = f"{token}.{self.canary_domain_suffix}"
        probes.append(CacheProbe(
            probe_id=f"dup_header_xfh_{token}",
            target_url=base_url,
            vulnerability_type=CacheVulnerabilityType.UNKEYED_HEADER_POISONING,
            strategy=CacheMutationStrategy.HEADER_PARAMETERIZATION_CLOAKING,
            headers={"X-Forwarded-Host": f"legitimate.local, {canary_host}"},
            canary=token,
            vector_name="duplicate_folded_X-Forwarded-Host",
            payload_value=f"legitimate.local, {canary_host}",
        ))

        return probes

    def apply_mutation(self, probe: CacheProbe, strategy: CacheMutationStrategy) -> CacheProbe:
        """Applies a specific mutation strategy to an existing probe."""
        mutated = copy.deepcopy(probe)
        mutated.strategy = strategy

        if strategy == CacheMutationStrategy.DYNAMIC_CACHE_BUSTER_INSERTION:
            nonce = uuid.uuid4().hex[:10]
            mutated.params["__argus_cb"] = nonce
            mutated.headers["X-Argus-Buster"] = nonce

        elif strategy == CacheMutationStrategy.PATH_DELIMITER_VARIATIONS:
            if not mutated.path_suffix:
                mutated.path_suffix = ";argus=1.css"
            elif not mutated.path_suffix.startswith(";"):
                mutated.path_suffix = f";{mutated.path_suffix.lstrip('/')}"

        elif strategy == CacheMutationStrategy.REQUEST_NORMALIZATION_INVERSION:
            # Invert header name casing and path casing
            new_headers = {}
            for k, v in mutated.headers.items():
                new_headers[k.upper() if random.random() > 0.5 else k.lower()] = v
            mutated.headers = new_headers

        elif strategy == CacheMutationStrategy.HEADER_PARAMETERIZATION_CLOAKING:
            # Add tab indirection or comma chaining to headers
            new_headers = {}
            for k, v in mutated.headers.items():
                new_headers[k] = f"{v};version=1"
            mutated.headers = new_headers

        elif strategy == CacheMutationStrategy.CACHE_RULE_PROBE_VARIATIONS:
            mutated.headers["Accept"] = "text/css,*/*;q=0.1"

        return mutated

    def generate_all_probes(self, base_url: str, canary: Optional[str] = None, is_auth: bool = False) -> List[CacheProbe]:
        """Generates all multi-vector probes for a target URL."""
        probes: List[CacheProbe] = []
        probes.extend(self.build_unkeyed_header_probes(base_url, canary))
        probes.extend(self.build_unkeyed_param_probes(base_url, canary))
        probes.extend(self.build_cache_deception_probes(base_url, is_auth=is_auth))
        probes.extend(self.build_normalization_flaw_probes(base_url, canary))
        return probes


# =============================================================================
# Differential Prober
# =============================================================================

_DEFAULT = object()


class CacheSecurityProber:
    """
    Executes sequential differential cache verification requests
    (Baseline B0 -> Perturbation B1 -> Replay B1 -> Isolation Control B2).
    """

    def __init__(self, http_client: Optional[Any] = None, timeout: float = 10.0):
        self.http_client = http_client
        self.timeout = timeout

    def generate_nonce(self, prefix: str = "cb") -> str:
        """Generates a randomized cache buster nonce."""
        return f"{prefix}_{int(time.time()*1000)}_{uuid.uuid4().hex[:8]}"

    def _prepare_url_with_nonce(self, base_url: str, nonce: str, path_suffix: str = "", extra_params: Optional[Dict[str, str]] = None) -> str:
        """Constructs target URL appending path suffix and cache buster nonces."""
        parsed = urllib.parse.urlparse(base_url)
        path = parsed.path
        if path_suffix:
            if path_suffix.startswith("/") and path.endswith("/"):
                path = path[:-1] + path_suffix
            elif not path_suffix.startswith("/") and not path_suffix.startswith(";") and not path.endswith("/"):
                path = path + "/" + path_suffix
            else:
                path = path + path_suffix

        # Query parameters
        existing_params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        query_dict = dict(existing_params)
        query_dict["cb"] = nonce
        if extra_params:
            query_dict.update(extra_params)

        new_query = urllib.parse.urlencode(query_dict)
        return urllib.parse.urlunparse((
            parsed.scheme,
            parsed.netloc,
            path,
            parsed.params,
            new_query,
            parsed.fragment,
        ))

    def send_probe_request(
        self,
        url: str,
        probe: CacheProbe,
        headers: Any = _DEFAULT,
        body: Any = _DEFAULT,
        method: Any = _DEFAULT,
        auth_identity: Optional[Any] = None,
    ) -> CacheProbeResponse:
        """Dispatches an HTTP request and converts the response to a CacheProbeResponse."""
        effective_method = (probe.method if method is _DEFAULT else (method or "GET")).upper()
        effective_headers = dict(probe.headers if headers is _DEFAULT else (headers or {}))
        effective_body = probe.body if body is _DEFAULT else body

        start_time = time.time()
        status_code = 0
        resp_headers: Dict[str, str] = {}
        resp_body = ""
        raw_body = ""

        try:
            if self.http_client is not None:
                # Use provided client (mock or custom)
                if hasattr(self.http_client, "request"):
                    res = self.http_client.request(effective_method, url, headers=effective_headers, data=effective_body, timeout=self.timeout)
                elif effective_method == "POST" and hasattr(self.http_client, "post"):
                    res = self.http_client.post(url, headers=effective_headers, data=effective_body, timeout=self.timeout)
                elif hasattr(self.http_client, "get"):
                    res = self.http_client.get(url, headers=effective_headers, timeout=self.timeout)
                else:
                    res = None

                if res is not None:
                    status_code = getattr(res, "status_code", 200) or 200
                    resp_headers = {k.lower(): str(v) for k, v in getattr(res, "headers", {}).items()}
                    resp_body = getattr(res, "body", "") or getattr(res, "text", "") or ""
                    raw_body = getattr(res, "raw_body", "") or resp_body
            else:
                # Use AuthenticatedHttpClient
                with AuthenticatedHttpClient(timeout=self.timeout) as client:
                    if effective_method == "POST":
                        res = client.post(url, headers=effective_headers, data=effective_body, identity=auth_identity)
                    else:
                        res = client.get(url, headers=effective_headers, identity=auth_identity)

                    if res is not None:
                        status_code = res.status_code or 0
                        resp_headers = {k.lower(): str(v) for k, v in (res.headers or {}).items()}
                        resp_body = res.body or ""
                        raw_body = res.raw_body or resp_body
        except Exception as e:
            logger.debug("CacheSecurityProber request exception for %s: %s", url, e)

        elapsed = time.time() - start_time

        # Analyze cache status and engine
        status, engine, age = CacheSecurityAnalyzer.analyze_cache_lifecycle(resp_headers)

        # Check canary presence
        canary_in_body = False
        canary_in_headers = False
        if probe.canary:
            canary_in_body = probe.canary in resp_body or probe.canary in raw_body
            canary_in_headers = any(probe.canary in v for v in resp_headers.values())

        # Check PII presence
        pii_detected, pii_matches = CacheSecurityAnalyzer.detect_pii(raw_body or resp_body)

        location_header = resp_headers.get("location")

        return CacheProbeResponse(
            probe=probe,
            status_code=status_code,
            headers=resp_headers,
            body=resp_body,
            raw_body=raw_body,
            elapsed=elapsed,
            cache_status=status,
            engine=engine,
            age=age,
            canary_in_body=canary_in_body,
            canary_in_headers=canary_in_headers,
            pii_detected=pii_detected,
            pii_matches=pii_matches,
            location_header=location_header,
        )

    def execute_differential_sequence(
        self,
        base_url: str,
        probe: CacheProbe,
        baseline_nonce: Optional[str] = None,
        probe_nonce: Optional[str] = None,
        control_nonce: Optional[str] = None,
        auth_identity: Optional[Any] = None,
    ) -> Dict[str, CacheProbeResponse]:
        """
        Executes the 4-step differential confirmation sequence:
        1. Baseline: Clean request with Nonce B0
        2. Perturbation: Injected probe request with Nonce B1
        3. Replay: Clean request (no poison headers / unauth) with Nonce B1
        4. Isolation Control: Clean request with Nonce B2
        """
        b0 = baseline_nonce or self.generate_nonce("b0")
        b1 = probe_nonce or self.generate_nonce("b1")
        b2 = control_nonce or self.generate_nonce("b2")

        # Step 1: Baseline measurement (Nonce B0)
        url_b0 = self._prepare_url_with_nonce(base_url, b0)
        resp_b0 = self.send_probe_request(
            url=url_b0,
            probe=probe,
            headers={},
            body=None,
            method="GET",
            auth_identity=auth_identity if probe.is_auth_required else None,
        )

        # Step 2: Perturbation probe (Nonce B1)
        url_b1 = self._prepare_url_with_nonce(base_url, b1, path_suffix=probe.path_suffix, extra_params=probe.params)
        resp_b1 = self.send_probe_request(
            url=url_b1,
            probe=probe,
            headers=probe.headers,
            body=probe.body,
            method=probe.method,
            auth_identity=auth_identity if probe.is_auth_required else None,
        )

        # Step 3: Replay verification probe without poisoning headers (Nonce B1)
        # For WCD, replay is done WITHOUT authentication to test unauthenticated cache exposure!
        url_replay = self._prepare_url_with_nonce(base_url, b1, path_suffix=probe.path_suffix if probe.vulnerability_type == CacheVulnerabilityType.WEB_CACHE_DECEPTION else "")
        resp_replay = self.send_probe_request(
            url=url_replay,
            probe=probe,
            headers={},
            body=None,
            method="GET",
            auth_identity=None,  # Unauthenticated victim replay
        )

        # Step 4: Isolation control probe (Nonce B2)
        url_b2 = self._prepare_url_with_nonce(base_url, b2)
        resp_b2 = self.send_probe_request(
            url=url_b2,
            probe=probe,
            headers={},
            body=None,
            method="GET",
            auth_identity=None,
        )

        return {
            "baseline": resp_b0,
            "perturbed": resp_b1,
            "replay": resp_replay,
            "control": resp_b2,
        }


# =============================================================================
# Security Analyzer & False Positive Suppression
# =============================================================================

class CacheSecurityAnalyzer:
    """
    Evaluates HTTP responses, parses cache lifecycles, fingerprints CDN engines,
    and applies strict false positive suppression rules.
    """

    @staticmethod
    def analyze_cache_lifecycle(headers: Dict[str, str]) -> Tuple[CacheStatus, CacheEngineFamily, Optional[int]]:
        """
        Parses response headers to determine CacheStatus, CacheEngineFamily, and Age integer.
        """
        h = {k.lower(): str(v) for k, v in headers.items()}

        # 1. Age header parsing
        age_val: Optional[int] = None
        if "age" in h:
            try:
                age_val = int(h["age"].strip())
            except (ValueError, TypeError):
                age_val = None

        # 2. CDN & Engine Fingerprinting
        engine = CacheEngineFamily.GENERIC
        server = h.get("server", "").lower()
        via = h.get("via", "").lower()

        if "cf-cache-status" in h or "cf-ray" in h or "cloudflare" in server:
            engine = CacheEngineFamily.CLOUDFLARE
        elif "x-amz-cf-id" in h or "x-amz-cf-pop" in h or "cloudfront" in via or "cloudfront" in h.get("x-cache", "").lower():
            engine = CacheEngineFamily.CLOUDFRONT
        elif "x-akamai-request-id" in h or "x-check-cacheable" in h or "akamaighost" in server:
            engine = CacheEngineFamily.AKAMAI
        elif "x-served-by" in h or "x-timer" in h or "fastly" in via:
            engine = CacheEngineFamily.FASTLY
        elif "x-varnish" in h or "varnish" in via or "varnish" in server:
            engine = CacheEngineFamily.VARNISH
        elif "nginx" in server or "x-cache-status" in h:
            engine = CacheEngineFamily.NGINX
        elif "ats" in server or "apachetrafficserver" in via or "ats" in h.get("x-cache", "").lower():
            engine = CacheEngineFamily.APACHE_TRAFFIC_SERVER

        # 3. Cache Status Evaluation
        status = CacheStatus.UNKNOWN

        # Cloudflare CF-Cache-Status
        if "cf-cache-status" in h:
            cf_stat = h["cf-cache-status"].strip().upper()
            if cf_stat in ("HIT", "STALE", "REVALIDATED", "UPDATING"):
                status = CacheStatus.HIT
            elif cf_stat in ("MISS", "EXPIRED"):
                status = CacheStatus.MISS
            elif cf_stat in ("BYPASS", "DYNAMIC"):
                status = CacheStatus.BYPASS
            else:
                status = CacheStatus.UNKNOWN

        # X-Cache (CloudFront, Squid, ATS, Custom Nginx)
        elif "x-cache" in h:
            xc = h["x-cache"].strip().upper()
            if "HIT" in xc or "TCP_HIT" in xc or "TCP_REFRESH_HIT" in xc:
                status = CacheStatus.HIT
            elif "MISS" in xc or "TCP_MISS" in xc:
                status = CacheStatus.MISS
            elif "BYPASS" in xc:
                status = CacheStatus.BYPASS

        # X-Cache-Status (Nginx)
        elif "x-cache-status" in h:
            xcs = h["x-cache-status"].strip().upper()
            if xcs in ("HIT", "REVALIDATED", "UPDATING"):
                status = CacheStatus.HIT
            elif xcs in ("MISS", "EXPIRED"):
                status = CacheStatus.MISS
            elif xcs in ("BYPASS",):
                status = CacheStatus.BYPASS

        # X-Varnish (Varnish returns two IDs on hit, e.g. "12345 67890")
        elif "x-varnish" in h:
            parts = h["x-varnish"].strip().split()
            if len(parts) >= 2:
                status = CacheStatus.HIT
            else:
                status = CacheStatus.MISS

        # Monotonic Age progression fallback
        if status == CacheStatus.UNKNOWN:
            if age_val is not None and age_val > 0:
                status = CacheStatus.HIT
            elif "cache-control" in h:
                cc = h["cache-control"].lower()
                if "no-store" in cc or "private" in cc:
                    status = CacheStatus.BYPASS
                elif "public" in cc or "max-age" in cc or "s-maxage" in cc:
                    status = CacheStatus.MISS

        return status, engine, age_val

    @staticmethod
    def detect_pii(content: str) -> Tuple[bool, List[str]]:
        """Scans content for sensitive tokens and user credentials."""
        if not content:
            return False, []
        matches: List[str] = []
        for label, pattern in SENSITIVE_PII_PATTERNS:
            found = pattern.findall(content)
            if found:
                matches.append(f"{label}:{len(found)}")
        return len(matches) > 0, matches

    @classmethod
    def evaluate_unkeyed_header_poisoning(
        cls,
        responses: Dict[str, CacheProbeResponse],
        probe: CacheProbe,
    ) -> Optional[CacheSecurityResult]:
        """Evaluates differential responses for Unkeyed Header Poisoning."""
        baseline = responses.get("baseline")
        perturbed = responses.get("perturbed")
        replay = responses.get("replay")
        control = responses.get("control")

        if not baseline or not perturbed or not replay or not control:
            return None

        # False Positive Filter 1: WAF rate limit or server error on perturbed
        if perturbed.status_code in (429, 403, 503):
            return None

        # False Positive Filter 2: Injected canary was not reflected or did not alter redirect
        canary = probe.canary
        canary_reflected_perturbed = (
            perturbed.canary_in_body
            or perturbed.canary_in_headers
            or (perturbed.location_header and canary in perturbed.location_header)
        )
        if not canary_reflected_perturbed:
            return None

        # False Positive Filter 3: Uncached reflection (Replay is MISS or does not contain canary)
        canary_persisted_replay = (
            replay.canary_in_body
            or replay.canary_in_headers
            or (replay.location_header and canary in replay.location_header)
        )
        is_cached_hit = (
            replay.cache_status == CacheStatus.HIT
            or (replay.age is not None and replay.age > 0)
            or (baseline.age is not None and replay.age is not None and replay.age >= baseline.age)
        )

        if not (canary_persisted_replay and is_cached_hit):
            return None

        # False Positive Filter 4: Global Dynamic Reflection (Canary appears in fresh control request B2)
        canary_in_control = (
            control.canary_in_body
            or control.canary_in_headers
            or (control.location_header and canary in control.location_header)
        )
        if canary_in_control:
            return None

        # Confirmed finding
        snippet = replay.raw_body[:250] if replay.canary_in_body else str(replay.headers)[:250]
        severity = CacheSecuritySeverity.CRITICAL.value if "Host" in probe.vector_name or "Prefix" in probe.vector_name or "Original-URL" in probe.vector_name else CacheSecuritySeverity.HIGH.value
        cvss_score = 9.8 if severity == CacheSecuritySeverity.CRITICAL.value else 8.2

        return CacheSecurityResult(
            vulnerability_type=CacheVulnerabilityType.UNKEYED_HEADER_POISONING,
            engine=replay.engine,
            strategy=probe.strategy,
            severity=severity,
            confidence=1.0,
            endpoint_url=probe.target_url,
            vector_name=probe.vector_name,
            payload_value=probe.payload_value,
            reflected_snippet=snippet,
            cache_headers=replay.headers,
            status_code=replay.status_code,
            cwe_id="CWE-444",
            cvss_score=cvss_score,
            is_valid_finding=True,
            metadata={
                "vector_type": "unkeyed_header",
                "canary": probe.canary,
                "replay_cache_status": replay.cache_status.value,
                "engine": replay.engine.value,
                "age": replay.age,
            },
        )

    @classmethod
    def evaluate_unkeyed_param_poisoning(
        cls,
        responses: Dict[str, CacheProbeResponse],
        probe: CacheProbe,
    ) -> Optional[CacheSecurityResult]:
        """Evaluates differential responses for Unkeyed Query Parameters and Parameter Cloaking."""
        baseline = responses.get("baseline")
        perturbed = responses.get("perturbed")
        replay = responses.get("replay")
        control = responses.get("control")

        if not baseline or not perturbed or not replay or not control:
            return None

        if perturbed.status_code in (429, 403, 503):
            return None

        canary = probe.canary
        canary_reflected_perturbed = perturbed.canary_in_body or perturbed.canary_in_headers
        if not canary_reflected_perturbed:
            return None

        canary_persisted_replay = replay.canary_in_body or replay.canary_in_headers
        is_cached_hit = (
            replay.cache_status == CacheStatus.HIT
            or (replay.age is not None and replay.age > 0)
        )

        if not (canary_persisted_replay and is_cached_hit):
            return None

        # Reject global dynamic echo
        if control.canary_in_body or control.canary_in_headers:
            return None

        snippet = replay.raw_body[:250]
        is_cloaking = probe.vulnerability_type == CacheVulnerabilityType.PARAMETER_CLOAKING
        vuln_type = CacheVulnerabilityType.PARAMETER_CLOAKING if is_cloaking else CacheVulnerabilityType.UNKEYED_PARAM_POISONING
        severity = CacheSecuritySeverity.HIGH.value
        cvss_score = 8.2

        return CacheSecurityResult(
            vulnerability_type=vuln_type,
            engine=replay.engine,
            strategy=probe.strategy,
            severity=severity,
            confidence=1.0,
            endpoint_url=probe.target_url,
            vector_name=probe.vector_name,
            payload_value=probe.payload_value,
            reflected_snippet=snippet,
            cache_headers=replay.headers,
            status_code=replay.status_code,
            cwe_id="CWE-444",
            cvss_score=cvss_score,
            is_valid_finding=True,
            metadata={
                "vector_type": "unkeyed_param",
                "canary": probe.canary,
                "replay_cache_status": replay.cache_status.value,
                "engine": replay.engine.value,
            },
        )

    @classmethod
    def evaluate_web_cache_deception(
        cls,
        responses: Dict[str, CacheProbeResponse],
        probe: CacheProbe,
    ) -> Optional[CacheSecurityResult]:
        """Evaluates differential responses for Web Cache Deception."""
        baseline = responses.get("baseline")
        perturbed = responses.get("perturbed")
        replay = responses.get("replay")
        control = responses.get("control")

        if not baseline or not perturbed or not replay or not control:
            return None

        # Rejection Filter 1: Must succeed on perturbed and replay
        if perturbed.status_code != 200 or replay.status_code != 200:
            return None

        # Rejection Filter 2: Public static asset with NO sensitive data
        # If perturbed or replay has no sensitive PII/tokens, reject false positive!
        if not (perturbed.pii_detected and replay.pii_detected):
            return None

        # Rejection Filter 3: Unauthenticated replay must be cached (HIT)
        is_cached_hit = (
            replay.cache_status == CacheStatus.HIT
            or (replay.age is not None and replay.age > 0)
        )
        if not is_cached_hit:
            return None

        # Rejection Filter 4: If unauthenticated control also returns PII, the endpoint is public (not an authenticated leak)
        if control.pii_detected:
            return None

        snippet = replay.raw_body[:250]
        severity = CacheSecuritySeverity.HIGH.value
        cvss_score = 8.5

        return CacheSecurityResult(
            vulnerability_type=CacheVulnerabilityType.WEB_CACHE_DECEPTION,
            engine=replay.engine,
            strategy=probe.strategy,
            severity=severity,
            confidence=1.0,
            endpoint_url=probe.target_url,
            vector_name=probe.vector_name,
            payload_value=probe.payload_value,
            reflected_snippet=snippet,
            cache_headers=replay.headers,
            status_code=replay.status_code,
            cwe_id="CWE-524",
            cvss_score=cvss_score,
            is_valid_finding=True,
            metadata={
                "vector_type": "web_cache_deception",
                "pii_matches": replay.pii_matches,
                "replay_cache_status": replay.cache_status.value,
                "engine": replay.engine.value,
            },
        )

    @classmethod
    def evaluate_normalization_flaws(
        cls,
        responses: Dict[str, CacheProbeResponse],
        probe: CacheProbe,
    ) -> Optional[CacheSecurityResult]:
        """Evaluates differential responses for FAT GET and Method Override normalization flaws."""
        baseline = responses.get("baseline")
        perturbed = responses.get("perturbed")
        replay = responses.get("replay")
        control = responses.get("control")

        if not baseline or not perturbed or not replay or not control:
            return None

        if perturbed.status_code in (429, 403, 503):
            return None

        canary = probe.canary
        canary_reflected_perturbed = perturbed.canary_in_body or perturbed.canary_in_headers
        if not canary_reflected_perturbed:
            return None

        canary_persisted_replay = replay.canary_in_body or replay.canary_in_headers
        is_cached_hit = (
            replay.cache_status == CacheStatus.HIT
            or (replay.age is not None and replay.age > 0)
        )

        if not (canary_persisted_replay and is_cached_hit):
            return None

        if control.canary_in_body or control.canary_in_headers:
            return None

        snippet = replay.raw_body[:250]
        severity = CacheSecuritySeverity.HIGH.value
        cvss_score = 8.2

        return CacheSecurityResult(
            vulnerability_type=probe.vulnerability_type,
            engine=replay.engine,
            strategy=probe.strategy,
            severity=severity,
            confidence=1.0,
            endpoint_url=probe.target_url,
            vector_name=probe.vector_name,
            payload_value=probe.payload_value,
            reflected_snippet=snippet,
            cache_headers=replay.headers,
            status_code=replay.status_code,
            cwe_id="CWE-444",
            cvss_score=cvss_score,
            is_valid_finding=True,
            metadata={
                "vector_type": "normalization_flaw",
                "canary": probe.canary,
                "replay_cache_status": replay.cache_status.value,
                "engine": replay.engine.value,
            },
        )


# =============================================================================
# Collector Implementation
# =============================================================================

class CacheSecurityCollector(BaseCollector):
    """
    Active Web Cache Poisoning and Web Cache Deception Collector for ARGUS.
    """

    def __init__(self, prober: Optional[CacheSecurityProber] = None, timeout: float = 10.0):
        self.prober = prober or CacheSecurityProber(timeout=timeout)
        self.generator = CacheSecurityPayloadGenerator()
        self.analyzer = CacheSecurityAnalyzer()

    def _discover_candidate_endpoints(self, mission: Any) -> List[str]:
        """Discovers candidate URLs from mission state."""
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
            if not target.startswith("http://") and not target.startswith("https://"):
                candidates.add(f"https://{target}")
            else:
                candidates.add(target)

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

        return list(candidates)

    def _emit_evidence(
        self,
        mission: Any,
        result: CacheSecurityResult,
        target_url: str,
        base_url: str,
    ) -> Evidence:
        """Publishes confirmed vulnerability evidence with Quadruple State Mutation."""
        title = f"Web Cache Security: {result.vector_name} on {target_url}"
        description = (
            f"Confirmed {result.vulnerability_type.value} via strategy {result.strategy.value}. "
            f"Reflected snippet: {result.reflected_snippet[:200]}"
        )
        raw_mission = getattr(mission, "_raw_mission", getattr(mission, "_mission", mission))

        ev = Evidence(
            category="cache_security",
            value=f"cache_security:{result.template_id}:{target_url}:{result.vector_name}",
            source="cache_security",
            status="CONFIRMED",
            confidence=result.confidence,
            severity=result.severity,
            title=title,
            description=description,
            provenance=ProvenanceData(
                observation_id=str(uuid.uuid4()),
                step_id=f"step_{result.vector_name}",
            ),
            tags=["cache_security", result.vulnerability_type.value, result.engine.value],
            metadata={
                "url": target_url,
                "host": base_url,
                "template_id": result.template_id,
                "technique": result.technique,
                "vulnerability_type": result.technique,
                "mutation_strategy": result.mutation_strategy,
                "strategy": result.mutation_strategy,
                "cache_engine": result.cache_engine,
                "engine": result.cache_engine,
                "cache_status_header": result.cache_status_header,
                "status_code": result.status_code,
                "evidence_snippet": result.reflected_snippet[:250],
                "payload": str(result.payload)[:300],
                "parameter": result.vector_name,
                "cwe_id": result.cwe_id,
                "cvss_score": result.cvss_score,
                "cache_buster": result.cache_buster,
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
                "cache_engine": result.cache_engine,
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

    def collect(self, mission: Any) -> List[Evidence]:
        """Collects web cache security findings across all candidate endpoints."""
        endpoints = self._discover_candidate_endpoints(mission)
        collected_evidence: List[Evidence] = []

        for target_url in endpoints:
            parsed = urllib.parse.urlparse(target_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else target_url

            # Generate probes
            probes = self.generator.generate_all_probes(target_url, is_auth=True)

            for probe in probes:
                responses = self.prober.execute_differential_sequence(target_url, probe)
                result: Optional[CacheSecurityResult] = None

                if probe.vulnerability_type == CacheVulnerabilityType.UNKEYED_HEADER_POISONING:
                    result = self.analyzer.evaluate_unkeyed_header_poisoning(responses, probe)
                elif probe.vulnerability_type in (CacheVulnerabilityType.UNKEYED_PARAM_POISONING, CacheVulnerabilityType.PARAMETER_CLOAKING):
                    result = self.analyzer.evaluate_unkeyed_param_poisoning(responses, probe)
                elif probe.vulnerability_type == CacheVulnerabilityType.WEB_CACHE_DECEPTION:
                    result = self.analyzer.evaluate_web_cache_deception(responses, probe)
                elif probe.vulnerability_type in (CacheVulnerabilityType.FAT_GET_POISONING, CacheVulnerabilityType.METHOD_OVERRIDE_POISONING):
                    result = self.analyzer.evaluate_normalization_flaws(responses, probe)

                if result and result.is_valid_finding:
                    ev = self._emit_evidence(mission, result, target_url, base_url)
                    collected_evidence.append(ev)

        return collected_evidence

    def execute(self, mission: Any) -> List[Evidence]:
        """Plugin execution alias for collect()."""
        return self.collect(mission)


# Backwards compatibility aliases
WebCachePoisoningCollector = CacheSecurityCollector
CachePoisoningCollector = CacheSecurityCollector
WebCacheDeceptionCollector = CacheSecurityCollector
