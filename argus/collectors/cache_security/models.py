"""cache_security: Data models, enums, and constants."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from argus.collectors.toolkit.enums import Severity


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

CacheSecurityMutationStrategy = CacheMutationStrategy

CacheMutationStrategy.DYNAMIC_CACHE_BUSTER = CacheMutationStrategy.DYNAMIC_CACHE_BUSTER_INSERTION  # type: ignore[attr-defined]

CacheMutationStrategy.PATH_DELIMITER = CacheMutationStrategy.PATH_DELIMITER_VARIATIONS  # type: ignore[attr-defined]

CacheMutationStrategy.NORMALIZATION_INVERSION = CacheMutationStrategy.REQUEST_NORMALIZATION_INVERSION  # type: ignore[attr-defined]

CacheMutationStrategy.HEADER_CLOAKING = CacheMutationStrategy.HEADER_PARAMETERIZATION_CLOAKING  # type: ignore[attr-defined]

CacheMutationStrategy.RULE_PROBE = CacheMutationStrategy.CACHE_RULE_PROBE_VARIATIONS  # type: ignore[attr-defined]

CacheSecuritySeverity = Severity

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

SENSITIVE_PII_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("email", re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')),
    ("jwt_token", re.compile(r'\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b')),
    ("api_key_json", re.compile(r'"(?:api[_-]?key|access[_-]?token|auth[_-]?token|secret|private[_-]?key|token)"\s*:\s*"[^"]{8,}"', re.IGNORECASE)),
    ("session_cookie", re.compile(r'(?:session[_-]?id|connect\.sid|PHPSESSID|JSESSIONID)["\s:=]+[a-zA-Z0-9_\-]{16,}', re.IGNORECASE)),
    ("credit_card", re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b')),
    ("user_credentials", re.compile(r'"(?:password|passwd|user_secret|pin)"\s*:\s*"[^"]+"', re.IGNORECASE)),
    ("user_profile_data", re.compile(r'"(?:first_name|last_name|ssn|dob|date_of_birth|phone_number|billing_address)"\s*:\s*"[^"]+"', re.IGNORECASE)),
]

_DEFAULT = object()
