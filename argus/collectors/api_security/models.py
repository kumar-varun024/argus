"""api_security: Data models, enums, and constants."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Union

from argus.collectors.toolkit.enums import Severity
from argus.http.client import HttpResponse


APISecuritySeverity = Severity

APISeverity = APISecuritySeverity

APISecuritySeverity.CRIT = APISecuritySeverity.CRITICAL  # type: ignore[attr-defined]

class APIVulnerabilityType(str, Enum):
    """Enumeration of API vulnerability types and detection modes."""
    PARAMETER_TAMPERING = "parameter_tampering"
    MASS_ASSIGNMENT = "mass_assignment"
    RATE_LIMITING_BYPASS = "rate_limiting_bypass"
    BOLA_IDOR = "bola_idor"
    EXCESSIVE_DATA_EXPOSURE = "excessive_data_exposure"
    METHOD_TAMPERING = "method_tampering"
    ERROR_INFO_DISCLOSURE = "error_info_disclosure"

APISecurityTechnique = APIVulnerabilityType

APIVulnerabilityType.BOLA = APIVulnerabilityType.BOLA_IDOR  # type: ignore[attr-defined]

APIVulnerabilityType.IDOR = APIVulnerabilityType.BOLA_IDOR  # type: ignore[attr-defined]

APIVulnerabilityType.RATE_LIMIT = APIVulnerabilityType.RATE_LIMITING_BYPASS  # type: ignore[attr-defined]

APIVulnerabilityType.RATE_LIMITING = APIVulnerabilityType.RATE_LIMITING_BYPASS  # type: ignore[attr-defined]

APIVulnerabilityType.DATA_EXPOSURE = APIVulnerabilityType.EXCESSIVE_DATA_EXPOSURE  # type: ignore[attr-defined]

class APIMutationStrategy(str, Enum):
    """Enumeration of API evasion and mutation strategies."""
    CONTENT_TYPE_SWITCHING = "content_type_switching"
    PARAMETER_POLLUTION = "parameter_pollution"
    HEADER_AUTH_BYPASS = "header_auth_bypass"
    VERSION_DOWNGRADE = "version_downgrade"
    ENCODING_VARIATIONS = "encoding_variations"
    STANDARD = "standard"

APISecurityMutationStrategy = APIMutationStrategy

@dataclass
class APIProbe:
    """Represents a targeted API security validation probe attempt."""
    probe_id: str
    target_url: str
    method: str = "GET"
    vulnerability_type: Union[APIVulnerabilityType, str] = APIVulnerabilityType.PARAMETER_TAMPERING
    strategy: Union[APIMutationStrategy, str] = APIMutationStrategy.STANDARD
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
class APIProbeResponse:
    """Captures the response outcome and metadata from an API probe execution."""
    probe: APIProbe
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
class APISecurityResult:
    """Represents an evaluated and confirmed API security finding."""
    template_id: str
    technique: str
    vulnerability_type: Union[APIVulnerabilityType, str]
    mutation_strategy: str
    endpoint_url: str
    severity: str
    cwe_id: str
    cvss_score: float
    description: str
    evidence_snippet: str
    parameter: Optional[str] = None
    status_code: int = 200
    confidence: float = 0.95
    is_valid_finding: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)
