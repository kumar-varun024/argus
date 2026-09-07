"""prototype_pollution: Data models, enums, and constants."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from argus.collectors.toolkit.enums import Severity


PrototypePollutionSeverity = Severity

ClientSideSeverity = PrototypePollutionSeverity

Severity = PrototypePollutionSeverity

PrototypePollutionSeverity.CRIT = PrototypePollutionSeverity.CRITICAL  # type: ignore[attr-defined]

class PrototypePollutionVulnerabilityType(str, Enum):
    """Enumeration of client-side and prototype pollution vulnerability detection modes."""
    SERVER_SIDE_PROTOTYPE_POLLUTION = "server_side_prototype_pollution"
    CLIENT_SIDE_PROTOTYPE_POLLUTION = "client_side_prototype_pollution"
    DOM_CLOBBERING = "dom_clobbering"
    OPEN_REDIRECT = "open_redirect"
    CLICKJACKING = "clickjacking"
    GADGET_POLLUTION = "gadget_pollution"
    DOS_POLLUTION = "dos_pollution"
    RCE_GADGET = "rce_gadget"

ClientSideVulnerabilityType = PrototypePollutionVulnerabilityType

PrototypePollutionTechnique = PrototypePollutionVulnerabilityType

ClientSideTechnique = PrototypePollutionVulnerabilityType

PrototypePollutionVulnerabilityType.SERVER_SIDE_PP = PrototypePollutionVulnerabilityType.SERVER_SIDE_PROTOTYPE_POLLUTION  # type: ignore[attr-defined]

PrototypePollutionVulnerabilityType.CLIENT_SIDE_PP = PrototypePollutionVulnerabilityType.CLIENT_SIDE_PROTOTYPE_POLLUTION  # type: ignore[attr-defined]

PrototypePollutionVulnerabilityType.HTML_CLOBBERING = PrototypePollutionVulnerabilityType.DOM_CLOBBERING  # type: ignore[attr-defined]

PrototypePollutionVulnerabilityType.OPEN_REDIRECT_CHAIN = PrototypePollutionVulnerabilityType.OPEN_REDIRECT  # type: ignore[attr-defined]

PrototypePollutionVulnerabilityType.UI_REDRESSING = PrototypePollutionVulnerabilityType.CLICKJACKING  # type: ignore[attr-defined]

class PrototypePollutionMutationStrategy(str, Enum):
    """Enumeration of probe mutation and evasion strategies."""
    JSON_KEY_ENCODING = "json_key_encoding"
    CONTENT_TYPE_MANIPULATION = "content_type_manipulation"
    REDIRECT_URL_ENCODING = "redirect_url_encoding"
    DOM_CLOBBERING_VARIANTS = "dom_clobbering_variants"
    FRAME_BUSTING_BYPASS = "frame_busting_bypass"
    STANDARD = "standard"

ClientSideMutationStrategy = PrototypePollutionMutationStrategy

PrototypePollutionStrategy = PrototypePollutionMutationStrategy

ClientSideStrategy = PrototypePollutionMutationStrategy

PrototypePollutionMutationStrategy.KEY_ENCODING = PrototypePollutionMutationStrategy.JSON_KEY_ENCODING  # type: ignore[attr-defined]

PrototypePollutionMutationStrategy.CONTENT_TYPE = PrototypePollutionMutationStrategy.CONTENT_TYPE_MANIPULATION  # type: ignore[attr-defined]

PrototypePollutionMutationStrategy.URL_ENCODING = PrototypePollutionMutationStrategy.REDIRECT_URL_ENCODING  # type: ignore[attr-defined]

PrototypePollutionMutationStrategy.CLOBBERING_VARIANT = PrototypePollutionMutationStrategy.DOM_CLOBBERING_VARIANTS  # type: ignore[attr-defined]

PrototypePollutionMutationStrategy.FRAME_BYPASS = PrototypePollutionMutationStrategy.FRAME_BUSTING_BYPASS  # type: ignore[attr-defined]

class GadgetFramework(str, Enum):
    """Enumeration of known framework targets for gadget pollution."""
    EXPRESS = "express"
    LODASH = "lodash"
    JQUERY = "jquery"
    HANDLEBARS = "handlebars"
    NODEJS_CHILD_PROCESS = "nodejs_child_process"
    GENERIC = "generic"

@dataclass
class PrototypePollutionProbe:
    """Represents a targeted probe for prototype pollution or client-side vulnerability analysis."""
    probe_id: str
    target_url: str
    method: str = "POST"
    vulnerability_type: PrototypePollutionVulnerabilityType = PrototypePollutionVulnerabilityType.SERVER_SIDE_PROTOTYPE_POLLUTION
    strategy: PrototypePollutionMutationStrategy = PrototypePollutionMutationStrategy.STANDARD
    headers: Dict[str, str] = field(default_factory=dict)
    params: Dict[str, Any] = field(default_factory=dict)
    json_data: Optional[Any] = None
    data: Optional[Any] = None
    content_type: str = "application/json"
    canary_property: str = ""
    canary_value: str = ""
    tested_parameter: str = ""
    framework_target: Optional[GadgetFramework] = None
    depth: int = 1
    is_benign_baseline: bool = False
    expected_redirect: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class PrototypePollutionProbeResponse:
    """Normalized response from HTTP probing execution."""
    probe: PrototypePollutionProbe
    status_code: int = 200
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    elapsed: float = 0.0
    success: bool = True
    error: Optional[str] = None
    url: str = ""
    redirect_history: List[str] = field(default_factory=list)
    side_effect_observed: bool = False
    polluted_properties: List[str] = field(default_factory=list)

@dataclass
class PrototypePollutionResult:
    """Evaluated vulnerability result produced by PrototypePollutionAnalyzer."""
    is_valid_finding: bool
    template_id: str
    vulnerability_type: PrototypePollutionVulnerabilityType
    technique: str
    severity: str
    confidence: float = 1.0
    cwe_id: str = "CWE-1321"
    cvss_score: float = 7.5
    parameter: str = ""
    mutation_strategy: str = ""
    gadget_framework: Optional[str] = None
    evidence_snippet: str = ""
    description: str = ""
    status_code: int = 200
    metadata: Dict[str, Any] = field(default_factory=dict)

ClientSideAttackResult = PrototypePollutionResult
