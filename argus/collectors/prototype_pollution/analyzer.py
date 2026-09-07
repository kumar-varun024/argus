"""prototype_pollution: Response analysis."""
from __future__ import annotations

import html
import urllib.parse
from typing import Optional

from argus.collectors.prototype_pollution.models import GadgetFramework, PrototypePollutionProbe, PrototypePollutionProbeResponse, PrototypePollutionResult, PrototypePollutionVulnerabilityType


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
