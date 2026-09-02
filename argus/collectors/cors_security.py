from __future__ import annotations

import logging
import urllib.parse
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Union

from argus.collectors.base import BaseCollector
from argus.evidence.model import Evidence, ProvenanceData
from argus.graph.node import Node
from argus.http.client import AuthenticatedHttpClient, HttpResponse

logger = logging.getLogger(__name__)

# =============================================================================
# Enums & Data Models
# =============================================================================

class CORSVulnerabilityType(str, Enum):
    ORIGIN_REFLECTION = "origin_reflection"
    NULL_ORIGIN = "null_origin"
    WILDCARD_CREDENTIALS = "wildcard_credentials"
    SUBDOMAIN_TRUST_ABUSE = "subdomain_trust_abuse"
    PREFLIGHT_BYPASS = "preflight_bypass"
    ORIGIN_PARSER_DIFFERENTIAL = "origin_parser_differential"

class HeaderVulnerabilityType(str, Enum):
    MISSING_CSP = "missing_csp"
    WEAK_CSP = "weak_csp"
    MISSING_HSTS = "missing_hsts"
    WEAK_HSTS = "weak_hsts"
    MISSING_X_FRAME_OPTIONS = "missing_x_frame_options"
    MISSING_X_CONTENT_TYPE_OPTIONS = "missing_x_content_type_options"
    MISSING_REFERRER_POLICY = "missing_referrer_policy"
    WEAK_REFERRER_POLICY = "weak_referrer_policy"
    MISSING_PERMISSIONS_POLICY = "missing_permissions_policy"
    DISABLED_XSS_PROTECTION = "disabled_xss_protection"
    MISSING_CACHE_CONTROL = "missing_cache_control"

class CORSMutationStrategy(str, Enum):
    ORIGIN_CASING = "origin_casing"
    PROTOCOL_SMUGGLING = "protocol_smuggling"
    SUBDOMAIN_INJECTION = "subdomain_injection"
    HEADER_DUPLICATION = "header_duplication"
    PREFLIGHT_ENUMERATION = "preflight_enumeration"

@dataclass
class CORSProbe:
    target_url: str
    vulnerability_type: CORSVulnerabilityType
    strategy: CORSMutationStrategy
    origin_value: str
    headers: Dict[str, str] = field(default_factory=dict)
    method: str = "GET"
    metadata: Dict[str, Any] = field(default_factory=dict)
    probe_id: str = field(default_factory=lambda: str(uuid.uuid4()))

@dataclass
class CORSProbeResponse:
    probe: CORSProbe
    status_code: int
    headers: Dict[str, str]
    body: str
    elapsed: float
    acao_value: Optional[str] = None
    acac_value: Optional[str] = None
    acao_methods: Optional[str] = None
    acao_headers: Optional[str] = None

@dataclass
class CORSSecurityResult:
    vulnerability_type: CORSVulnerabilityType
    strategy: CORSMutationStrategy
    severity: str
    confidence: str
    endpoint_url: str
    origin_tested: str
    reflected_origin: str
    cwe_id: str
    cvss_score: float
    is_valid_finding: bool
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class HeaderAuditResult:
    vulnerability_type: HeaderVulnerabilityType
    severity: str
    confidence: str
    endpoint_url: str
    header_name: str
    header_value: Optional[str]
    recommendation: str
    cwe_id: str
    cvss_score: float
    is_valid_finding: bool
    metadata: Dict[str, Any] = field(default_factory=dict)


# =============================================================================
# Payloads & Generation
# =============================================================================

class CORSPayloadGenerator:
    def __init__(self):
        pass

    def apply_mutation(self, probe: CORSProbe, strategy: CORSMutationStrategy) -> CORSProbe:
        mutated_probe = CORSProbe(
            target_url=probe.target_url,
            vulnerability_type=probe.vulnerability_type,
            strategy=strategy,
            origin_value=probe.origin_value,
            headers=dict(probe.headers),
            method=probe.method,
            metadata=dict(probe.metadata)
        )

        if strategy == CORSMutationStrategy.ORIGIN_CASING:
            mutated_probe.origin_value = mutated_probe.origin_value.upper()
        elif strategy == CORSMutationStrategy.PROTOCOL_SMUGGLING:
            if mutated_probe.origin_value.startswith("https://"):
                mutated_probe.origin_value = mutated_probe.origin_value.replace("https://", "http://", 1)
        elif strategy == CORSMutationStrategy.SUBDOMAIN_INJECTION:
            parsed = urllib.parse.urlparse(mutated_probe.target_url)
            host = parsed.netloc or parsed.path
            mutated_probe.origin_value = f"https://evil.{host}"
        elif strategy == CORSMutationStrategy.HEADER_DUPLICATION:
            mutated_probe.headers["Origin"] = mutated_probe.origin_value
            mutated_probe.headers["X-Forwarded-Host"] = mutated_probe.origin_value
        elif strategy == CORSMutationStrategy.PREFLIGHT_ENUMERATION:
            mutated_probe.method = "OPTIONS"
            mutated_probe.headers["Access-Control-Request-Method"] = "POST"
            mutated_probe.headers["Access-Control-Request-Headers"] = "X-Custom-Header"
            
        mutated_probe.headers["Origin"] = mutated_probe.origin_value
        return mutated_probe

    def generate_origin_reflection_probes(self, base_url: str) -> List[CORSProbe]:
        base_probe = CORSProbe(
            target_url=base_url,
            vulnerability_type=CORSVulnerabilityType.ORIGIN_REFLECTION,
            strategy=CORSMutationStrategy.ORIGIN_CASING,
            origin_value="https://evil.com"
        )
        return [self.apply_mutation(base_probe, s) for s in list(CORSMutationStrategy)]

    def generate_null_origin_probes(self, base_url: str) -> List[CORSProbe]:
        base_probe = CORSProbe(
            target_url=base_url,
            vulnerability_type=CORSVulnerabilityType.NULL_ORIGIN,
            strategy=CORSMutationStrategy.ORIGIN_CASING,
            origin_value="null",
            headers={"Origin": "null"}
        )
        return [base_probe]

    def generate_wildcard_credential_probes(self, base_url: str) -> List[CORSProbe]:
        base_probe = CORSProbe(
            target_url=base_url,
            vulnerability_type=CORSVulnerabilityType.WILDCARD_CREDENTIALS,
            strategy=CORSMutationStrategy.ORIGIN_CASING,
            origin_value="*",
            headers={"Origin": "*"}
        )
        return [base_probe]

    def generate_subdomain_trust_probes(self, base_url: str) -> List[CORSProbe]:
        parsed = urllib.parse.urlparse(base_url)
        host = parsed.netloc or parsed.path
        base_probe = CORSProbe(
            target_url=base_url,
            vulnerability_type=CORSVulnerabilityType.SUBDOMAIN_TRUST_ABUSE,
            strategy=CORSMutationStrategy.SUBDOMAIN_INJECTION,
            origin_value=f"https://attacker.{host}",
            headers={"Origin": f"https://attacker.{host}"}
        )
        return [base_probe]

    def generate_preflight_probes(self, base_url: str) -> List[CORSProbe]:
        base_probe = CORSProbe(
            target_url=base_url,
            vulnerability_type=CORSVulnerabilityType.PREFLIGHT_BYPASS,
            strategy=CORSMutationStrategy.PREFLIGHT_ENUMERATION,
            origin_value="https://evil.com"
        )
        return [self.apply_mutation(base_probe, CORSMutationStrategy.PREFLIGHT_ENUMERATION)]

    def generate_parser_differential_probes(self, base_url: str) -> List[CORSProbe]:
        parsed = urllib.parse.urlparse(base_url)
        host = parsed.netloc or parsed.path
        probes = []
        
        origins = [
            f"https://{host}.evil.com",
            f"https://evil.com.{host}",
            f"https://{host}%60.evil.com"
        ]
        
        for origin in origins:
            probes.append(CORSProbe(
                target_url=base_url,
                vulnerability_type=CORSVulnerabilityType.ORIGIN_PARSER_DIFFERENTIAL,
                strategy=CORSMutationStrategy.ORIGIN_CASING,
                origin_value=origin,
                headers={"Origin": origin}
            ))
            
        return probes

    def generate_all_probes(self, base_url: str) -> List[CORSProbe]:
        return (
            self.generate_origin_reflection_probes(base_url) +
            self.generate_null_origin_probes(base_url) +
            self.generate_wildcard_credential_probes(base_url) +
            self.generate_subdomain_trust_probes(base_url) +
            self.generate_preflight_probes(base_url) +
            self.generate_parser_differential_probes(base_url)
        )

# =============================================================================
# Analyzer
# =============================================================================

class CORSSecurityAnalyzer:
    def __init__(self):
        pass

    def _is_same_origin(self, origin: str, url: str) -> bool:
        if origin == "null" or origin == "*":
            return False
        
        try:
            o_parsed = urllib.parse.urlparse(origin)
            u_parsed = urllib.parse.urlparse(url)
            return o_parsed.netloc == u_parsed.netloc
        except Exception:
            return False

    def analyze_origin_reflection(self, response: CORSProbeResponse, probe: CORSProbe) -> Optional[CORSSecurityResult]:
        if not response.acao_value:
            return None
            
        if self._is_same_origin(response.acao_value, probe.target_url):
            return None

        if response.acao_value == probe.origin_value and probe.origin_value != "null":
            is_valid = True
            severity = "HIGH" if response.acac_value == "true" else "MEDIUM"
            cvss = 7.5 if severity == "HIGH" else 5.3
            
            return CORSSecurityResult(
                vulnerability_type=CORSVulnerabilityType.ORIGIN_REFLECTION,
                strategy=probe.strategy,
                severity=severity,
                confidence="HIGH",
                endpoint_url=probe.target_url,
                origin_tested=probe.origin_value,
                reflected_origin=response.acao_value,
                cwe_id="CWE-942",
                cvss_score=cvss,
                is_valid_finding=is_valid
            )
        return None

    def analyze_null_origin(self, response: CORSProbeResponse, probe: CORSProbe) -> Optional[CORSSecurityResult]:
        if response.acao_value == "null" and response.acac_value == "true":
            is_valid = True
            severity = "HIGH"
            cvss = 7.5
            
            return CORSSecurityResult(
                vulnerability_type=CORSVulnerabilityType.NULL_ORIGIN,
                strategy=probe.strategy,
                severity=severity,
                confidence="HIGH",
                endpoint_url=probe.target_url,
                origin_tested=probe.origin_value,
                reflected_origin=response.acao_value,
                cwe_id="CWE-942",
                cvss_score=cvss,
                is_valid_finding=is_valid
            )
        elif response.acao_value == "null":
            return CORSSecurityResult(
                vulnerability_type=CORSVulnerabilityType.NULL_ORIGIN,
                strategy=probe.strategy,
                severity="MEDIUM",
                confidence="HIGH",
                endpoint_url=probe.target_url,
                origin_tested=probe.origin_value,
                reflected_origin=response.acao_value,
                cwe_id="CWE-942",
                cvss_score=5.3,
                is_valid_finding=True
            )
        return None

    def analyze_wildcard_credentials(self, response: CORSProbeResponse, probe: CORSProbe) -> Optional[CORSSecurityResult]:
        # Wildcard + Credentials = CRITICAL, but browsers block it.
        # It's a misconfiguration finding.
        if response.acao_value == "*" and response.acac_value == "true":
            return CORSSecurityResult(
                vulnerability_type=CORSVulnerabilityType.WILDCARD_CREDENTIALS,
                strategy=probe.strategy,
                severity="CRITICAL",
                confidence="HIGH",
                endpoint_url=probe.target_url,
                origin_tested=probe.origin_value,
                reflected_origin=response.acao_value,
                cwe_id="CWE-942",
                cvss_score=9.1,
                is_valid_finding=True
            )
        return None

    def analyze_subdomain_trust(self, response: CORSProbeResponse, probe: CORSProbe) -> Optional[CORSSecurityResult]:
        if response.acao_value == probe.origin_value:
            if self._is_same_origin(response.acao_value, probe.target_url):
                return None
            severity = "MEDIUM"
            cvss = 5.4
            if response.acac_value == "true":
                severity = "HIGH"
                cvss = 7.5
                
            return CORSSecurityResult(
                vulnerability_type=CORSVulnerabilityType.SUBDOMAIN_TRUST_ABUSE,
                strategy=probe.strategy,
                severity=severity,
                confidence="HIGH",
                endpoint_url=probe.target_url,
                origin_tested=probe.origin_value,
                reflected_origin=response.acao_value,
                cwe_id="CWE-942",
                cvss_score=cvss,
                is_valid_finding=True
            )
        return None

    def analyze_preflight(self, response: CORSProbeResponse, probe: CORSProbe) -> Optional[CORSSecurityResult]:
        if response.status_code == 200 and response.acao_value == probe.origin_value:
            if self._is_same_origin(response.acao_value, probe.target_url):
                return None
            return CORSSecurityResult(
                vulnerability_type=CORSVulnerabilityType.PREFLIGHT_BYPASS,
                strategy=probe.strategy,
                severity="MEDIUM",
                confidence="HIGH",
                endpoint_url=probe.target_url,
                origin_tested=probe.origin_value,
                reflected_origin=response.acao_value,
                cwe_id="CWE-942",
                cvss_score=5.4,
                is_valid_finding=True
            )
        return None

    def analyze_parser_differential(self, response: CORSProbeResponse, probe: CORSProbe, base_url: str) -> Optional[CORSSecurityResult]:
        if response.acao_value == probe.origin_value:
            if self._is_same_origin(response.acao_value, probe.target_url):
                return None
            severity = "HIGH"
            cvss = 7.5
            return CORSSecurityResult(
                vulnerability_type=CORSVulnerabilityType.ORIGIN_PARSER_DIFFERENTIAL,
                strategy=probe.strategy,
                severity=severity,
                confidence="HIGH",
                endpoint_url=probe.target_url,
                origin_tested=probe.origin_value,
                reflected_origin=response.acao_value,
                cwe_id="CWE-942",
                cvss_score=cvss,
                is_valid_finding=True
            )
        return None

    def audit_security_headers(self, headers: Dict[str, str], url: str, is_authenticated: bool = False) -> List[HeaderAuditResult]:
        findings = []
        lower_headers = {k.lower(): v for k, v in headers.items()}
        
        # CSP
        csp = lower_headers.get("content-security-policy")
        if not csp:
            findings.append(HeaderAuditResult(
                vulnerability_type=HeaderVulnerabilityType.MISSING_CSP,
                severity="MEDIUM",
                confidence="HIGH",
                endpoint_url=url,
                header_name="Content-Security-Policy",
                header_value=None,
                recommendation="Implement a strong Content-Security-Policy.",
                cwe_id="CWE-693",
                cvss_score=4.3,
                is_valid_finding=True
            ))
            
        # HSTS
        hsts = lower_headers.get("strict-transport-security")
        if url.startswith("https://"):
            if not hsts:
                findings.append(HeaderAuditResult(
                    vulnerability_type=HeaderVulnerabilityType.MISSING_HSTS,
                    severity="MEDIUM",
                    confidence="HIGH",
                    endpoint_url=url,
                    header_name="Strict-Transport-Security",
                    header_value=None,
                    recommendation="Implement Strict-Transport-Security.",
                    cwe_id="CWE-693",
                    cvss_score=4.3,
                    is_valid_finding=True
                ))
            else:
                try:
                    parts = [p.strip().lower() for p in hsts.split(";")]
                    max_age = 0
                    has_subdomains = False
                    for p in parts:
                        if p.startswith("max-age="):
                            max_age = int(p.split("=")[1])
                        elif p == "includesubdomains":
                            has_subdomains = True
                    if max_age < 31536000 or not has_subdomains:
                        findings.append(HeaderAuditResult(
                            vulnerability_type=HeaderVulnerabilityType.WEAK_HSTS,
                            severity="LOW",
                            confidence="HIGH",
                            endpoint_url=url,
                            header_name="Strict-Transport-Security",
                            header_value=hsts,
                            recommendation="HSTS max-age should be at least 31536000 and includeSubDomains should be specified.",
                            cwe_id="CWE-693",
                            cvss_score=2.6,
                            is_valid_finding=True
                        ))
                except Exception:
                    # Malformed HSTS header handled gracefully (weak)
                    findings.append(HeaderAuditResult(
                        vulnerability_type=HeaderVulnerabilityType.WEAK_HSTS,
                        severity="LOW",
                        confidence="HIGH",
                        endpoint_url=url,
                        header_name="Strict-Transport-Security",
                        header_value=hsts,
                        recommendation="Fix malformed HSTS header.",
                        cwe_id="CWE-693",
                        cvss_score=2.6,
                        is_valid_finding=True
                    ))

        # X-Frame-Options
        x_frame = lower_headers.get("x-frame-options")
        if not x_frame:
            findings.append(HeaderAuditResult(
                vulnerability_type=HeaderVulnerabilityType.MISSING_X_FRAME_OPTIONS,
                severity="MEDIUM",
                confidence="HIGH",
                endpoint_url=url,
                header_name="X-Frame-Options",
                header_value=None,
                recommendation="Implement X-Frame-Options to prevent Clickjacking.",
                cwe_id="CWE-1021",
                cvss_score=4.3,
                is_valid_finding=True
            ))

        # X-Content-Type-Options
        x_content = lower_headers.get("x-content-type-options")
        if not x_content:
            findings.append(HeaderAuditResult(
                vulnerability_type=HeaderVulnerabilityType.MISSING_X_CONTENT_TYPE_OPTIONS,
                severity="LOW",
                confidence="HIGH",
                endpoint_url=url,
                header_name="X-Content-Type-Options",
                header_value=None,
                recommendation="Set X-Content-Type-Options to nosniff.",
                cwe_id="CWE-693",
                cvss_score=2.6,
                is_valid_finding=True
            ))
            
        return findings


# =============================================================================
# Collector
# =============================================================================

class CORSSecurityCollector(BaseCollector):
    def __init__(self):
        super().__init__()
        self.generator = CORSPayloadGenerator()
        self.analyzer = CORSSecurityAnalyzer()
        self.http = AuthenticatedHttpClient()

    def _discover_candidate_endpoints(self, mission: Any) -> List[str]:
        raw_mission = getattr(mission, "_raw_mission", mission)
        endpoints: Set[str] = set()
        
        # 1. From inputs
        if hasattr(raw_mission, "inputs") and isinstance(raw_mission.inputs, dict):
            for ep in raw_mission.inputs.get("endpoints", []):
                if isinstance(ep, str):
                    endpoints.add(ep)
                elif hasattr(ep, "url"):
                    endpoints.add(ep.url)
                    
        # 2. From graph
        graph = getattr(raw_mission, "attack_surface_graph", None) or getattr(raw_mission, "graph", None)
        if graph and hasattr(graph, "nodes"):
            for node in graph.nodes.values():
                if node.type == "endpoint":
                    url = getattr(node, "value", None)
                    if url:
                        endpoints.add(url)
                        
        if not endpoints:
            logger.warning("No endpoints discovered for CORS security collection.")
            
        return list(endpoints)

    def _emit_evidence(
        self,
        mission: Any,
        result: Union[CORSSecurityResult, HeaderAuditResult],
        target_url: str,
        base_url: str
    ) -> Evidence:
        raw_mission = getattr(mission, "_raw_mission", mission)
        
        title = f"{result.vulnerability_type.value} at {target_url}"
        
        ev = Evidence(
            category="cors_security",
            value=f"cors_security:{result.vulnerability_type.value}:{target_url}",
            source="cors_security",
            status="CONFIRMED",
            severity=result.severity,
            confidence=result.confidence,
            title=title,
            description=f"Detected {result.vulnerability_type.value}",
            provenance=ProvenanceData(
                observation_id=str(uuid.uuid4()),
                step_id=f"step_{result.vulnerability_type.value}"
            ),
            metadata={
                "target_url": target_url,
                "vulnerability_type": result.vulnerability_type.value,
                "cwe_id": result.cwe_id,
                "cvss_score": result.cvss_score,
                "is_valid_finding": result.is_valid_finding,
            },
        )

        if isinstance(result, CORSSecurityResult):
            ev.metadata.update({
                "strategy": result.strategy.value,
                "origin_tested": result.origin_tested,
                "reflected_origin": result.reflected_origin,
            })
        elif isinstance(result, HeaderAuditResult):
            ev.metadata.update({
                "header_name": result.header_name,
                "header_value": result.header_value,
                "recommendation": result.recommendation,
            })

        # 1. Update raw_mission.evidence
        if hasattr(raw_mission, "evidence") and raw_mission.evidence is not None:
            if hasattr(raw_mission.evidence, "add"):
                raw_mission.evidence.add(ev)
            elif isinstance(raw_mission.evidence, list):
                raw_mission.evidence.append(ev)

        # 2. Update raw_mission.vulnerabilities
        if hasattr(raw_mission, "vulnerabilities") and isinstance(raw_mission.vulnerabilities, list):
            vuln_dict = {
                "name": title,
                "template_id": result.vulnerability_type.value,
                "severity": result.severity,
                "host": base_url,
                "url": target_url,
                "description": f"Detected {result.vulnerability_type.value}",
                "cwe_id": result.cwe_id,
                "cvss_score": result.cvss_score,
            }
            if isinstance(result, CORSSecurityResult):
                vuln_dict["strategy"] = result.strategy.value
            raw_mission.vulnerabilities.append(vuln_dict)

        # 3. Attack Surface Knowledge Graph Expansion
        graph = getattr(raw_mission, "attack_surface_graph", None) or getattr(raw_mission, "graph", None)
        if graph is not None and hasattr(graph, "add") and hasattr(graph, "connect"):
            lh_id = f"live_host:{base_url}"
            ep_id = f"endpoint:{target_url}"
            vuln_id = f"vulnerability:{result.vulnerability_type.value}:{target_url}"
            if isinstance(result, HeaderAuditResult):
                vuln_id += f":{result.header_name}"

            parsed_b = urllib.parse.urlparse(base_url)
            graph.add(Node(id=lh_id, type="live_host", value=base_url, metadata={"url": base_url, "host": parsed_b.hostname or base_url}))
            graph.add(Node(id=ep_id, type="endpoint", value=target_url, metadata={"url": target_url}))
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

    def _execute_probe(self, probe: CORSProbe) -> CORSProbeResponse:
        import time
        start = time.time()
        
        try:
            resp = self.http.request(
                method=probe.method,
                url=probe.target_url,
                headers=probe.headers,
                timeout=10.0
            )
            elapsed = time.time() - start
            headers = {k.lower(): v for k, v in resp.headers.items()}
            return CORSProbeResponse(
                probe=probe,
                status_code=resp.status_code,
                headers=resp.headers,
                body=resp.text,
                elapsed=elapsed,
                acao_value=headers.get("access-control-allow-origin"),
                acac_value=headers.get("access-control-allow-credentials"),
                acao_methods=headers.get("access-control-allow-methods"),
                acao_headers=headers.get("access-control-allow-headers")
            )
        except Exception:
            elapsed = time.time() - start
            return CORSProbeResponse(
                probe=probe,
                status_code=0,
                headers={},
                body="",
                elapsed=elapsed
            )

    def collect(self, mission: Any) -> List[Evidence]:
        endpoints = self._discover_candidate_endpoints(mission)
        collected_evidence: List[Evidence] = []
        
        for target_url in endpoints:
            parsed = urllib.parse.urlparse(target_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else target_url
            
            # Step 1: Audit Security Headers with a standard GET
            try:
                resp = self.http.request(method="GET", url=target_url, timeout=10.0)
                header_findings = self.analyzer.audit_security_headers(resp.headers, target_url)
                for finding in header_findings:
                    if finding.is_valid_finding:
                        ev = self._emit_evidence(mission, finding, target_url, base_url)
                        collected_evidence.append(ev)
            except Exception:
                pass

            # Step 2: CORS probes
            probes = self.generator.generate_all_probes(target_url)
            for probe in probes:
                response = self._execute_probe(probe)
                
                # Graceful handling for rate limits or server errors
                if response.status_code in [429, 500, 0]:
                    continue
                    
                result = None
                if probe.vulnerability_type == CORSVulnerabilityType.ORIGIN_REFLECTION:
                    result = self.analyzer.analyze_origin_reflection(response, probe)
                elif probe.vulnerability_type == CORSVulnerabilityType.NULL_ORIGIN:
                    result = self.analyzer.analyze_null_origin(response, probe)
                elif probe.vulnerability_type == CORSVulnerabilityType.WILDCARD_CREDENTIALS:
                    result = self.analyzer.analyze_wildcard_credentials(response, probe)
                elif probe.vulnerability_type == CORSVulnerabilityType.SUBDOMAIN_TRUST_ABUSE:
                    result = self.analyzer.analyze_subdomain_trust(response, probe)
                elif probe.vulnerability_type == CORSVulnerabilityType.PREFLIGHT_BYPASS:
                    result = self.analyzer.analyze_preflight(response, probe)
                elif probe.vulnerability_type == CORSVulnerabilityType.ORIGIN_PARSER_DIFFERENTIAL:
                    result = self.analyzer.analyze_parser_differential(response, probe, target_url)

                if result and result.is_valid_finding:
                    ev = self._emit_evidence(mission, result, target_url, base_url)
                    collected_evidence.append(ev)

        return collected_evidence

    def execute(self, mission: Any) -> List[Evidence]:
        return self.collect(mission)
