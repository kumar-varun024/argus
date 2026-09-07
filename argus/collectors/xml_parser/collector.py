"""xml_parser: Collector orchestration."""
from __future__ import annotations

import logging
import urllib.parse
from typing import Any, Dict, List, Optional, Set, Tuple

from argus.collectors.base import BaseCollector
from argus.evidence.model import Evidence, ProvenanceData
from argus.graph.node import Node
from argus.http.client import AuthenticatedHttpClient, HttpResponse
from argus.collectors.xml_parser.models import XMLTechnique, XMLValidationResult
from argus.collectors.xml_parser.payloads import XMLPayloadGenerator
from argus.collectors.xml_parser.analyzer import XMLParserAnalyzer

logger = logging.getLogger(__name__)


class XMLParserSecurityCollector(BaseCollector):
    """
    Autonomous XML Parser Security & XXE Collector for ARGUS.
    Fuzzes discovered XML-accepting endpoints, POST bodies, SOAP envelopes, and parameter-based
    structured XML inputs for insecure parser configurations using AuthenticatedHttpClient.
    """

    XML_CONTENT_TYPES = [
        "application/xml",
        "text/xml",
        "application/soap+xml",
    ]

    XML_PARAM_NAMES = [
        "xml", "xml_data", "xmldata", "doc", "document", "config", "configuration",
        "data", "payload", "request", "req", "msg", "message", "saml", "samlrequest",
        "assertion", "manifest", "template", "query", "order", "input", "body", "file",
    ]

    COMMON_XML_PROBE_ROUTES = [
        "/api/xml", "/xml", "/soap", "/ws", "/service", "/services",
        "/xmlrpc.php", "/saml", "/saml/sso", "/rpc", "/ws/soap", "/api/v1/xml",
    ]

    def __init__(
        self,
        http_client: Optional[Any] = None,
        payload_generator: Optional[XMLPayloadGenerator] = None,
        analyzer: Optional[XMLParserAnalyzer] = None,
        timeout: float = 10.0,
    ):
        self.http_client = http_client
        self.generator = payload_generator or XMLPayloadGenerator()
        self.analyzer = analyzer or XMLParserAnalyzer()
        self.timeout = timeout

    def _normalize_base_url(self, raw_url: str) -> str:
        raw_clean = str(raw_url).strip()
        if not raw_clean.startswith("http://") and not raw_clean.startswith("https://"):
            raw_clean = f"https://{raw_clean}"
        parsed = urllib.parse.urlparse(raw_clean)
        scheme = parsed.scheme or "https"
        netloc = parsed.netloc or parsed.path.split("/")[0]
        return f"{scheme}://{netloc}"

    def _extract_candidate_endpoints(self, mission: Any) -> List[Dict[str, Any]]:
        """
        Extracts structured candidate endpoints, methods, and parameter targets from mission state.
        """
        raw_mission = getattr(mission, "_mission", mission)
        candidates: List[Dict[str, Any]] = []
        seen_urls: Set[Tuple[str, str]] = set()

        base_hosts: List[str] = []
        for h in getattr(raw_mission, "live_hosts", []) or []:
            if isinstance(h, dict):
                url = h.get("url") or h.get("host")
                if url:
                    base_hosts.append(self._normalize_base_url(url))
            elif isinstance(h, str) and h:
                base_hosts.append(self._normalize_base_url(h))

        target_str = getattr(raw_mission, "target", None)
        if target_str:
            base_hosts.append(self._normalize_base_url(str(target_str)))

        base_hosts = list(dict.fromkeys(base_hosts))
        default_base = base_hosts[0] if base_hosts else "https://target.local"

        # 1. Ingest explicit mission endpoints
        for ep in getattr(raw_mission, "endpoints", []) or []:
            raw_url = ""
            method = "POST"
            params_dict: Dict[str, Any] = {}
            body_data: Any = None
            headers_dict: Dict[str, str] = {}

            if isinstance(ep, dict):
                raw_url = ep.get("url") or ep.get("path") or ""
                method = (ep.get("method") or "POST").upper()
                params_dict = ep.get("params") or {}
                body_data = ep.get("body")
                headers_dict = ep.get("headers") or {}
            elif isinstance(ep, str):
                raw_url = ep

            if not raw_url:
                continue

            if not raw_url.startswith("http://") and not raw_url.startswith("https://"):
                full_url = urllib.parse.urljoin(default_base, raw_url)
            else:
                full_url = raw_url

            key = (full_url, method)
            if key not in seen_urls:
                seen_urls.add(key)
                candidates.append({
                    "url": full_url,
                    "method": method,
                    "params": params_dict,
                    "body": body_data,
                    "headers": headers_dict,
                })

        # 2. Add common probe routes for each live host if candidates are few
        if not candidates or len(candidates) < 5:
            for base in base_hosts:
                for probe_path in self.COMMON_XML_PROBE_ROUTES:
                    probe_url = urllib.parse.urljoin(base, probe_path)
                    key = (probe_url, "POST")
                    if key not in seen_urls:
                        seen_urls.add(key)
                        candidates.append({
                            "url": probe_url,
                            "method": "POST",
                            "params": {},
                            "body": None,
                            "headers": {"Content-Type": "application/xml"},
                        })

        return candidates

    def _execute_request(
        self,
        mission: Any,
        method: str,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Any] = None,
        json_data: Optional[Any] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
    ) -> Optional[HttpResponse]:
        """Dispatches HTTP request polymorphically via injected or context client."""
        method = method.upper()
        try:
            if self.http_client is not None:
                # Handle injected client (supports mock clients in unit tests)
                if method == "GET" and hasattr(self.http_client, "get"):
                    try:
                        return self.http_client.get(
                            mission, url, params=params, headers=headers, cookies=cookies, timeout=self.timeout
                        )
                    except TypeError:
                        return self.http_client.get(url, params=params, headers=headers)
                elif method == "POST" and hasattr(self.http_client, "post"):
                    try:
                        return self.http_client.post(
                            mission, url, data=data, json=json_data, headers=headers, cookies=cookies, timeout=self.timeout
                        )
                    except TypeError:
                        return self.http_client.post(url, data=data, headers=headers)
                elif hasattr(self.http_client, "request"):
                    try:
                        return self.http_client.request(
                            mission, method, url, params=params, data=data, json=json_data, headers=headers, cookies=cookies, timeout=self.timeout
                        )
                    except TypeError:
                        return self.http_client.request(method, url, data=data, headers=headers)
                elif callable(self.http_client):
                    return self.http_client(url)

            # Fallback to AuthenticatedHttpClient context manager
            with AuthenticatedHttpClient(timeout=self.timeout, max_retries=1) as client:
                if method == "GET":
                    return client.get(mission, url, params=params, headers=headers, cookies=cookies, timeout=self.timeout)
                elif method == "POST":
                    return client.post(mission, url, data=data, json=json_data, headers=headers, cookies=cookies, timeout=self.timeout)
                else:
                    return client.request(mission, method, url, params=params, data=data, json=json_data, headers=headers, cookies=cookies, timeout=self.timeout)
        except Exception as e:
            logger.debug(f"Request failed for {url}: {e}")
            return None

    def collect(self, mission: Any) -> List[Evidence]:
        """
        Executes XML parser security validation across discovered candidate endpoints.
        """
        raw_mission = getattr(mission, "_mission", mission)
        candidates = self._extract_candidate_endpoints(mission)
        detected_evidence: List[Evidence] = []
        confirmed_findings: Set[str] = set()

        if not candidates:
            logger.info("XMLParserSecurityCollector: No candidate endpoints available to audit.")
            return detected_evidence

        logger.info(f"XMLParserSecurityCollector: Auditing {len(candidates)} candidate endpoint(s).")
        all_payloads = self.generator.generate_all_payloads()
        baseline_payload = self.generator.generate_baseline_payload()

        for ep in candidates:
            target_url = ep["url"]
            method = ep["method"]
            headers = dict(ep.get("headers") or {})
            params = dict(ep.get("params") or {})
            body = ep.get("body")
            base_url = self._normalize_base_url(target_url)

            # Step 1: Baseline Calibration Request
            baseline_resp = None
            if method in ("POST", "PUT", "PATCH") and not isinstance(body, dict):
                baseline_resp = self._execute_request(
                    mission,
                    method="POST",
                    url=target_url,
                    data=baseline_payload,
                    headers={"Content-Type": "application/xml", **headers},
                )
            elif method == "GET":
                baseline_resp = self._execute_request(
                    mission,
                    method="GET",
                    url=target_url,
                    headers=headers,
                )
            elif isinstance(body, dict):
                baseline_resp = self._execute_request(
                    mission,
                    method="POST",
                    url=target_url,
                    json_data=body,
                    headers={"Content-Type": "application/json", **headers},
                )

            # Channel A: Raw XML POST Body Fuzzing (when endpoint accepts POST/PUT/PATCH and body is not a dict)
            if method in ("POST", "PUT", "PATCH") and not isinstance(body, dict):
                for p_info in all_payloads:
                    finding_key = f"{target_url}:body:{p_info['target_file']}:{p_info['technique']}"
                    if finding_key in confirmed_findings:
                        continue

                    content_type = p_info.get("content_type", "application/xml")
                    req_headers = {"Content-Type": content_type, **headers}
                    req_data = p_info.get("raw_bytes") or p_info.get("payload")

                    resp = self._execute_request(
                        mission,
                        method=method,
                        url=target_url,
                        data=req_data,
                        headers=req_headers,
                    )

                    if resp is not None:
                        result = self.analyzer.analyze_response(resp, p_info, baseline_response=baseline_resp)
                        if result is not None and result.is_valid_finding:
                            ev = self._create_evidence_and_update_state(
                                mission=mission,
                                target_url=target_url,
                                base_url=base_url,
                                param="xml_body",
                                param_type="body",
                                payload=p_info["payload"],
                                status_code=getattr(resp, "status_code", 200) or 200,
                                result=result,
                            )
                            detected_evidence.append(ev)
                            confirmed_findings.add(finding_key)
                            break  # Move to next endpoint on confirmed critical finding

            # Channel B: Parameter-Based Structured XML Fuzzing (Query Parameters)
            parsed_url = urllib.parse.urlparse(target_url)
            query_params = urllib.parse.parse_qs(parsed_url.query, keep_blank_values=True)
            target_param_names = list(query_params.keys()) or [
                p for p in self.XML_PARAM_NAMES if p in target_url.lower()
            ]

            if query_params or any(p in target_url.lower() for p in self.XML_PARAM_NAMES):
                for param_name in target_param_names:
                    for p_info in all_payloads[:10]:
                        finding_key = f"{target_url}:query:{param_name}:{p_info['target_file']}"
                        if finding_key in confirmed_findings:
                            continue

                        mutated_qs = dict(query_params)
                        mutated_qs[param_name] = [p_info["payload"]]
                        qs_str = urllib.parse.urlencode(mutated_qs, doseq=True)
                        fuzzed_url = urllib.parse.urlunparse(parsed_url._replace(query=qs_str))

                        resp = self._execute_request(
                            mission,
                            method="GET",
                            url=fuzzed_url,
                            headers=headers,
                        )

                        if resp is not None:
                            result = self.analyzer.analyze_response(resp, p_info, baseline_response=baseline_resp)
                            if result is not None and result.is_valid_finding:
                                ev = self._create_evidence_and_update_state(
                                    mission=mission,
                                    target_url=target_url,
                                    base_url=base_url,
                                    param=param_name,
                                    param_type="query_parameter",
                                    payload=p_info["payload"],
                                    status_code=getattr(resp, "status_code", 200) or 200,
                                    result=result,
                                )
                                detected_evidence.append(ev)
                                confirmed_findings.add(finding_key)
                                break

            # Channel C: Form & JSON Parameters Containing XML Strings
            if isinstance(body, dict):
                for key_name in list(body.keys()):
                    for p_info in all_payloads[:10]:
                        finding_key = f"{target_url}:json:{key_name}:{p_info['target_file']}"
                        if finding_key in confirmed_findings:
                            continue

                        mutated_body = dict(body)
                        mutated_body[key_name] = p_info["payload"]

                        resp = self._execute_request(
                            mission,
                            method="POST",
                            url=target_url,
                            json_data=mutated_body,
                            headers={"Content-Type": "application/json", **headers},
                        )

                        if resp is not None:
                            result = self.analyzer.analyze_response(resp, p_info, baseline_response=baseline_resp)
                            if result is not None and result.is_valid_finding:
                                ev = self._create_evidence_and_update_state(
                                    mission=mission,
                                    target_url=target_url,
                                    base_url=base_url,
                                    param=key_name,
                                    param_type="json_field",
                                    payload=p_info["payload"],
                                    status_code=getattr(resp, "status_code", 200) or 200,
                                    result=result,
                                )
                                detected_evidence.append(ev)
                                confirmed_findings.add(finding_key)
                                break

        logger.info(
            f"XMLParserSecurityCollector complete: {len(detected_evidence)} XML parser misconfiguration finding(s) confirmed."
        )
        return detected_evidence

    def _create_evidence_and_update_state(
        self,
        mission: Any,
        target_url: str,
        base_url: str,
        param: str,
        param_type: str,
        payload: str,
        status_code: int,
        result: XMLValidationResult,
    ) -> Evidence:
        """
        Constructs Evidence, appends to mission.evidence & mission.vulnerabilities,
        and expands the KnowledgeGraph attack surface with HAS_ENDPOINT and HAS_VULNERABILITY edges.
        """
        raw_mission = getattr(mission, "_mission", mission)
        template_id = result.template_id or "xxe"
        technique = result.technique
        severity = result.severity
        confidence = result.confidence
        snippet = result.evidence_snippet
        mutation = result.mutation_strategy

        parsed_url = urllib.parse.urlparse(target_url)
        url_path = parsed_url.path or "/"

        technique_labels = {
            XMLTechnique.ENTITY_RESOLUTION.value: "External Entity Resolution",
            XMLTechnique.PARAMETER_ENTITY.value: "Parameter Entity Resolution",
            XMLTechnique.RECURSIVE_ENTITY.value: "Recursive Entity Expansion",
            XMLTechnique.XINCLUDE.value: "XInclude Directive Processing",
        }
        tech_label = technique_labels.get(technique, technique)

        title = f"XML Parser Misconfiguration ({tech_label}): {param} on {target_url}"
        description = (
            f"Insecure XML parser configuration ({tech_label} / {mutation}) confirmed on endpoint {target_url} "
            f"via {param_type} '{param}' using payload snippet: '{payload[:120]}...'. "
            f"Evidence: {snippet[:200]}"
        )

        ev = Evidence(
            mission_id=getattr(raw_mission, "id", ""),
            source_type="LOG",
            created_by="SYSTEM_GENERATED",
            title=title,
            description=description,
            category="xml_parser_validation",
            value=target_url,
            source=target_url,
            status="CONFIRMED",
            confidence=confidence,
            severity=severity,
            provenance=ProvenanceData(
                step_id="xml_parser_security_collector",
            ),
            tags=["xml_parser_validation", "xxe", "xml_external_entity", technique, template_id],
            metadata={
                "url": target_url,
                "host": base_url,
                "path": url_path,
                "parameter": param,
                "parameter_type": param_type,
                "payload": payload,
                "category": "xml_parser_validation",
                "severity": severity,
                "confidence": confidence,
                "technique": technique,
                "mutation_strategy": mutation,
                "target_file": result.target_file,
                "matched_signature": result.matched_signature,
                "template_id": template_id,
                "status_code": status_code,
                "evidence_snippet": snippet[:250],
                "delay_delta": result.delay_delta,
                "baseline_elapsed": result.baseline_elapsed,
                "injected_elapsed": result.injected_elapsed,
            },
        )

        # 1. Add to raw_mission.evidence
        if hasattr(raw_mission, "evidence") and raw_mission.evidence is not None:
            if hasattr(raw_mission.evidence, "add"):
                raw_mission.evidence.add(ev)
            elif isinstance(raw_mission.evidence, list):
                raw_mission.evidence.append(ev)

        # 2. Add to raw_mission.vulnerabilities
        if hasattr(raw_mission, "vulnerabilities") and isinstance(raw_mission.vulnerabilities, list):
            raw_mission.vulnerabilities.append({
                "name": f"XML Parser Misconfiguration ({tech_label})",
                "template_id": template_id,
                "severity": severity,
                "host": base_url,
                "url": target_url,
                "description": description,
                "parameter": param,
                "parameter_type": param_type,
                "payload": payload,
                "technique": technique,
                "mutation_strategy": mutation,
                "target_file": result.target_file,
            })

        # 3. KnowledgeGraph Node & Edge Expansion
        graph = getattr(raw_mission, "attack_surface_graph", None) or getattr(raw_mission, "graph", None)
        if graph is not None and hasattr(graph, "add") and hasattr(graph, "connect"):
            lh_id = f"live_host:{base_url}"
            ep_id = f"endpoint:{target_url}"
            vuln_id = f"vulnerability:{template_id}:{target_url}:{param}"

            graph.add(Node(id=lh_id, type="live_host", value=base_url, metadata={"url": base_url}))
            graph.add(Node(id=ep_id, type="endpoint", value=target_url, metadata={"url": target_url, "status_code": status_code}))
            graph.add(Node(id=vuln_id, type="vulnerability", value=f"XML Parser Misconfiguration ({tech_label})", metadata=ev.metadata))

            graph.connect(lh_id, ep_id, edge_type="HAS_ENDPOINT")
            graph.connect(lh_id, vuln_id, edge_type="HAS_VULNERABILITY")
            graph.connect(ep_id, vuln_id, edge_type="HAS_VULNERABILITY")

        # 4. Safe publish to ControlledMission wrapper
        if mission is not raw_mission and hasattr(mission, "publish_finding"):
            try:
                mission.publish_finding(ev.evidence_id, ev)
            except Exception:
                pass

        return ev

    def execute(self, mission: Any) -> List[Evidence]:
        """Plugin / Specialist adapter interface."""
        return self.collect(mission)

XMLParserValidationCollector = XMLParserSecurityCollector

XXECollector = XMLParserSecurityCollector
