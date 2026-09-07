"""deserialization: Collector orchestration."""
from __future__ import annotations

import logging
import urllib.parse
from typing import Any, Dict, List, Optional, Set, Union

from argus.collectors.base import BaseCollector
from argus.collectors.toolkit.enums import Severity
from argus.evidence.model import Evidence, ProvenanceData
from argus.graph.node import Node
from argus.http.client import AuthenticatedHttpClient, HttpResponse
from argus.collectors.deserialization.models import DeserializationFormat, DeserializationResult
from argus.collectors.deserialization.payloads import DeserializationPayloadGenerator
from argus.collectors.deserialization.analyzer import DeserializationAnalyzer

logger = logging.getLogger(__name__)


class DeserializationCollector(BaseCollector):
    """
    Collector testing discovered endpoints, parameters, cookies, and custom headers
    for Insecure Deserialization vulnerabilities.
    """

    COMMON_DESERIALIZATION_PARAMS = [
        "data",
        "payload",
        "state",
        "viewstate",
        "session",
        "token",
        "object",
        "serialized",
        "cmd",
        "callback",
        "query",
        "item",
        "target",
        "profile",
        "config",
        "auth",
        "credentials",
        "context",
    ]

    COMMON_DESERIALIZATION_COOKIES = [
        "session",
        "session_id",
        "user_session",
        "auth_token",
        "state",
        "data",
        "profile",
        "token",
        "remember_me",
        "user",
    ]

    COMMON_DESERIALIZATION_HEADERS = [
        "X-Serialized-Payload",
        "X-ViewState",
        "X-Token",
        "X-Session-Data",
        "X-Object",
        "Authorization",
    ]

    def __init__(
        self,
        http_client: Optional[Any] = None,
        timeout: float = 10.0,
        max_probes_per_endpoint: int = 30,
    ) -> None:
        self.http_client = http_client
        self.timeout = timeout
        self.max_probes_per_endpoint = max_probes_per_endpoint
        self.payload_generator = DeserializationPayloadGenerator()
        self.analyzer = DeserializationAnalyzer()

    def _execute_request(
        self,
        mission: Any,
        method: str,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Union[str, bytes, Dict[str, Any]]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
    ) -> Optional[HttpResponse]:
        """
        Executes an HTTP request with polymorphic support for different client interfaces.
        """
        method = method.upper()
        req_headers = dict(headers or {})
        req_cookies = dict(cookies or {})

        try:
            if self.http_client is not None:
                client = self.http_client
                if method == "GET" and hasattr(client, "get"):
                    try:
                        return client.get(
                            mission, url, params=params, headers=req_headers, cookies=req_cookies, timeout=self.timeout
                        )
                    except TypeError:
                        return client.get(url, params=params, headers=req_headers, cookies=req_cookies)

                if method == "POST" and hasattr(client, "post"):
                    kwargs: Dict[str, Any] = {"headers": req_headers, "cookies": req_cookies}
                    if params:
                        kwargs["params"] = params
                    if json_data is not None:
                        kwargs["json"] = json_data
                    if data is not None:
                        kwargs["data"] = data
                    try:
                        return client.post(mission, url, timeout=self.timeout, **kwargs)
                    except TypeError:
                        return client.post(url, **kwargs)

                if hasattr(client, "request"):
                    try:
                        return client.request(
                            mission,
                            method=method,
                            url=url,
                            params=params,
                            data=data,
                            json=json_data,
                            headers=req_headers,
                            cookies=req_cookies,
                            timeout=self.timeout,
                        )
                    except TypeError:
                        return client.request(
                            method=method,
                            url=url,
                            params=params,
                            data=data,
                            json=json_data,
                            headers=req_headers,
                            cookies=req_cookies,
                        )

                if callable(client):
                    return client(
                        method=method,
                        url=url,
                        params=params,
                        data=data,
                        json=json_data,
                        headers=req_headers,
                        cookies=req_cookies,
                    )

            # Fallback to AuthenticatedHttpClient context manager
            with AuthenticatedHttpClient(timeout=self.timeout, max_retries=1) as client:
                if method == "GET":
                    return client.get(
                        mission, url, params=params, headers=req_headers, cookies=req_cookies, timeout=self.timeout
                    )
                elif method == "POST":
                    return client.post(
                        mission, url, data=data, json=json_data, headers=req_headers, cookies=req_cookies, timeout=self.timeout
                    )
                else:
                    return client.request(
                        mission, method, url, params=params, data=data, json=json_data, headers=req_headers, cookies=req_cookies, timeout=self.timeout
                    )
        except Exception as e:
            logger.debug(f"DeserializationCollector: HTTP request to {url} failed: {e}")

        return None

    def collect(self, mission: Any) -> List[Evidence]:
        """
        Executes active insecure deserialization testing against discovered endpoints.
        """
        raw_mission = getattr(mission, "_mission", mission)
        endpoints = list(getattr(raw_mission, "endpoints", []) or [])
        live_hosts = list(getattr(raw_mission, "live_hosts", []) or [])
        target = str(getattr(raw_mission, "target", "") or "")

        # Fallback target synthesis if endpoints is empty
        if not endpoints:
            if live_hosts:
                for lh in live_hosts:
                    url = lh.get("url", lh) if isinstance(lh, dict) else str(lh)
                    if url:
                        endpoints.append({"url": url, "method": "GET"})
            elif target:
                endpoints.append({"url": target if target.startswith("http") else f"http://{target}", "method": "GET"})

        if not endpoints:
            logger.info("DeserializationCollector: No endpoints or targets discovered.")
            return []

        detected_evidence: List[Evidence] = []
        confirmed_findings: Set[str] = set()

        all_mutated_payloads = self.payload_generator.generate_mutated_payloads()

        for ep in endpoints:
            if isinstance(ep, dict):
                target_url = ep.get("url") or ""
                ep_method = (ep.get("method") or "GET").upper()
                body = ep.get("body")
                headers = ep.get("headers") or {}
                cookies = ep.get("cookies") or {}
                query_params = ep.get("params") or {}
            else:
                target_url = str(ep)
                ep_method = "GET"
                body = None
                headers = {}
                cookies = {}
                query_params = {}

            if not target_url or not target_url.startswith("http"):
                continue

            parsed_url = urllib.parse.urlparse(target_url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"

            # Baseline measurement
            baseline_resp = self._execute_request(
                mission,
                method=ep_method,
                url=target_url,
                params=query_params if query_params else None,
                data=body if isinstance(body, (str, bytes)) else None,
                json_data=body if isinstance(body, dict) else None,
                headers=headers,
                cookies=cookies,
            )

            # Channel 1: POST Body (JSON / Form / Raw bytes)
            if ep_method == "POST" or body is not None:
                # 1A: JSON Fields
                if isinstance(body, dict):
                    keys_to_fuzz = list(body.keys()) or ["data"]
                    for k in keys_to_fuzz:
                        for p_info in all_mutated_payloads[: self.max_probes_per_endpoint]:
                            finding_key = f"{target_url}:json:{k}:{p_info['format']}"
                            if finding_key in confirmed_findings:
                                continue

                            fuzzed_json = dict(body)
                            fuzzed_json[k] = p_info["payload"]
                            resp = self._execute_request(
                                mission,
                                method="POST",
                                url=target_url,
                                json_data=fuzzed_json,
                                headers={"Content-Type": "application/json", **headers},
                                cookies=cookies,
                            )
                            if resp:
                                res = self.analyzer.analyze_response(
                                    resp, p_info, baseline_response=baseline_resp, parameter_name=k, parameter_type="json_field"
                                )
                                if res and res.is_valid_finding:
                                    ev = self._create_evidence_and_update_state(
                                        mission=mission,
                                        target_url=target_url,
                                        base_url=base_url,
                                        param=k,
                                        param_type="json_field",
                                        payload=p_info["payload"],
                                        status_code=getattr(resp, "status_code", 200) or 200,
                                        result=res,
                                    )
                                    detected_evidence.append(ev)
                                    confirmed_findings.add(finding_key)
                                    break
                else:
                    # 1B: Raw POST Body / Form Body
                    for p_info in all_mutated_payloads[: self.max_probes_per_endpoint]:
                        finding_key = f"{target_url}:body:{p_info['format']}"
                        if finding_key in confirmed_findings:
                            continue

                        ct = p_info.get("content_type", "application/x-www-form-urlencoded")
                        req_hdrs = {"Content-Type": ct, **headers}
                        raw_data = p_info.get("raw_bytes") if "raw_bytes" in p_info else p_info["payload"]

                        resp = self._execute_request(
                            mission,
                            method="POST",
                            url=target_url,
                            data=raw_data,
                            headers=req_hdrs,
                            cookies=cookies,
                        )
                        if resp:
                            res = self.analyzer.analyze_response(
                                resp, p_info, baseline_response=baseline_resp, parameter_name="body", parameter_type="post_body"
                            )
                            if res and res.is_valid_finding:
                                ev = self._create_evidence_and_update_state(
                                    mission=mission,
                                    target_url=target_url,
                                    base_url=base_url,
                                    param="body",
                                    param_type="post_body",
                                    payload=str(p_info["payload"]),
                                    status_code=getattr(resp, "status_code", 200) or 200,
                                    result=res,
                                )
                                detected_evidence.append(ev)
                                confirmed_findings.add(finding_key)
                                break

            # Channel 2: GET Query Parameters
            url_query = parsed_url.query
            parsed_params = urllib.parse.parse_qs(url_query)
            params_to_test = list(parsed_params.keys()) if parsed_params else self.COMMON_DESERIALIZATION_PARAMS[:5]

            for param_name in params_to_test:
                for p_info in all_mutated_payloads[: self.max_probes_per_endpoint]:
                    finding_key = f"{target_url}:query:{param_name}:{p_info['format']}"
                    if finding_key in confirmed_findings:
                        continue

                    # Craft query string
                    test_params = dict(query_params)
                    test_params[param_name] = p_info["payload"]
                    resp = self._execute_request(
                        mission,
                        method="GET",
                        url=target_url,
                        params=test_params,
                        headers=headers,
                        cookies=cookies,
                    )
                    if resp:
                        res = self.analyzer.analyze_response(
                            resp, p_info, baseline_response=baseline_resp, parameter_name=param_name, parameter_type="query_param"
                        )
                        if res and res.is_valid_finding:
                            ev = self._create_evidence_and_update_state(
                                mission=mission,
                                target_url=target_url,
                                base_url=base_url,
                                param=param_name,
                                param_type="query_param",
                                payload=str(p_info["payload"]),
                                status_code=getattr(resp, "status_code", 200) or 200,
                                result=res,
                            )
                            detected_evidence.append(ev)
                            confirmed_findings.add(finding_key)
                            break

            # Channel 3: Cookies
            cookies_to_test = list(cookies.keys()) if cookies else self.COMMON_DESERIALIZATION_COOKIES[:4]
            for cookie_name in cookies_to_test:
                for p_info in all_mutated_payloads[: self.max_probes_per_endpoint]:
                    finding_key = f"{target_url}:cookie:{cookie_name}:{p_info['format']}"
                    if finding_key in confirmed_findings:
                        continue

                    test_cookies = dict(cookies)
                    test_cookies[cookie_name] = p_info["payload"]
                    resp = self._execute_request(
                        mission,
                        method="GET",
                        url=target_url,
                        headers=headers,
                        cookies=test_cookies,
                    )
                    if resp:
                        res = self.analyzer.analyze_response(
                            resp, p_info, baseline_response=baseline_resp, parameter_name=cookie_name, parameter_type="cookie"
                        )
                        if res and res.is_valid_finding:
                            ev = self._create_evidence_and_update_state(
                                mission=mission,
                                target_url=target_url,
                                base_url=base_url,
                                param=cookie_name,
                                param_type="cookie",
                                payload=str(p_info["payload"]),
                                status_code=getattr(resp, "status_code", 200) or 200,
                                result=res,
                            )
                            detected_evidence.append(ev)
                            confirmed_findings.add(finding_key)
                            break

            # Channel 4: Custom Headers
            for header_name in self.COMMON_DESERIALIZATION_HEADERS:
                for p_info in all_mutated_payloads[: self.max_probes_per_endpoint]:
                    finding_key = f"{target_url}:header:{header_name}:{p_info['format']}"
                    if finding_key in confirmed_findings:
                        continue

                    test_headers = dict(headers)
                    test_headers[header_name] = p_info["payload"]
                    resp = self._execute_request(
                        mission,
                        method=ep_method,
                        url=target_url,
                        headers=test_headers,
                        cookies=cookies,
                    )
                    if resp:
                        res = self.analyzer.analyze_response(
                            resp, p_info, baseline_response=baseline_resp, parameter_name=header_name, parameter_type="header"
                        )
                        if res and res.is_valid_finding:
                            ev = self._create_evidence_and_update_state(
                                mission=mission,
                                target_url=target_url,
                                base_url=base_url,
                                param=header_name,
                                param_type="header",
                                payload=str(p_info["payload"]),
                                status_code=getattr(resp, "status_code", 200) or 200,
                                result=res,
                            )
                            detected_evidence.append(ev)
                            confirmed_findings.add(finding_key)
                            break

        logger.info(
            f"DeserializationCollector complete: {len(detected_evidence)} insecure deserialization finding(s) confirmed."
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
        result: DeserializationResult,
    ) -> Evidence:
        """
        Constructs Evidence, appends to mission.evidence & mission.vulnerabilities,
        and expands the KnowledgeGraph attack surface with HAS_ENDPOINT and HAS_VULNERABILITY edges.
        """
        raw_mission = getattr(mission, "_mission", mission)
        template_id = result.template_id or "deserialization"
        fmt = result.format
        technique = result.technique
        severity = result.severity
        confidence = result.confidence
        snippet = result.evidence_snippet
        mutation = result.mutation_strategy

        parsed_url = urllib.parse.urlparse(target_url)
        url_path = parsed_url.path or "/"

        format_labels = {
            DeserializationFormat.JAVA.value: "Java ObjectInputStream",
            DeserializationFormat.PYTHON_PICKLE.value: "Python Pickle",
            DeserializationFormat.PHP_SERIALIZE.value: "PHP Serialize",
            DeserializationFormat.RUBY_MARSHAL.value: "Ruby Marshal",
            DeserializationFormat.DOTNET_VIEWSTATE.value: ".NET ViewState",
            DeserializationFormat.DOTNET_BINARY_FORMATTER.value: ".NET BinaryFormatter",
        }
        fmt_label = format_labels.get(fmt, fmt.title())

        title = f"Insecure Deserialization ({fmt_label}): {param} on {target_url}"
        description = (
            f"Insecure deserialization vulnerability ({fmt_label} / {mutation}) confirmed on endpoint {target_url} "
            f"via {param_type} '{param}' using payload: '{payload[:100]}...'. "
            f"Evidence signature: {result.matched_signature}. Snippet: {snippet[:200]}"
        )

        ev = Evidence(
            mission_id=getattr(raw_mission, "id", ""),
            source_type="LOG",
            created_by="SYSTEM_GENERATED",
            title=title,
            description=description,
            category="deserialization",
            value=target_url,
            source=target_url,
            status="CONFIRMED",
            confidence=confidence,
            severity=severity,
            provenance=ProvenanceData(
                step_id="deserialization_validation_collector",
            ),
            tags=["deserialization", "insecure_deserialization", "cwe-502", fmt, technique, template_id],
            metadata={
                "url": target_url,
                "host": base_url,
                "path": url_path,
                "parameter": param,
                "parameter_type": param_type,
                "payload": payload,
                "category": "deserialization",
                "severity": severity,
                "confidence": confidence,
                "format": fmt,
                "technique": technique,
                "mutation_strategy": mutation,
                "matched_signature": result.matched_signature,
                "template_id": template_id,
                "status_code": status_code,
                "evidence_snippet": snippet[:250],
                "delay_delta": result.delay_delta,
                "baseline_elapsed": result.baseline_elapsed,
                "injected_elapsed": result.injected_elapsed,
                "cwe_id": "CWE-502",
                "cvss_score": 9.8 if severity == Severity.CRITICAL.value else 8.5,
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
                "name": f"Insecure Deserialization ({fmt_label})",
                "template_id": template_id,
                "severity": severity,
                "host": base_url,
                "url": target_url,
                "description": description,
                "parameter": param,
                "parameter_type": param_type,
                "payload": payload,
                "format": fmt,
                "technique": technique,
                "mutation_strategy": mutation,
                "cwe_id": "CWE-502",
            })

        # 3. KnowledgeGraph Node & Edge Expansion
        graph = getattr(raw_mission, "attack_surface_graph", None) or getattr(raw_mission, "graph", None)
        if graph is not None and hasattr(graph, "add") and hasattr(graph, "connect"):
            lh_id = f"live_host:{base_url}"
            ep_id = f"endpoint:{target_url}"
            vuln_id = f"vulnerability:{template_id}:{target_url}:{param}"

            graph.add(Node(id=lh_id, type="live_host", value=base_url, metadata={"url": base_url}))
            graph.add(Node(id=ep_id, type="endpoint", value=target_url, metadata={"url": target_url, "status_code": status_code}))
            graph.add(Node(id=vuln_id, type="vulnerability", value=f"Insecure Deserialization ({fmt_label})", metadata=ev.metadata))

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

InsecureDeserializationCollector = DeserializationCollector

DeserializationValidationCollector = DeserializationCollector
