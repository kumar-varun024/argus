"""Active OS command-injection fuzzing collector."""
from __future__ import annotations

import json
import logging
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Set

from argus.collectors.base import BaseCollector
from argus.collectors.toolkit.enums import Severity
from argus.evidence.model import Evidence, ProvenanceData
from argus.graph.node import Node
from argus.http.client import AuthenticatedHttpClient, HttpResponse
from argus.collectors.command_injection.models import DEFAULT_CMDI_PROBE_ROUTES
from argus.collectors.command_injection.payloads import CommandInjectionPayloadGenerator
from argus.collectors.command_injection.analyzer import CommandInjectionAnalyzer

logger = logging.getLogger(__name__)


class CommandInjectionCollector(BaseCollector):
    """
    ARGUS Collector for active OS Command Injection (CMDi) detection.
    Fuzzes GET query parameters, POST body fields (form and JSON), path segments,
    and HTTP headers using AuthenticatedHttpClient.
    """

    def __init__(
        self,
        http_client: Optional[AuthenticatedHttpClient] = None,
        timeout: float = 15.0,
        delay_threshold: float = 4.0,
    ):
        self.http_client = http_client
        self.timeout = timeout
        self.delay_threshold = delay_threshold
        self.generator = CommandInjectionPayloadGenerator()
        self.analyzer = CommandInjectionAnalyzer()

    def _extract_candidate_endpoints(self, raw_mission: Any) -> List[Dict[str, Any]]:
        """
        Extracts and normalizes target endpoints from mission state or constructs
        standard probe routes against discovered live hosts and target URL.
        """
        candidates: List[Dict[str, Any]] = []
        seen_urls: Set[str] = set()

        # 1. Inspect mission.endpoints
        endpoints = getattr(raw_mission, "endpoints", []) or []
        for ep in endpoints:
            url = None
            method = "GET"
            params: Dict[str, Any] = {}
            body: Any = None
            headers: Dict[str, str] = {}

            if isinstance(ep, str):
                url = ep
            elif isinstance(ep, dict):
                url = ep.get("url") or ep.get("endpoint")
                method = ep.get("method", "GET").upper()
                params = ep.get("params") or {}
                body = ep.get("body")
                headers = ep.get("headers") or {}
            elif hasattr(ep, "url"):
                url = getattr(ep, "url")
                method = getattr(ep, "method", "GET")

            if url and isinstance(url, str) and url.startswith("http") and url not in seen_urls:
                seen_urls.add(url)
                parsed = urllib.parse.urlparse(url)
                base_url = f"{parsed.scheme}://{parsed.netloc}"
                candidates.append({
                    "url": url,
                    "base_url": base_url,
                    "path": parsed.path or "/",
                    "method": method,
                    "params": params,
                    "body": body,
                    "headers": headers,
                    "source": "mission.endpoints",
                })

        # 2. Inspect mission.live_hosts or mission.subdomains
        live_hosts = getattr(raw_mission, "live_hosts", []) or []
        target = getattr(raw_mission, "target", "") or ""
        host_urls: List[str] = []

        for lh in live_hosts:
            if isinstance(lh, str) and lh.startswith("http"):
                host_urls.append(lh)
            elif isinstance(lh, dict) and lh.get("url"):
                host_urls.append(lh["url"])
            elif isinstance(lh, str) and lh:
                host_urls.append(f"http://{lh}")

        if not host_urls and target:
            host_urls.append(target if target.startswith("http") else f"http://{target}")

        for base_url in host_urls:
            parsed_base = urllib.parse.urlparse(base_url)
            clean_base = f"{parsed_base.scheme}://{parsed_base.netloc}" if parsed_base.netloc else base_url
            if clean_base not in seen_urls and not candidates:
                seen_urls.add(clean_base)
                candidates.append({
                    "url": clean_base,
                    "base_url": clean_base,
                    "path": "/",
                    "method": "GET",
                    "params": {},
                    "body": None,
                    "headers": {},
                    "source": "live_host",
                })

            # If fewer than 5 candidate endpoints exist, seed with common probe routes
            if len(candidates) < 5:
                for route in DEFAULT_CMDI_PROBE_ROUTES[:4]:
                    probe_url = f"{clean_base.rstrip('/')}{route}"
                    if probe_url not in seen_urls:
                        seen_urls.add(probe_url)
                        candidates.append({
                            "url": probe_url,
                            "base_url": clean_base,
                            "path": route,
                            "method": "GET",
                            "params": {"ip": "127.0.0.1"},
                            "body": None,
                            "headers": {},
                            "source": "default_probe",
                        })

        return candidates

    def _execute_request(
        self,
        mission: Any,
        method: str,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        json_data: Optional[Any] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
    ) -> Optional[HttpResponse]:
        """
        Dispatches HTTP request using custom injected client or AuthenticatedHttpClient.
        """
        method = method.upper()
        try:
            if self.http_client is not None:
                if method == "GET" and hasattr(self.http_client, "get"):
                    try:
                        return self.http_client.get(
                            mission, url, params=params, headers=headers, cookies=cookies, timeout=self.timeout
                        )
                    except TypeError:
                        try:
                            return self.http_client.get(mission, url, timeout=self.timeout)
                        except TypeError:
                            return self.http_client.get(url)
                elif method == "POST" and hasattr(self.http_client, "post"):
                    try:
                        return self.http_client.post(
                            mission, url, data=data, json=json_data, headers=headers, cookies=cookies, timeout=self.timeout
                        )
                    except TypeError:
                        try:
                            return self.http_client.post(mission, url, timeout=self.timeout)
                        except TypeError:
                            return self.http_client.post(url)
                elif hasattr(self.http_client, "request"):
                    try:
                        return self.http_client.request(
                            mission, method, url, params=params, data=data, json=json_data, headers=headers, cookies=cookies, timeout=self.timeout
                        )
                    except TypeError:
                        return self.http_client.request(method, url)
                elif callable(self.http_client):
                    return self.http_client(url)
                return None

            with AuthenticatedHttpClient(timeout=self.timeout, max_retries=1) as client:
                if method == "GET":
                    return client.get(mission, url, params=params, headers=headers, cookies=cookies, timeout=self.timeout)
                elif method == "POST":
                    return client.post(mission, url, data=data, json=json_data, headers=headers, cookies=cookies, timeout=self.timeout)
                else:
                    return client.request(mission, method, url, params=params, data=data, json=json_data, headers=headers, cookies=cookies, timeout=self.timeout)
        except Exception as e:
            logger.debug(f"CommandInjectionCollector request failed for {url}: {e}")
            return None

    def collect(self, mission: Any) -> List[Evidence]:
        """
        Executes active OS command injection fuzzing across discovered endpoints and parameters.
        """
        raw_mission = getattr(mission, "_mission", mission)
        candidates = self._extract_candidate_endpoints(raw_mission)
        if not candidates:
            logger.info("CommandInjectionCollector: No candidate endpoints or hosts to fuzz.")
            return []

        logger.info(f"CommandInjectionCollector: Fuzzing {len(candidates)} candidate endpoint(s)...")

        detected_evidence: List[Evidence] = []
        confirmed_vuln_keys: Set[str] = set()

        result_payload_entries = self.generator.generate_result_payloads()
        time_payload_entries = self.generator.generate_time_payloads(delay=5)
        error_payloads = self.generator.generate_error_payloads()

        for candidate in candidates:
            orig_url = candidate["url"]
            base_url = candidate["base_url"]
            parsed_url = urllib.parse.urlparse(orig_url)
            method = candidate.get("method", "GET")
            raw_params = candidate.get("params") or {}
            body_data = candidate.get("body")
            headers_data = dict(candidate.get("headers") or {})

            # 0. Measure Baseline
            start_base = time.time()
            baseline_resp = self._execute_request(
                mission=raw_mission,
                method=method,
                url=orig_url,
                params=raw_params if method == "GET" else None,
                data=body_data if method == "POST" and isinstance(body_data, dict) else None,
                headers=headers_data,
            )
            baseline_elapsed = getattr(baseline_resp, "elapsed", 0.0) if baseline_resp else (time.time() - start_base)

            # -------------------------------------------------------------
            # Vector 1: GET Query Parameters
            # -------------------------------------------------------------
            query_params = urllib.parse.parse_qs(parsed_url.query, keep_blank_values=True)
            if not query_params and raw_params and method == "GET":
                for k, v in raw_params.items():
                    query_params[k] = [str(v)]

            # If no parameters in URL but route is common command route and method is GET, test common params
            if not query_params and method == "GET" and (candidate.get("source") == "default_probe" or parsed_url.path in DEFAULT_CMDI_PROBE_ROUTES):
                query_params = {"ip": ["127.0.0.1"], "cmd": ["test"]}

            if query_params:
                for param_name in list(query_params.keys()):
                    param_vuln_found = False

                    # 1.1 Result-Based Fuzzing
                    for entry in result_payload_entries:
                        cmd = entry["cmd"]
                        mutated_variants = self.generator.generate_mutated_payloads(cmd)
                        # Test raw and top mutated variants
                        for payload in mutated_variants[:6]:
                            mut_query = dict(query_params)
                            mut_query[param_name] = [payload]
                            target_url = urllib.parse.urlunparse((
                                parsed_url.scheme, parsed_url.netloc, parsed_url.path,
                                parsed_url.params, urllib.parse.urlencode(mut_query, doseq=True), parsed_url.fragment,
                            ))

                            resp = self._execute_request(mission, "GET", target_url, headers=headers_data)
                            if not resp:
                                continue

                            analysis = self.analyzer.analyze_result_based(
                                response=resp,
                                baseline=baseline_resp,
                                payload_info=entry,
                            )
                            if analysis:
                                vuln_key = f"{parsed_url.path}:{param_name}:{analysis['template_id']}"
                                if vuln_key not in confirmed_vuln_keys:
                                    confirmed_vuln_keys.add(vuln_key)
                                    ev = self._create_evidence_and_update_state(
                                        mission=mission,
                                        target_url=target_url,
                                        base_url=base_url,
                                        param=param_name,
                                        param_type="query",
                                        payload=payload,
                                        status_code=getattr(resp, "status_code", 200) or 200,
                                        analysis=analysis,
                                    )
                                    detected_evidence.append(ev)
                                    param_vuln_found = True
                                    break
                        if param_vuln_found:
                            break

                    # 1.2 Time-Based Blind Fuzzing
                    if not param_vuln_found:
                        for entry in time_payload_entries[:3]:
                            cmd = entry["cmd"]
                            mutated_variants = self.generator.generate_mutated_payloads(cmd)
                            for payload in mutated_variants[:4]:
                                mut_query = dict(query_params)
                                mut_query[param_name] = [payload]
                                target_url = urllib.parse.urlunparse((
                                    parsed_url.scheme, parsed_url.netloc, parsed_url.path,
                                    parsed_url.params, urllib.parse.urlencode(mut_query, doseq=True), parsed_url.fragment,
                                ))

                                resp = self._execute_request(mission, "GET", target_url, headers=headers_data)
                                if not resp:
                                    continue

                                analysis = self.analyzer.analyze_time_blind(
                                    injected_resp=resp,
                                    baseline_resp=baseline_resp,
                                    threshold=self.delay_threshold,
                                )
                                if analysis:
                                    vuln_key = f"{parsed_url.path}:{param_name}:{analysis['template_id']}"
                                    if vuln_key not in confirmed_vuln_keys:
                                        confirmed_vuln_keys.add(vuln_key)
                                        ev = self._create_evidence_and_update_state(
                                            mission=mission,
                                            target_url=target_url,
                                            base_url=base_url,
                                            param=param_name,
                                            param_type="query",
                                            payload=payload,
                                            status_code=getattr(resp, "status_code", 200) or 200,
                                            analysis=analysis,
                                        )
                                        detected_evidence.append(ev)
                                        param_vuln_found = True
                                        break
                            if param_vuln_found:
                                break

                    # 1.3 Error-Based Fuzzing
                    if not param_vuln_found:
                        for payload in error_payloads[:5]:
                            mut_query = dict(query_params)
                            mut_query[param_name] = [payload]
                            target_url = urllib.parse.urlunparse((
                                parsed_url.scheme, parsed_url.netloc, parsed_url.path,
                                parsed_url.params, urllib.parse.urlencode(mut_query, doseq=True), parsed_url.fragment,
                            ))

                            resp = self._execute_request(mission, "GET", target_url, headers=headers_data)
                            if not resp:
                                continue

                            analysis = self.analyzer.analyze_error_based(
                                response=resp,
                                baseline=baseline_resp,
                                payload=payload,
                            )
                            if analysis:
                                vuln_key = f"{parsed_url.path}:{param_name}:{analysis['template_id']}"
                                if vuln_key not in confirmed_vuln_keys:
                                    confirmed_vuln_keys.add(vuln_key)
                                    ev = self._create_evidence_and_update_state(
                                        mission=mission,
                                        target_url=target_url,
                                        base_url=base_url,
                                        param=param_name,
                                        param_type="query",
                                        payload=payload,
                                        status_code=getattr(resp, "status_code", 200) or 200,
                                        analysis=analysis,
                                    )
                                    detected_evidence.append(ev)
                                    param_vuln_found = True
                                    break

            # -------------------------------------------------------------
            # Vector 2: POST Body (JSON & Form-Urlencoded)
            # -------------------------------------------------------------
            post_fields: Dict[str, Any] = {}
            is_json_body = False
            if method == "POST" or body_data is not None:
                if isinstance(body_data, dict):
                    post_fields = dict(body_data)
                    is_json_body = True
                elif isinstance(body_data, str) and body_data.strip().startswith("{"):
                    try:
                        post_fields = json.loads(body_data)
                        is_json_body = True
                    except Exception:
                        pass
                elif raw_params and method == "POST":
                    post_fields = dict(raw_params)

            if post_fields:
                clean_target_url = urllib.parse.urlunparse((
                    parsed_url.scheme, parsed_url.netloc, parsed_url.path, "", "", ""
                ))
                for field_name in list(post_fields.keys()):
                    post_vuln_found = False

                    # 2.1 Result-based
                    for entry in result_payload_entries:
                        cmd = entry["cmd"]
                        mutated_variants = self.generator.generate_mutated_payloads(cmd)
                        for payload in mutated_variants[:5]:
                            mut_body = dict(post_fields)
                            mut_body[field_name] = payload

                            if is_json_body:
                                resp = self._execute_request(mission, "POST", clean_target_url, json_data=mut_body, headers=headers_data)
                            else:
                                resp = self._execute_request(mission, "POST", clean_target_url, data=mut_body, headers=headers_data)

                            if not resp:
                                continue

                            analysis = self.analyzer.analyze_result_based(resp, baseline=baseline_resp, payload_info=entry)
                            if analysis:
                                vuln_key = f"{parsed_url.path}:{field_name}:{analysis['template_id']}"
                                if vuln_key not in confirmed_vuln_keys:
                                    confirmed_vuln_keys.add(vuln_key)
                                    ev = self._create_evidence_and_update_state(
                                        mission=mission,
                                        target_url=clean_target_url,
                                        base_url=base_url,
                                        param=field_name,
                                        param_type="json" if is_json_body else "body",
                                        payload=payload,
                                        status_code=getattr(resp, "status_code", 200) or 200,
                                        analysis=analysis,
                                    )
                                    detected_evidence.append(ev)
                                    post_vuln_found = True
                                    break
                        if post_vuln_found:
                            break

                    # 2.2 Time-based
                    if not post_vuln_found:
                        for entry in time_payload_entries[:2]:
                            cmd = entry["cmd"]
                            mutated_variants = self.generator.generate_mutated_payloads(cmd)
                            for payload in mutated_variants[:3]:
                                mut_body = dict(post_fields)
                                mut_body[field_name] = payload

                                if is_json_body:
                                    resp = self._execute_request(mission, "POST", clean_target_url, json_data=mut_body, headers=headers_data)
                                else:
                                    resp = self._execute_request(mission, "POST", clean_target_url, data=mut_body, headers=headers_data)

                                if not resp:
                                    continue

                                analysis = self.analyzer.analyze_time_blind(resp, baseline_resp=baseline_resp, threshold=self.delay_threshold)
                                if analysis:
                                    vuln_key = f"{parsed_url.path}:{field_name}:{analysis['template_id']}"
                                    if vuln_key not in confirmed_vuln_keys:
                                        confirmed_vuln_keys.add(vuln_key)
                                        ev = self._create_evidence_and_update_state(
                                            mission=mission,
                                            target_url=clean_target_url,
                                            base_url=base_url,
                                            param=field_name,
                                            param_type="json" if is_json_body else "body",
                                            payload=payload,
                                            status_code=getattr(resp, "status_code", 200) or 200,
                                            analysis=analysis,
                                        )
                                        detected_evidence.append(ev)
                                        post_vuln_found = True
                                        break
                            if post_vuln_found:
                                break

                    # 2.3 Error-based
                    if not post_vuln_found:
                        for payload in error_payloads[:4]:
                            mut_body = dict(post_fields)
                            mut_body[field_name] = payload

                            if is_json_body:
                                resp = self._execute_request(mission, "POST", clean_target_url, json_data=mut_body, headers=headers_data)
                            else:
                                resp = self._execute_request(mission, "POST", clean_target_url, data=mut_body, headers=headers_data)

                            if not resp:
                                continue

                            analysis = self.analyzer.analyze_error_based(resp, baseline=baseline_resp, payload=payload)
                            if analysis:
                                vuln_key = f"{parsed_url.path}:{field_name}:{analysis['template_id']}"
                                if vuln_key not in confirmed_vuln_keys:
                                    confirmed_vuln_keys.add(vuln_key)
                                    ev = self._create_evidence_and_update_state(
                                        mission=mission,
                                        target_url=clean_target_url,
                                        base_url=base_url,
                                        param=field_name,
                                        param_type="json" if is_json_body else "body",
                                        payload=payload,
                                        status_code=getattr(resp, "status_code", 200) or 200,
                                        analysis=analysis,
                                    )
                                    detected_evidence.append(ev)
                                    post_vuln_found = True
                                    break

            # -------------------------------------------------------------
            # Vector 3: RESTful Path Segments
            # -------------------------------------------------------------
            path_segments = [s for s in parsed_url.path.strip("/").split("/") if s]
            if path_segments:
                for idx, segment in enumerate(path_segments):
                    # Fuzz ID-like or resource-like segments
                    if segment.isdigit() or len(segment) > 10 or segment in ("view", "item", "tools", "ping", "test", "run"):
                        for entry in result_payload_entries[:4]:
                            cmd = entry["cmd"]
                            for payload in [f"; {cmd}", f"| {cmd}", f"%0a{cmd}", f"`{cmd}`"]:
                                mutated_segs = list(path_segments)
                                mutated_segs[idx] = f"{segment}{payload}"
                                mut_path = "/" + "/".join(mutated_segs)
                                target_url = urllib.parse.urlunparse((
                                    parsed_url.scheme, parsed_url.netloc, mut_path,
                                    parsed_url.params, parsed_url.query, parsed_url.fragment,
                                ))

                                resp = self._execute_request(mission, "GET", target_url, headers=headers_data)
                                if not resp:
                                    continue

                                analysis = self.analyzer.analyze_result_based(resp, baseline=baseline_resp, payload_info=entry)
                                if analysis:
                                    vuln_key = f"{parsed_url.path}:path_segment_{idx}:{analysis['template_id']}"
                                    if vuln_key not in confirmed_vuln_keys:
                                        confirmed_vuln_keys.add(vuln_key)
                                        ev = self._create_evidence_and_update_state(
                                            mission=mission,
                                            target_url=target_url,
                                            base_url=base_url,
                                            param=f"path_segment_{idx}",
                                            param_type="path",
                                            payload=payload,
                                            status_code=getattr(resp, "status_code", 200) or 200,
                                            analysis=analysis,
                                        )
                                        detected_evidence.append(ev)
                                        break

            # -------------------------------------------------------------
            # Vector 4: HTTP Request Headers (User-Agent, Referer, Cookie, X-Forwarded-For)
            # -------------------------------------------------------------
            header_targets = [
                ("User-Agent", "Mozilla/5.0; {payload}"),
                ("Referer", "{base_url}/{payload}"),
                ("Cookie", "session_id={payload}"),
                ("X-Forwarded-For", "127.0.0.1; {payload}"),
                ("X-Client-IP", "127.0.0.1; {payload}"),
            ]
            clean_url = urllib.parse.urlunparse((
                parsed_url.scheme, parsed_url.netloc, parsed_url.path, "", "", ""
            ))
            for header_name, template_fmt in header_targets:
                for entry in result_payload_entries[:3]:
                    cmd = entry["cmd"]
                    for payload in [f"; {cmd}", f"| {cmd}", f"`{cmd}`", f"$({cmd})"]:
                        injected_val = template_fmt.format(payload=payload, base_url=base_url)
                        mut_headers = dict(headers_data)
                        mut_headers[header_name] = injected_val

                        resp = self._execute_request(mission, "GET", clean_url, headers=mut_headers)
                        if not resp:
                            continue

                        analysis = self.analyzer.analyze_result_based(resp, baseline=baseline_resp, payload_info=entry)
                        if analysis:
                            vuln_key = f"{parsed_url.path}:{header_name}:{analysis['template_id']}"
                            if vuln_key not in confirmed_vuln_keys:
                                confirmed_vuln_keys.add(vuln_key)
                                ev = self._create_evidence_and_update_state(
                                    mission=mission,
                                    target_url=clean_url,
                                    base_url=base_url,
                                    param=header_name,
                                    param_type="header",
                                    payload=payload,
                                    status_code=getattr(resp, "status_code", 200) or 200,
                                    analysis=analysis,
                                )
                                detected_evidence.append(ev)
                                break

        logger.info(
            f"CommandInjectionCollector complete: {len(detected_evidence)} command injection vulnerability(ies) identified."
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
        analysis: Dict[str, Any],
    ) -> Evidence:
        """
        Constructs Evidence, appends to mission.evidence & mission.vulnerabilities,
        and expands the KnowledgeGraph attack surface with HAS_ENDPOINT and HAS_VULNERABILITY edges.
        """
        raw_mission = getattr(mission, "_mission", mission)
        template_id = analysis.get("template_id", "cmdi")
        technique = analysis.get("technique", "result_based")
        severity = analysis.get("severity", Severity.CRITICAL)
        if isinstance(severity, Severity):
            severity = severity.value
        confidence = analysis.get("confidence", 0.95)
        snippet = analysis.get("snippet", "")
        os_family = analysis.get("os_family", "generic")

        parsed_url = urllib.parse.urlparse(target_url)
        url_path = parsed_url.path or "/"

        technique_labels = {
            "result_based": f"Result-Based ({os_family.upper()})",
            "time_blind": "Time-Based Blind Delay",
            "error_based": "Error-Based Shell Trigger",
        }
        tech_label = technique_labels.get(technique, technique)

        title = f"Command Injection: {param} on {target_url}"
        description = (
            f"OS Command Injection ({tech_label}) vulnerability confirmed on endpoint {target_url} "
            f"via {param_type} parameter '{param}' using payload '{payload}'. "
            f"Evidence: {snippet[:200]}"
        )

        ev = Evidence(
            mission_id=getattr(raw_mission, "id", ""),
            source_type="LOG",
            created_by="SYSTEM_GENERATED",
            title=title,
            description=description,
            category="command_injection",
            value=target_url,
            source=target_url,
            status="CONFIRMED",
            confidence=confidence,
            severity=severity,
            provenance=ProvenanceData(
                step_id="command_injection_collector",
            ),
            tags=["command_injection", "cmdi", "rce", technique, template_id],
            metadata={
                "url": target_url,
                "host": base_url,
                "path": url_path,
                "parameter": param,
                "parameter_type": param_type,
                "payload": payload,
                "category": "command_injection",
                "severity": severity,
                "technique": technique,
                "template_id": template_id,
                "os_family": os_family,
                "status_code": status_code,
                "evidence_snippet": snippet[:250],
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
                "name": f"Command Injection ({tech_label})",
                "template_id": template_id,
                "severity": severity,
                "host": base_url,
                "url": target_url,
                "description": description,
                "parameter": param,
                "parameter_type": param_type,
                "payload": payload,
                "technique": technique,
                "os_family": os_family,
            })

        # 3. KnowledgeGraph Node & Edge Expansion
        graph = getattr(raw_mission, "attack_surface_graph", None) or getattr(raw_mission, "graph", None)
        if graph is not None and hasattr(graph, "add") and hasattr(graph, "connect"):
            lh_id = f"live_host:{base_url}"
            ep_id = f"endpoint:{target_url}"
            vuln_id = f"vulnerability:{template_id}:{target_url}:{param}"

            graph.add(Node(id=lh_id, type="live_host", value=base_url, metadata={"url": base_url}))
            graph.add(Node(id=ep_id, type="endpoint", value=target_url, metadata={"url": target_url, "status_code": status_code}))
            graph.add(Node(id=vuln_id, type="vulnerability", value=f"Command Injection ({tech_label})", metadata=ev.metadata))

            graph.connect(lh_id, ep_id, edge_type="HAS_ENDPOINT")
            graph.connect(lh_id, vuln_id, edge_type="HAS_VULNERABILITY")
            graph.connect(ep_id, vuln_id, edge_type="HAS_VULNERABILITY")

        # 4. Publish to ControlledMission wrapper
        if mission is not raw_mission and hasattr(mission, "publish_finding"):
            try:
                mission.publish_finding(ev.evidence_id if hasattr(ev, "evidence_id") else getattr(ev, "id", ""), ev)
            except Exception:
                pass

        return ev

    def execute(self, mission: Any) -> List[Evidence]:
        """Plugin / Specialist adapter interface."""
        return self.collect(mission)

