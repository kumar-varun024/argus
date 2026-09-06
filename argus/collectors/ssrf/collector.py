"""ssrf: Collector orchestration."""
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
from argus.collectors.ssrf.models import DEFAULT_SSRF_PROBE_ROUTES, SSRFTechnique
from argus.collectors.ssrf.payloads import SSRFPayloadGenerator
from argus.collectors.ssrf.analyzer import SSRFAnalyzer

logger = logging.getLogger(__name__)


class SSRFCollector(BaseCollector):
    """
    ARGUS Collector for active Server-Side Request Forgery (SSRF) validation.
    Fuzzes GET query parameters, POST body fields (form and JSON), RESTful path segments,
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
        self.generator = SSRFPayloadGenerator()
        self.analyzer = SSRFAnalyzer()

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

            # If fewer than 5 candidate endpoints exist, seed with common SSRF probe routes
            if len(candidates) < 5:
                for route in DEFAULT_SSRF_PROBE_ROUTES[:4]:
                    probe_url = f"{clean_base.rstrip('/')}{route}"
                    if probe_url not in seen_urls:
                        seen_urls.add(probe_url)
                        candidates.append({
                            "url": probe_url,
                            "base_url": clean_base,
                            "path": route,
                            "method": "GET",
                            "params": {"url": "http://127.0.0.1"},
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
            logger.debug(f"SSRFCollector request failed for {url}: {e}")
            return None

    def collect(self, mission: Any) -> List[Evidence]:
        """
        Executes active Server-Side Request Forgery (SSRF) fuzzing across discovered endpoints and parameters.
        """
        raw_mission = getattr(mission, "_mission", mission)
        candidates = self._extract_candidate_endpoints(raw_mission)
        if not candidates:
            logger.info("SSRFCollector: No candidate endpoints or hosts to fuzz.")
            return []

        logger.info(f"SSRFCollector: Fuzzing {len(candidates)} candidate endpoint(s)...")

        detected_evidence: List[Evidence] = []
        confirmed_vuln_keys: Set[str] = set()

        cloud_targets = self.generator.generate_cloud_metadata_payloads()
        internal_targets = self.generator.generate_internal_service_payloads()
        timing_targets = self.generator.generate_timing_payloads(delay=5.0)

        for candidate in candidates:
            orig_url = candidate["url"]
            base_url = candidate["base_url"]
            parsed_url = urllib.parse.urlparse(orig_url)
            method = candidate.get("method", "GET")
            raw_params = candidate.get("params") or {}
            body_data = candidate.get("body")
            headers_data = dict(candidate.get("headers") or {})

            # 0. Measure Baseline Response
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

            # If no parameters in URL but route is common SSRF probe route, test common SSRF params
            if not query_params and method == "GET" and (candidate.get("source") == "default_probe" or parsed_url.path in DEFAULT_SSRF_PROBE_ROUTES):
                query_params = {"url": ["http://127.0.0.1"], "target": ["http://localhost"]}

            if query_params:
                for param_name in list(query_params.keys()):
                    param_vuln_found = False

                    # 1.1 Cloud Metadata Fuzzing
                    for target_info in cloud_targets:
                        base_target_url = target_info["url"]
                        mutated_variants = self.generator.generate_mutated_payloads(base_target_url)
                        for payload in mutated_variants[:6]:
                            mut_query = dict(query_params)
                            mut_query[param_name] = [payload]
                            target_url = urllib.parse.urlunparse((
                                parsed_url.scheme, parsed_url.netloc, parsed_url.path,
                                parsed_url.params, urllib.parse.urlencode(mut_query, doseq=True), parsed_url.fragment,
                            ))

                            req_headers = dict(headers_data)
                            if "headers" in target_info:
                                req_headers.update(target_info["headers"])

                            resp = self._execute_request(mission, "GET", target_url, headers=req_headers)
                            if not resp:
                                continue

                            analysis = self.analyzer.analyze_cloud_metadata(
                                response=resp,
                                baseline=baseline_resp,
                                target_info=target_info,
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

                    # 1.2 Internal Service Fuzzing
                    if not param_vuln_found:
                        for target_info in internal_targets:
                            base_target_url = target_info["url"]
                            mutated_variants = self.generator.generate_mutated_payloads(base_target_url)
                            for payload in mutated_variants[:5]:
                                mut_query = dict(query_params)
                                mut_query[param_name] = [payload]
                                target_url = urllib.parse.urlunparse((
                                    parsed_url.scheme, parsed_url.netloc, parsed_url.path,
                                    parsed_url.params, urllib.parse.urlencode(mut_query, doseq=True), parsed_url.fragment,
                                ))

                                resp = self._execute_request(mission, "GET", target_url, headers=headers_data)
                                if not resp:
                                    continue

                                analysis = self.analyzer.analyze_internal_service(
                                    response=resp,
                                    baseline=baseline_resp,
                                    target_info=target_info,
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

                    # 1.3 Differential Timing Fuzzing
                    if not param_vuln_found:
                        for target_info in timing_targets[:2]:
                            drop_url = target_info["url"]
                            mut_query = dict(query_params)
                            mut_query[param_name] = [drop_url]
                            target_url = urllib.parse.urlunparse((
                                parsed_url.scheme, parsed_url.netloc, parsed_url.path,
                                parsed_url.params, urllib.parse.urlencode(mut_query, doseq=True), parsed_url.fragment,
                            ))

                            resp = self._execute_request(mission, "GET", target_url, headers=headers_data)
                            if not resp:
                                continue

                            analysis = self.analyzer.analyze_differential_timing(
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
                                        payload=drop_url,
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

            if not post_fields and method == "POST" and (candidate.get("source") == "default_probe" or parsed_url.path in DEFAULT_SSRF_PROBE_ROUTES):
                post_fields = {"url": "http://127.0.0.1", "target": "http://localhost"}

            if post_fields:
                clean_target_url = urllib.parse.urlunparse((
                    parsed_url.scheme, parsed_url.netloc, parsed_url.path, "", "", ""
                ))
                for field_name in list(post_fields.keys()):
                    post_vuln_found = False

                    # 2.1 Cloud Metadata
                    for target_info in cloud_targets:
                        base_target_url = target_info["url"]
                        mutated_variants = self.generator.generate_mutated_payloads(base_target_url)
                        for payload in mutated_variants[:5]:
                            mut_body = dict(post_fields)
                            mut_body[field_name] = payload

                            req_headers = dict(headers_data)
                            if "headers" in target_info:
                                req_headers.update(target_info["headers"])

                            if is_json_body:
                                resp = self._execute_request(mission, "POST", clean_target_url, json_data=mut_body, headers=req_headers)
                            else:
                                resp = self._execute_request(mission, "POST", clean_target_url, data=mut_body, headers=req_headers)

                            if not resp:
                                continue

                            analysis = self.analyzer.analyze_cloud_metadata(resp, baseline=baseline_resp, target_info=target_info)
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

                    # 2.2 Internal Services
                    if not post_vuln_found:
                        for target_info in internal_targets:
                            base_target_url = target_info["url"]
                            mutated_variants = self.generator.generate_mutated_payloads(base_target_url)
                            for payload in mutated_variants[:4]:
                                mut_body = dict(post_fields)
                                mut_body[field_name] = payload

                                if is_json_body:
                                    resp = self._execute_request(mission, "POST", clean_target_url, json_data=mut_body, headers=headers_data)
                                else:
                                    resp = self._execute_request(mission, "POST", clean_target_url, data=mut_body, headers=headers_data)

                                if not resp:
                                    continue

                                analysis = self.analyzer.analyze_internal_service(resp, baseline=baseline_resp, target_info=target_info)
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

                    # 2.3 Differential Timing
                    if not post_vuln_found:
                        for target_info in timing_targets[:2]:
                            drop_url = target_info["url"]
                            mut_body = dict(post_fields)
                            mut_body[field_name] = drop_url

                            if is_json_body:
                                resp = self._execute_request(mission, "POST", clean_target_url, json_data=mut_body, headers=headers_data)
                            else:
                                resp = self._execute_request(mission, "POST", clean_target_url, data=mut_body, headers=headers_data)

                            if not resp:
                                continue

                            analysis = self.analyzer.analyze_differential_timing(resp, baseline_resp=baseline_resp, threshold=self.delay_threshold)
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
                                        payload=drop_url,
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
                    # Fuzz URL-like, fetch-like, or ID-like segments
                    if segment.isdigit() or segment.startswith("http") or "%3A" in segment.lower() or "%2f" in segment.lower() or segment in ("proxy", "fetch", "view", "preview", "download", "url", "redirect"):
                        path_vuln_found = False
                        for target_info in cloud_targets[:5]:
                            payload = target_info["url"]
                            for enc_payload in [urllib.parse.quote(payload, safe=""), payload]:
                                mutated_segs = list(path_segments)
                                mutated_segs[idx] = enc_payload
                                mut_path = "/" + "/".join(mutated_segs)
                                target_url = urllib.parse.urlunparse((
                                    parsed_url.scheme, parsed_url.netloc, mut_path,
                                    parsed_url.params, parsed_url.query, parsed_url.fragment,
                                ))

                                req_headers = dict(headers_data)
                                if "headers" in target_info:
                                    req_headers.update(target_info["headers"])

                                resp = self._execute_request(mission, "GET", target_url, headers=req_headers)
                                if not resp:
                                    continue

                                analysis = self.analyzer.analyze_cloud_metadata(resp, baseline=baseline_resp, target_info=target_info)
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
                                        path_vuln_found = True
                                        break
                            if path_vuln_found:
                                break


            # -------------------------------------------------------------
            # Vector 4: HTTP Request Headers (Referer, X-Forwarded-For, X-Forwarded-Host, X-Original-URL, X-Rewrite-URL)
            # -------------------------------------------------------------
            header_targets = [
                ("Referer", "{payload}"),
                ("X-Forwarded-For", "{payload}"),
                ("X-Forwarded-Host", "{payload}"),
                ("X-Original-URL", "{payload}"),
                ("X-Rewrite-URL", "{payload}"),
                ("X-Custom-IP-Authorization", "{payload}"),
            ]
            clean_url = urllib.parse.urlunparse((
                parsed_url.scheme, parsed_url.netloc, parsed_url.path, "", "", ""
            ))
            for header_name, template_fmt in header_targets:
                for target_info in cloud_targets[:3]:
                    payload = target_info["url"]
                    injected_val = template_fmt.format(payload=payload)
                    mut_headers = dict(headers_data)
                    mut_headers[header_name] = injected_val
                    if "headers" in target_info:
                        mut_headers.update(target_info["headers"])

                    resp = self._execute_request(mission, "GET", clean_url, headers=mut_headers)
                    if not resp:
                        continue

                    analysis = self.analyzer.analyze_cloud_metadata(resp, baseline=baseline_resp, target_info=target_info)
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
            f"SSRFCollector complete: {len(detected_evidence)} SSRF vulnerability(ies) identified."
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
        template_id = analysis.get("template_id", "ssrf")
        technique = analysis.get("technique", SSRFTechnique.CLOUD_METADATA.value)
        severity = analysis.get("severity", Severity.CRITICAL)
        if isinstance(severity, Severity):
            severity = severity.value
        confidence = analysis.get("confidence", 0.95)
        snippet = analysis.get("snippet", "")
        cloud_provider = analysis.get("cloud_provider", "")
        target_service = analysis.get("target_service", "generic")

        parsed_url = urllib.parse.urlparse(target_url)
        url_path = parsed_url.path or "/"

        technique_labels = {
            SSRFTechnique.CLOUD_METADATA.value: f"Cloud Metadata ({cloud_provider.upper() if cloud_provider else 'Generic'})",
            SSRFTechnique.INTERNAL_SERVICE.value: f"Internal Service ({target_service.upper()})",
            SSRFTechnique.DIFFERENTIAL_TIMING.value: "Differential Timing Latency",
        }
        tech_label = technique_labels.get(technique, technique)

        title = f"Server-Side Request Forgery: {param} on {target_url}"
        description = (
            f"Server-Side Request Forgery ({tech_label}) vulnerability confirmed on endpoint {target_url} "
            f"via {param_type} parameter '{param}' using payload '{payload}'. "
            f"Evidence: {snippet[:200]}"
        )

        ev = Evidence(
            mission_id=getattr(raw_mission, "id", ""),
            source_type="LOG",
            created_by="SYSTEM_GENERATED",
            title=title,
            description=description,
            category="ssrf",
            value=target_url,
            source=target_url,
            status="CONFIRMED",
            confidence=confidence,
            severity=severity,
            provenance=ProvenanceData(
                step_id="ssrf_collector",
            ),
            tags=["ssrf", "server_side_request_forgery", technique, template_id],
            metadata={
                "url": target_url,
                "host": base_url,
                "path": url_path,
                "parameter": param,
                "parameter_type": param_type,
                "payload": payload,
                "category": "ssrf",
                "severity": severity,
                "technique": technique,
                "template_id": template_id,
                "cloud_provider": cloud_provider,
                "target_service": target_service,
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
                "name": f"Server-Side Request Forgery ({tech_label})",
                "template_id": template_id,
                "severity": severity,
                "host": base_url,
                "url": target_url,
                "description": description,
                "parameter": param,
                "parameter_type": param_type,
                "payload": payload,
                "technique": technique,
                "cloud_provider": cloud_provider,
                "target_service": target_service,
            })

        # 3. KnowledgeGraph Node & Edge Expansion
        graph = getattr(raw_mission, "attack_surface_graph", None) or getattr(raw_mission, "graph", None)
        if graph is not None and hasattr(graph, "add") and hasattr(graph, "connect"):
            lh_id = f"live_host:{base_url}"
            ep_id = f"endpoint:{target_url}"
            vuln_id = f"vulnerability:{template_id}:{target_url}:{param}"

            graph.add(Node(id=lh_id, type="live_host", value=base_url, metadata={"url": base_url}))
            graph.add(Node(id=ep_id, type="endpoint", value=target_url, metadata={"url": target_url, "status_code": status_code}))
            graph.add(Node(id=vuln_id, type="vulnerability", value=f"Server-Side Request Forgery ({tech_label})", metadata=ev.metadata))

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
