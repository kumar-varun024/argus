"""Active SQL injection fuzzing collector."""
from __future__ import annotations

import json
import logging
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Set

from argus.collectors.base import BaseCollector
from argus.evidence.model import Evidence, ProvenanceData
from argus.graph.node import Node
from argus.http.client import AuthenticatedHttpClient, HttpResponse
from argus.collectors.sql_injection.models import DEFAULT_SQLI_PROBE_ROUTES
from argus.collectors.sql_injection.payloads import SQLInjectionPayloadGenerator
from argus.collectors.sql_injection.analyzer import SQLInjectionAnalyzer

logger = logging.getLogger(__name__)


class SQLInjectionCollector(BaseCollector):
    """
    Autonomous SQL Injection Collector for ARGUS.
    Fuzzes endpoint parameters across query strings, POST JSON & form bodies,
    path segments, and HTTP headers using AuthenticatedHttpClient.
    """

    def __init__(
        self,
        http_client: Optional[Any] = None,
        payload_generator: Optional[SQLInjectionPayloadGenerator] = None,
        analyzer: Optional[SQLInjectionAnalyzer] = None,
        timeout: float = 10.0,
    ):
        self.http_client = http_client
        self.generator = payload_generator or SQLInjectionPayloadGenerator()
        self.analyzer = analyzer or SQLInjectionAnalyzer()
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
        seen_urls: Set[str] = set()

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
            method = "GET"
            params_dict: Dict[str, Any] = {}
            body_data: Any = None
            headers_dict: Dict[str, str] = {}

            if isinstance(ep, dict):
                raw_url = ep.get("url") or ep.get("path") or ""
                method = (ep.get("method") or "GET").upper()
                params_dict = ep.get("params") or {}
                body_data = ep.get("body")
                headers_dict = ep.get("headers") or {}
            elif isinstance(ep, str):
                raw_url = ep

            if not raw_url:
                continue

            if not raw_url.startswith("http://") and not raw_url.startswith("https://"):
                full_url = urllib.parse.urljoin(default_base.rstrip("/") + "/", raw_url.lstrip("/"))
            else:
                full_url = raw_url

            parsed = urllib.parse.urlparse(full_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            # Merge query params from URL if not explicitly given
            if not params_dict and parsed.query:
                parsed_qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                params_dict = {k: v[0] if isinstance(v, list) and len(v) == 1 else v for k, v in parsed_qs.items()}

            if full_url not in seen_urls:
                seen_urls.add(full_url)
                candidates.append({
                    "url": full_url,
                    "base_url": base_url,
                    "path": parsed.path or "/",
                    "method": method,
                    "params": params_dict,
                    "body": body_data,
                    "headers": headers_dict,
                    "source": "mission.endpoints",
                })

        # 2. Add fallback standard probe routes on candidate base hosts
        for base_url in (base_hosts or [default_base]):
            for probe_path in DEFAULT_SQLI_PROBE_ROUTES:
                for param in ("id", "user", "q", "query", "category", "search"):
                    probe_url = f"{base_url.rstrip('/')}{probe_path}?{param}=1"
                    if probe_url not in seen_urls:
                        seen_urls.add(probe_url)
                        parsed = urllib.parse.urlparse(probe_url)
                        candidates.append({
                            "url": probe_url,
                            "base_url": base_url,
                            "path": parsed.path,
                            "method": "GET",
                            "params": {param: "1"},
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
        Dispatches HTTP request using injected or standard AuthenticatedHttpClient.
        """
        method = method.upper()
        try:
            if self.http_client is not None:
                # Check for method-specific callables
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
            logger.debug(f"SQLInjectionCollector request failed for {url}: {e}")
            return None

    def collect(self, mission: Any) -> List[Evidence]:
        """
        Executes active SQL injection fuzzing across discovered endpoints and parameters.
        """
        raw_mission = getattr(mission, "_mission", mission)
        candidates = self._extract_candidate_endpoints(raw_mission)
        if not candidates:
            logger.info("SQLInjectionCollector: No candidate endpoints or hosts to fuzz.")
            return []

        logger.info(f"SQLInjectionCollector: Fuzzing {len(candidates)} candidate endpoint(s)...")

        detected_evidence: List[Evidence] = []
        confirmed_vuln_keys: Set[str] = set()

        error_payloads = self.generator.generate_error_payloads()
        boolean_pairs = self.generator.generate_boolean_payload_pairs()
        time_payloads = self.generator.generate_time_payloads(delay=5)

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
            baseline_status = getattr(baseline_resp, "status_code", 200) if baseline_resp else 200

            # -------------------------------------------------------------
            # Vector 1: GET Query Parameters
            # -------------------------------------------------------------
            query_params = urllib.parse.parse_qs(parsed_url.query, keep_blank_values=True) if parsed_url.query else {}
            if not query_params and raw_params and method == "GET":
                query_params = {k: [v] if not isinstance(v, list) else v for k, v in raw_params.items()}

            if query_params:
                for param_name in list(query_params.keys()):
                    param_vuln_found = False

                    # 1.1 Error-Based Fuzzing
                    for payload in error_payloads:
                        mutated_params = dict(query_params)
                        mutated_params[param_name] = [payload]
                        new_query = urllib.parse.urlencode(mutated_params, doseq=True)
                        target_url = urllib.parse.urlunparse((
                            parsed_url.scheme, parsed_url.netloc, parsed_url.path,
                            parsed_url.params, new_query, parsed_url.fragment,
                        ))

                        resp = self._execute_request(mission, "GET", target_url, headers=headers_data)
                        if not resp:
                            continue

                        analysis = self.analyzer.analyze_error_based(resp, baseline=baseline_resp, payload=payload)
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

                    # 1.2 Boolean-Based Blind Differential
                    if not param_vuln_found:
                        for true_payload, false_payload in boolean_pairs:
                            mut_true = dict(query_params)
                            mut_true[param_name] = [true_payload]
                            url_true = urllib.parse.urlunparse((
                                parsed_url.scheme, parsed_url.netloc, parsed_url.path,
                                parsed_url.params, urllib.parse.urlencode(mut_true, doseq=True), parsed_url.fragment,
                            ))

                            mut_false = dict(query_params)
                            mut_false[param_name] = [false_payload]
                            url_false = urllib.parse.urlunparse((
                                parsed_url.scheme, parsed_url.netloc, parsed_url.path,
                                parsed_url.params, urllib.parse.urlencode(mut_false, doseq=True), parsed_url.fragment,
                            ))

                            true_resp = self._execute_request(mission, "GET", url_true, headers=headers_data)
                            false_resp = self._execute_request(mission, "GET", url_false, headers=headers_data)

                            if true_resp and false_resp:
                                analysis = self.analyzer.analyze_boolean_blind(
                                    true_resp=true_resp,
                                    false_resp=false_resp,
                                    baseline=baseline_resp,
                                    true_payload=true_payload,
                                    false_payload=false_payload,
                                )
                                if analysis:
                                    vuln_key = f"{parsed_url.path}:{param_name}:{analysis['template_id']}"
                                    if vuln_key not in confirmed_vuln_keys:
                                        confirmed_vuln_keys.add(vuln_key)
                                        ev = self._create_evidence_and_update_state(
                                            mission=mission,
                                            target_url=url_true,
                                            base_url=base_url,
                                            param=param_name,
                                            param_type="query",
                                            payload=f"TRUE: {true_payload} | FALSE: {false_payload}",
                                            status_code=getattr(true_resp, "status_code", 200) or 200,
                                            analysis=analysis,
                                        )
                                        detected_evidence.append(ev)
                                        param_vuln_found = True
                                        break

                    # 1.3 Time-Based Blind
                    if not param_vuln_found:
                        for payload in time_payloads:
                            mut_time = dict(query_params)
                            mut_time[param_name] = [payload]
                            target_url = urllib.parse.urlunparse((
                                parsed_url.scheme, parsed_url.netloc, parsed_url.path,
                                parsed_url.params, urllib.parse.urlencode(mut_time, doseq=True), parsed_url.fragment,
                            ))

                            resp = self._execute_request(mission, "GET", target_url, headers=headers_data)
                            if not resp:
                                continue

                            analysis = self.analyzer.analyze_time_blind(
                                injected_resp=resp,
                                baseline_elapsed=baseline_elapsed,
                                threshold=4.0,
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
                    field_vuln_found = False

                    # 2.1 Error-Based on POST Body
                    for payload in error_payloads:
                        mutated_body = dict(post_fields)
                        mutated_body[field_name] = payload

                        if is_json_body:
                            resp = self._execute_request(mission, "POST", clean_target_url, json_data=mutated_body, headers=headers_data)
                        else:
                            resp = self._execute_request(mission, "POST", clean_target_url, data=mutated_body, headers=headers_data)

                        if not resp:
                            continue

                        analysis = self.analyzer.analyze_error_based(resp, baseline=baseline_resp, payload=payload)
                        if analysis:
                            vuln_key = f"{parsed_url.path}:{field_name}:post:{analysis['template_id']}"
                            if vuln_key not in confirmed_vuln_keys:
                                confirmed_vuln_keys.add(vuln_key)
                                ev = self._create_evidence_and_update_state(
                                    mission=mission,
                                    target_url=clean_target_url,
                                    base_url=base_url,
                                    param=field_name,
                                    param_type="post_body",
                                    payload=payload,
                                    status_code=getattr(resp, "status_code", 200) or 200,
                                    analysis=analysis,
                                )
                                detected_evidence.append(ev)
                                field_vuln_found = True
                                break

                    # 2.2 Boolean-Based on POST Body
                    if not field_vuln_found:
                        for true_payload, false_payload in boolean_pairs:
                            body_true = dict(post_fields)
                            body_true[field_name] = true_payload
                            body_false = dict(post_fields)
                            body_false[field_name] = false_payload

                            if is_json_body:
                                true_resp = self._execute_request(mission, "POST", clean_target_url, json_data=body_true, headers=headers_data)
                                false_resp = self._execute_request(mission, "POST", clean_target_url, json_data=body_false, headers=headers_data)
                            else:
                                true_resp = self._execute_request(mission, "POST", clean_target_url, data=body_true, headers=headers_data)
                                false_resp = self._execute_request(mission, "POST", clean_target_url, data=body_false, headers=headers_data)

                            if true_resp and false_resp:
                                analysis = self.analyzer.analyze_boolean_blind(
                                    true_resp=true_resp,
                                    false_resp=false_resp,
                                    baseline=baseline_resp,
                                    true_payload=true_payload,
                                    false_payload=false_payload,
                                )
                                if analysis:
                                    vuln_key = f"{parsed_url.path}:{field_name}:post:{analysis['template_id']}"
                                    if vuln_key not in confirmed_vuln_keys:
                                        confirmed_vuln_keys.add(vuln_key)
                                        ev = self._create_evidence_and_update_state(
                                            mission=mission,
                                            target_url=clean_target_url,
                                            base_url=base_url,
                                            param=field_name,
                                            param_type="post_body",
                                            payload=f"TRUE: {true_payload} | FALSE: {false_payload}",
                                            status_code=getattr(true_resp, "status_code", 200) or 200,
                                            analysis=analysis,
                                        )
                                        detected_evidence.append(ev)
                                        field_vuln_found = True
                                        break

            # -------------------------------------------------------------
            # Vector 3: Path Segments
            # -------------------------------------------------------------
            path_segments = [s for s in parsed_url.path.strip("/").split("/") if s]
            if path_segments and any(s.isdigit() or len(s) > 15 for s in path_segments):
                for idx, segment in enumerate(path_segments):
                    if segment.isdigit() or len(segment) > 15:
                        for payload in error_payloads[:5]:
                            mutated_segments = list(path_segments)
                            mutated_segments[idx] = f"{segment}{payload}"
                            new_path = "/" + "/".join(mutated_segments)
                            target_url = urllib.parse.urlunparse((
                                parsed_url.scheme, parsed_url.netloc, new_path,
                                parsed_url.params, parsed_url.query, parsed_url.fragment,
                            ))

                            resp = self._execute_request(mission, "GET", target_url, headers=headers_data)
                            if not resp:
                                continue

                            analysis = self.analyzer.analyze_error_based(resp, baseline=baseline_resp, payload=payload)
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
            # Vector 4: HTTP Headers (Cookie, Referer, X-Forwarded-For)
            # -------------------------------------------------------------
            header_targets = [
                ("Cookie", "session_id={payload}"),
                ("Referer", "{base_url}/{payload}"),
                ("X-Forwarded-For", "127.0.0.1'{payload}"),
                ("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) {payload}"),
            ]
            for header_name, template_fmt in header_targets:
                for payload in error_payloads[:4]:
                    injected_val = template_fmt.format(payload=payload, base_url=base_url)
                    mut_headers = dict(headers_data)
                    mut_headers[header_name] = injected_val

                    clean_url = urllib.parse.urlunparse((
                        parsed_url.scheme, parsed_url.netloc, parsed_url.path, "", "", ""
                    ))
                    resp = self._execute_request(mission, "GET", clean_url, headers=mut_headers)
                    if not resp:
                        continue

                    analysis = self.analyzer.analyze_error_based(resp, baseline=baseline_resp, payload=payload)
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
            f"SQLInjectionCollector complete: {len(detected_evidence)} SQL injection vulnerability(ies) identified."
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
        template_id = analysis.get("template_id", "sqli")
        technique = analysis.get("technique", "error_based")
        severity = analysis.get("severity", "critical")
        confidence = analysis.get("confidence", 0.95)
        snippet = analysis.get("snippet", "")
        dbms = analysis.get("dbms", "database")

        parsed_url = urllib.parse.urlparse(target_url)
        url_path = parsed_url.path or "/"

        technique_labels = {
            "error_based": f"Error-Based ({dbms.upper()})",
            "boolean_blind": "Boolean-Based Blind",
            "time_blind": "Time-Based Blind Delay",
        }
        tech_label = technique_labels.get(technique, technique)

        title = f"SQL Injection: {param} on {target_url}"
        description = (
            f"SQL Injection ({tech_label}) vulnerability confirmed on endpoint {target_url} "
            f"via {param_type} parameter '{param}' using payload '{payload}'. "
            f"Evidence: {snippet[:200]}"
        )

        ev = Evidence(
            mission_id=getattr(raw_mission, "id", ""),
            source_type="LOG",
            created_by="SYSTEM_GENERATED",
            title=title,
            description=description,
            category="sql_injection",
            value=target_url,
            source=target_url,
            status="CONFIRMED",
            confidence=confidence,
            severity=severity,
            provenance=ProvenanceData(
                step_id="sql_injection_collector",
            ),
            tags=["sql_injection", "sqli", technique, template_id],
            metadata={
                "url": target_url,
                "host": base_url,
                "path": url_path,
                "parameter": param,
                "parameter_type": param_type,
                "payload": payload,
                "category": "sql_injection",
                "severity": severity,
                "technique": technique,
                "template_id": template_id,
                "dbms": dbms,
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
                "name": f"SQL Injection ({tech_label})",
                "template_id": template_id,
                "severity": severity,
                "host": base_url,
                "url": target_url,
                "description": description,
                "parameter": param,
                "parameter_type": param_type,
                "payload": payload,
                "technique": technique,
                "dbms": dbms,
            })

        # 3. KnowledgeGraph Node & Edge Expansion
        graph = getattr(raw_mission, "attack_surface_graph", None) or getattr(raw_mission, "graph", None)
        if graph is not None and hasattr(graph, "add") and hasattr(graph, "connect"):
            lh_id = f"live_host:{base_url}"
            ep_id = f"endpoint:{target_url}"
            vuln_id = f"vulnerability:{template_id}:{target_url}:{param}"

            graph.add(Node(id=lh_id, type="live_host", value=base_url, metadata={"url": base_url}))
            graph.add(Node(id=ep_id, type="endpoint", value=target_url, metadata={"url": target_url, "status_code": status_code}))
            graph.add(Node(id=vuln_id, type="vulnerability", value=f"SQL Injection ({tech_label})", metadata=ev.metadata))

            graph.connect(lh_id, ep_id, edge_type="HAS_ENDPOINT")
            graph.connect(lh_id, vuln_id, edge_type="HAS_VULNERABILITY")
            graph.connect(ep_id, vuln_id, edge_type="HAS_VULNERABILITY")

        # 4. Safe publish to ControlledMission wrapper
        if mission is not raw_mission and hasattr(mission, "publish_finding"):
            try:
                mission.publish_finding(ev.id, ev)
            except Exception:
                pass

        return ev

    def execute(self, mission: Any) -> List[Evidence]:
        """Plugin / Specialist adapter interface."""
        return self.collect(mission)

