"""Active XSS fuzzing collector (GET/POST/header injection, stored validation)."""
from __future__ import annotations

import logging
import urllib.parse
from typing import Any, Dict, List, Optional, Set

from argus.collectors.base import BaseCollector
from argus.evidence.model import Evidence, ProvenanceData
from argus.graph.node import Node
from argus.http.client import AuthenticatedHttpClient, HttpResponse
from argus.collectors.xss.models import DEFAULT_XSS_PROBE_ROUTES
from argus.collectors.xss.payloads import XSSPayloadGenerator
from argus.collectors.xss.analyzer import XSSAnalyzer

logger = logging.getLogger(__name__)


class XSSCollector(BaseCollector):
    """
    Multi-mode Cross-Site Scripting (XSS) vulnerability detection collector.
    Fuzzes GET query parameters, POST form bodies, POST JSON bodies, and HTTP headers,
    and performs stateful POST-then-GET testing for Stored XSS persistence.
    """

    def __init__(
        self,
        http_client: Optional[Any] = None,
        payload_generator: Optional[XSSPayloadGenerator] = None,
        analyzer: Optional[XSSAnalyzer] = None,
        timeout: float = 10.0,
    ):
        self.http_client = http_client
        self.generator = payload_generator or XSSPayloadGenerator()
        self.analyzer = analyzer or XSSAnalyzer()
        self.timeout = timeout

    def _extract_candidate_endpoints(self, mission: Any) -> List[Dict[str, Any]]:
        """
        Extracts and normalizes target candidate endpoints from mission state.
        """
        candidates: List[Dict[str, Any]] = []
        seen_urls: Set[str] = set()

        raw_target = getattr(mission, "target", "") or ""
        default_base = raw_target if (raw_target.startswith("http://") or raw_target.startswith("https://")) else f"http://{raw_target}" if raw_target else "http://localhost"

        # 1. Base hosts from mission.live_hosts
        base_hosts: List[str] = []
        for host_entry in getattr(mission, "live_hosts", []) or []:
            if isinstance(host_entry, dict):
                h_url = host_entry.get("url") or host_entry.get("host") or ""
            else:
                h_url = str(host_entry) if host_entry else ""
            if h_url:
                if not h_url.startswith("http://") and not h_url.startswith("https://"):
                    h_url = f"http://{h_url}"
                base_hosts.append(h_url.rstrip("/"))

        if not base_hosts and default_base:
            base_hosts.append(default_base.rstrip("/"))

        # 2. Extract from mission.endpoints
        for ep in getattr(mission, "endpoints", []) or []:
            if not ep:
                continue

            method = "GET"
            params_dict: Dict[str, Any] = {}
            body_data: Any = None
            headers_dict: Dict[str, str] = {}

            if isinstance(ep, dict):
                raw_url = ep.get("url") or ep.get("path") or ""
                method = (ep.get("method") or "GET").upper()
                params_dict = dict(ep.get("params") or {})
                body_data = ep.get("body")
                headers_dict = dict(ep.get("headers") or {})
            else:
                raw_url = str(ep)

            if not raw_url:
                continue

            if not raw_url.startswith("http://") and not raw_url.startswith("https://"):
                full_url = urllib.parse.urljoin(default_base.rstrip("/") + "/", raw_url.lstrip("/"))
            else:
                full_url = raw_url

            parsed = urllib.parse.urlparse(full_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            # Extract query parameters from URL if not provided
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

        # 3. Fallback standard probe routes on candidate base hosts
        for base_url in base_hosts:
            for probe_path in DEFAULT_XSS_PROBE_ROUTES:
                for param in ("q", "search", "name", "comment", "msg"):
                    probe_url = f"{base_url.rstrip('/')}{probe_path}?{param}=test"
                    if probe_url not in seen_urls:
                        seen_urls.add(probe_url)
                        parsed = urllib.parse.urlparse(probe_url)
                        candidates.append({
                            "url": probe_url,
                            "base_url": base_url,
                            "path": parsed.path,
                            "method": "GET",
                            "params": {param: "test"},
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
        Dispatches HTTP request using the injected or standard AuthenticatedHttpClient.
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
                            return self.http_client.get(url, params=params, headers=headers, cookies=cookies)
                        except TypeError:
                            return self.http_client.get(url)
                elif method == "POST" and hasattr(self.http_client, "post"):
                    try:
                        return self.http_client.post(
                            mission, url, data=data, json=json_data, headers=headers, cookies=cookies, timeout=self.timeout
                        )
                    except TypeError:
                        try:
                            return self.http_client.post(url, data=data, json=json_data, headers=headers, cookies=cookies)
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
            logger.debug(f"XSSCollector request failed for {url}: {e}")
            return None

    def collect(self, mission: Any) -> List[Evidence]:
        """
        Executes multi-mode Cross-Site Scripting (XSS) detection across candidate endpoints.
        """
        raw_mission = getattr(mission, "_mission", mission)
        candidates = self._extract_candidate_endpoints(raw_mission)
        if not candidates:
            logger.info("XSSCollector: No candidate endpoints or hosts to fuzz.")
            return []

        logger.info(f"XSSCollector: Fuzzing {len(candidates)} candidate endpoint(s)...")

        detected_evidence: List[Evidence] = []
        confirmed_vuln_keys: Set[str] = set()

        for candidate in candidates:
            orig_url = candidate["url"]
            base_url = candidate["base_url"]
            parsed_url = urllib.parse.urlparse(orig_url)
            method = candidate.get("method", "GET")
            raw_params = dict(candidate.get("params") or {})
            body_data = candidate.get("body")
            headers_data = dict(candidate.get("headers") or {})

            # -------------------------------------------------------------
            # Vector 1: GET Query Parameter Fuzzing
            # -------------------------------------------------------------
            if raw_params:
                for param_name in list(raw_params.keys()):
                    canary = self.generator.generate_canary("rxss")
                    probe = self.generator.get_canary_probe(canary)

                    # Step 1: Send canary probe
                    probe_params = dict(raw_params)
                    probe_params[param_name] = probe
                    probe_query = urllib.parse.urlencode(probe_params, doseq=True)
                    probe_target = urllib.parse.urlunparse((
                        parsed_url.scheme,
                        parsed_url.netloc,
                        parsed_url.path,
                        parsed_url.params,
                        probe_query,
                        parsed_url.fragment,
                    ))

                    resp = self._execute_request(raw_mission, "GET", probe_target, params=probe_params, headers=headers_data)
                    raw_body = getattr(resp, "raw_body", None) or getattr(resp, "body", None) or ""

                    if resp and canary in raw_body:
                        # Context discovered
                        context = self.analyzer.detect_context(raw_body, canary)
                        context_payloads = self.generator.get_context_payloads(context, canary)

                        for item in context_payloads:
                            payload = item["payload"]
                            mutated_params = dict(raw_params)
                            mutated_params[param_name] = payload
                            mut_query = urllib.parse.urlencode(mutated_params, doseq=True)
                            target_url = urllib.parse.urlunparse((
                                parsed_url.scheme,
                                parsed_url.netloc,
                                parsed_url.path,
                                parsed_url.params,
                                mut_query,
                                parsed_url.fragment,
                            ))

                            payload_resp = self._execute_request(raw_mission, "GET", target_url, params=mutated_params, headers=headers_data)
                            if not payload_resp:
                                continue

                            analysis = self.analyzer.analyze_reflected(payload_resp, canary, payload, context)
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
                                        status_code=getattr(payload_resp, "status_code", 200) or 200,
                                        analysis=analysis,
                                    )
                                    detected_evidence.append(ev)
                                    break
                    else:
                        # Fallback: test default payload suite
                        suite = self.generator.get_default_payload_suite(canary)
                        for payload, ctx, marker in suite:
                            mutated_params = dict(raw_params)
                            mutated_params[param_name] = payload
                            mut_query = urllib.parse.urlencode(mutated_params, doseq=True)
                            target_url = urllib.parse.urlunparse((
                                parsed_url.scheme,
                                parsed_url.netloc,
                                parsed_url.path,
                                parsed_url.params,
                                mut_query,
                                parsed_url.fragment,
                            ))

                            payload_resp = self._execute_request(raw_mission, "GET", target_url, params=mutated_params, headers=headers_data)
                            if not payload_resp:
                                continue

                            analysis = self.analyzer.analyze_reflected(payload_resp, canary, payload, ctx)
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
                                        status_code=getattr(payload_resp, "status_code", 200) or 200,
                                        analysis=analysis,
                                    )
                                    detected_evidence.append(ev)
                                    break

            # -------------------------------------------------------------
            # Vector 2: POST Form Body Fuzzing
            # -------------------------------------------------------------
            if method == "POST" or isinstance(body_data, dict):
                form_fields = list(body_data.keys()) if isinstance(body_data, dict) and body_data else ["comment", "message", "query", "search", "name", "feedback"]
                for field in form_fields:
                    canary = self.generator.generate_canary("postxss")
                    suite = self.generator.get_default_payload_suite(canary)
                    for payload, ctx, marker in suite:
                        post_body = dict(body_data) if isinstance(body_data, dict) else {}
                        post_body[field] = payload

                        resp = self._execute_request(raw_mission, "POST", orig_url, data=post_body, headers=headers_data)
                        if not resp:
                            continue

                        analysis = self.analyzer.analyze_reflected(resp, canary, payload, ctx)
                        if analysis:
                            vuln_key = f"{parsed_url.path}:{field}:post_form:{analysis['template_id']}"
                            if vuln_key not in confirmed_vuln_keys:
                                confirmed_vuln_keys.add(vuln_key)
                                ev = self._create_evidence_and_update_state(
                                    mission=mission,
                                    target_url=orig_url,
                                    base_url=base_url,
                                    param=field,
                                    param_type="post_form",
                                    payload=payload,
                                    status_code=getattr(resp, "status_code", 200) or 200,
                                    analysis=analysis,
                                )
                                detected_evidence.append(ev)
                                break

            # -------------------------------------------------------------
            # Vector 3: POST JSON Body Fuzzing
            # -------------------------------------------------------------
            json_fields = ["query", "search", "name", "comment", "message", "input", "data"]
            for field in json_fields:
                canary = self.generator.generate_canary("jsonxss")
                suite = self.generator.get_default_payload_suite(canary)
                for payload, ctx, marker in suite:
                    json_body = {field: payload}
                    resp = self._execute_request(raw_mission, "POST", orig_url, json_data=json_body, headers=headers_data)
                    if not resp:
                        continue

                    analysis = self.analyzer.analyze_reflected(resp, canary, payload, ctx)
                    if analysis:
                        vuln_key = f"{parsed_url.path}:{field}:post_json:{analysis['template_id']}"
                        if vuln_key not in confirmed_vuln_keys:
                            confirmed_vuln_keys.add(vuln_key)
                            ev = self._create_evidence_and_update_state(
                                mission=mission,
                                target_url=orig_url,
                                base_url=base_url,
                                param=field,
                                param_type="post_json",
                                payload=payload,
                                status_code=getattr(resp, "status_code", 200) or 200,
                                analysis=analysis,
                            )
                            detected_evidence.append(ev)
                            break

            # -------------------------------------------------------------
            # Vector 4: HTTP Header Fuzzing
            # -------------------------------------------------------------
            header_names = ["User-Agent", "Referer", "X-Forwarded-For"]
            for hname in header_names:
                canary = self.generator.generate_canary("hdrxss")
                suite = self.generator.get_default_payload_suite(canary)
                for payload, ctx, marker in suite:
                    mutated_hdrs = dict(headers_data)
                    mutated_hdrs[hname] = payload

                    resp = self._execute_request(raw_mission, method, orig_url, params=raw_params if method == "GET" else None, headers=mutated_hdrs)
                    if not resp:
                        continue

                    analysis = self.analyzer.analyze_reflected(resp, canary, payload, ctx)
                    if analysis:
                        analysis["severity"] = "medium"
                        vuln_key = f"{parsed_url.path}:{hname}:header:{analysis['template_id']}"
                        if vuln_key not in confirmed_vuln_keys:
                            confirmed_vuln_keys.add(vuln_key)
                            ev = self._create_evidence_and_update_state(
                                mission=mission,
                                target_url=orig_url,
                                base_url=base_url,
                                param=hname,
                                param_type="header",
                                payload=payload,
                                status_code=getattr(resp, "status_code", 200) or 200,
                                analysis=analysis,
                            )
                            detected_evidence.append(ev)
                            break

            # -------------------------------------------------------------
            # Vector 5: Stored XSS Stateful Testing (POST-then-GET)
            # -------------------------------------------------------------
            stored_canary = self.generator.generate_canary("stored")
            stored_payload = self.generator.get_stored_payload(stored_canary)
            stored_post_data = {
                "comment": stored_payload,
                "message": stored_payload,
                "content": stored_payload,
                "text": stored_payload,
                "feedback": stored_payload,
                "name": stored_payload,
            }

            post_resp = self._execute_request(raw_mission, "POST", orig_url, data=stored_post_data, headers=headers_data)
            if post_resp:
                # Re-fetch page via GET to check persistence
                get_resp = self._execute_request(raw_mission, "GET", orig_url, headers=headers_data)
                analysis = self.analyzer.analyze_stored(get_resp, stored_canary, stored_payload)
                if analysis:
                    vuln_key = f"{parsed_url.path}:stored:xss-stored"
                    if vuln_key not in confirmed_vuln_keys:
                        confirmed_vuln_keys.add(vuln_key)
                        ev = self._create_evidence_and_update_state(
                            mission=mission,
                            target_url=orig_url,
                            base_url=base_url,
                            param="comment",
                            param_type="stored_post",
                            payload=stored_payload,
                            status_code=getattr(get_resp, "status_code", 200) or 200,
                            analysis=analysis,
                        )
                        detected_evidence.append(ev)

        logger.info(f"XSSCollector complete: {len(detected_evidence)} XSS vulnerability(ies) identified.")
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
        **kwargs,
    ) -> Evidence:
        """
        Constructs Evidence, appends to mission.evidence & mission.vulnerabilities,
        and expands the KnowledgeGraph attack surface with HAS_ENDPOINT and HAS_VULNERABILITY edges.
        """
        raw_mission = getattr(mission, "_mission", mission)
        template_id = analysis.get("template_id", "xss")
        xss_type = analysis.get("xss_type", "reflected")
        context = analysis.get("context", "html_body")
        severity = analysis.get("severity", "critical" if xss_type == "stored" else "high")
        confidence = analysis.get("confidence", 0.95)
        snippet = analysis.get("snippet", "")

        parsed_url = urllib.parse.urlparse(target_url)
        url_path = parsed_url.path or "/"

        type_label = "Stored XSS" if xss_type == "stored" else f"Reflected XSS ({context})"
        title = f"Cross-Site Scripting ({type_label}): {param} on {target_url}"
        description = (
            f"Cross-Site Scripting ({type_label}) vulnerability confirmed on endpoint {target_url} "
            f"via {param_type} parameter '{param}' using payload '{payload}'. "
            f"Evidence: {snippet[:200]}"
        )

        ev = Evidence(
            mission_id=getattr(raw_mission, "id", ""),
            source_type="LOG",
            created_by="SYSTEM_GENERATED",
            title=title,
            description=description,
            category="xss",
            value=target_url,
            source=target_url,
            status="CONFIRMED",
            confidence=confidence,
            severity=severity,
            provenance=ProvenanceData(
                step_id="xss_collector",
            ),
            tags=["xss", "cross_site_scripting", xss_type, context, template_id],
            metadata={
                "url": target_url,
                "host": base_url,
                "path": url_path,
                "parameter": param,
                "parameter_type": param_type,
                "payload": payload,
                "category": "xss",
                "severity": severity,
                "xss_type": xss_type,
                "context": context,
                "template_id": template_id,
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
                "name": f"Cross-Site Scripting ({type_label})",
                "template_id": template_id,
                "severity": severity,
                "host": base_url,
                "url": target_url,
                "description": description,
                "parameter": param,
                "parameter_type": param_type,
                "payload": payload,
                "xss_type": xss_type,
                "context": context,
            })

        # 3. KnowledgeGraph Node & Edge Expansion
        graph = getattr(raw_mission, "attack_surface_graph", None) or getattr(raw_mission, "graph", None)
        if graph is not None and hasattr(graph, "add") and hasattr(graph, "connect"):
            lh_id = f"live_host:{base_url}"
            ep_id = f"endpoint:{target_url}"
            vuln_id = f"vulnerability:{template_id}:{target_url}:{param}"

            graph.add(Node(id=lh_id, type="live_host", value=base_url, metadata={"url": base_url}))
            graph.add(Node(id=ep_id, type="endpoint", value=target_url, metadata={"url": target_url, "status_code": status_code}))
            graph.add(Node(id=vuln_id, type="vulnerability", value=f"Cross-Site Scripting ({type_label})", metadata=ev.metadata))

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

