"""graphql: Collector orchestration."""
from __future__ import annotations

import json
import logging
import urllib.parse
from typing import Any, Dict, List, Optional, Set, Union

from argus.collectors.base import BaseCollector
from argus.evidence.model import Evidence, ProvenanceData
from argus.graph.node import Node
from argus.http.client import AuthenticatedHttpClient, HttpResponse
from argus.collectors.graphql.models import GraphQLMutationStrategy, GraphQLSecurityResult, GraphQLSeverity, GraphQLTechnique
from argus.collectors.graphql.payloads import GraphQLPayloadGenerator
from argus.collectors.graphql.analyzer import GraphQLSecurityAnalyzer

logger = logging.getLogger(__name__)


class GraphQLSecurityCollector(BaseCollector):
    """
    Active GraphQL Security Detection Collector for ARGUS.

    Identifies GraphQL endpoints and actively fuzzes for introspection exposure,
    field suggestion leakage, query complexity DoS, batch multiplexing abuse,
    and field authorization / injection flaws across 6 mutation strategies.
    """

    DEFAULT_GRAPHQL_PATHS: List[str] = [
        "/graphql",
        "/api/graphql",
        "/v1/graphql",
        "/v2/graphql",
        "/query",
        "/api/query",
        "/gql",
        "/graphql/console",
        "/graphiql",
        "/playground",
    ]

    def __init__(
        self,
        http_client: Optional[Any] = None,
        timeout: float = 10.0,
        max_probes_per_endpoint: int = 50,
    ) -> None:
        self.http_client = http_client
        self.timeout = timeout
        self.max_probes_per_endpoint = max_probes_per_endpoint
        self.payload_generator = GraphQLPayloadGenerator()
        self.analyzer = GraphQLSecurityAnalyzer()

    def _execute_request(
        self,
        mission: Any,
        method: str = "POST",
        url: str = "",
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Union[str, bytes, Dict[str, Any]]] = None,
        json_data: Optional[Any] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
    ) -> Optional[HttpResponse]:
        """Polymorphic HTTP request execution supporting mock clients and AuthenticatedHttpClient."""
        method = method.upper()
        req_headers = dict(headers or {})
        req_cookies = dict(cookies or {})

        try:
            if self.http_client is not None:
                client = self.http_client

                # 1. Direct method calls: client.get(...), client.post(...)
                if method == "GET" and hasattr(client, "get"):
                    try:
                        return client.get(
                            mission,
                            url,
                            params=params,
                            headers=req_headers,
                            cookies=req_cookies,
                            timeout=self.timeout,
                        )
                    except TypeError:
                        return client.get(
                            url,
                            params=params,
                            headers=req_headers,
                            cookies=req_cookies,
                        )
                if method == "POST" and hasattr(client, "post"):
                    kwargs: Dict[str, Any] = {
                        "headers": req_headers,
                        "cookies": req_cookies,
                    }
                    if params:
                        kwargs["params"] = params
                    if json_data is not None:
                        kwargs["json"] = json_data
                    if data is not None:
                        kwargs["data"] = data
                    try:
                        return client.post(
                            mission, url, timeout=self.timeout, **kwargs
                        )
                    except TypeError:
                        return client.post(url, **kwargs)

                # 2. Universal client.request(...)
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

                # 3. Callable mock
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

            # Fallback to production AuthenticatedHttpClient
            with AuthenticatedHttpClient(
                timeout=self.timeout, max_retries=1
            ) as client:
                if method == "GET":
                    return client.get(
                        mission,
                        url,
                        params=params,
                        headers=req_headers,
                        cookies=req_cookies,
                        timeout=self.timeout,
                    )
                elif method == "POST":
                    return client.post(
                        mission,
                        url,
                        data=data,
                        json=json_data,
                        headers=req_headers,
                        cookies=req_cookies,
                        timeout=self.timeout,
                    )
                else:
                    return client.request(
                        mission,
                        method,
                        url,
                        params=params,
                        data=data,
                        json=json_data,
                        headers=req_headers,
                        cookies=req_cookies,
                        timeout=self.timeout,
                    )
        except Exception as e:
            logger.debug(f"GraphQLSecurityCollector: Request to {url} failed: {e}")
        return None

    def _discover_candidate_endpoints(self, mission: Any) -> List[Dict[str, Any]]:
        """Extracts candidate GraphQL endpoints from mission assets and default path probes."""
        raw_mission = getattr(mission, "_mission", mission)
        candidates: List[Dict[str, Any]] = []
        seen_urls: Set[str] = set()

        endpoints = list(getattr(raw_mission, "endpoints", []) or [])
        live_hosts = list(getattr(raw_mission, "live_hosts", []) or [])
        target = str(getattr(raw_mission, "target", "") or "")

        # 1. Process explicitly discovered endpoints
        for ep in endpoints:
            if isinstance(ep, dict):
                u = ep.get("url") or ""
                m = ep.get("method") or "POST"
                headers = ep.get("headers") or {}
                cookies = ep.get("cookies") or {}
            else:
                u = str(ep)
                m = "POST"
                headers = {}
                cookies = {}

            if not u or not u.startswith("http"):
                continue

            parsed = urllib.parse.urlparse(u)
            path_lower = parsed.path.lower()
            if any(gp in path_lower for gp in ("/graphql", "/query", "/gql")):
                if u not in seen_urls:
                    seen_urls.add(u)
                    candidates.append({"url": u, "method": m, "headers": headers, "cookies": cookies})

        # 2. Synthesize candidate endpoints from live hosts or target if no explicit GraphQL endpoints
        host_urls: List[str] = []
        for lh in live_hosts:
            u = lh.get("url", lh) if isinstance(lh, dict) else str(lh)
            if u and u.startswith("http"):
                host_urls.append(u.rstrip("/"))
            elif u:
                host_urls.append(f"http://{u}".rstrip("/"))

        if not host_urls and target:
            t_url = target if target.startswith("http") else f"http://{target}"
            host_urls.append(t_url.rstrip("/"))

        for base in host_urls:
            for path in self.DEFAULT_GRAPHQL_PATHS:
                full_url = f"{base}{path}"
                if full_url not in seen_urls:
                    seen_urls.add(full_url)
                    candidates.append({"url": full_url, "method": "POST", "headers": {}, "cookies": {}})

        # If still empty but general endpoints exist, test those endpoints as candidates
        if not candidates and endpoints:
            for ep in endpoints:
                u = ep.get("url") if isinstance(ep, dict) else str(ep)
                if u and u.startswith("http") and u not in seen_urls:
                    seen_urls.add(u)
                    candidates.append({"url": u, "method": "POST", "headers": {}, "cookies": {}})

        return candidates

    def _dispatch_mutation(
        self,
        mission: Any,
        target_url: str,
        query: str,
        strategy: GraphQLMutationStrategy,
        variables: Optional[Dict[str, Any]] = None,
        operation_name: Optional[str] = None,
        base_headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
    ) -> Optional[HttpResponse]:
        """Dispatches an HTTP request with the specified mutation strategy."""
        req_spec = self.payload_generator.mutate_payload(
            query=query,
            strategy=strategy,
            variables=variables,
            operation_name=operation_name,
        )

        headers = dict(base_headers or {})
        headers.update(req_spec.get("headers") or {})

        return self._execute_request(
            mission=mission,
            method=req_spec["method"],
            url=target_url,
            params=req_spec.get("params"),
            data=req_spec.get("data"),
            json_data=req_spec.get("json"),
            headers=headers,
            cookies=cookies,
        )

    def _create_evidence_and_update_state(
        self,
        mission: Any,
        target_url: str,
        base_url: str,
        result: GraphQLSecurityResult,
    ) -> Evidence:
        """Executes quadruple state update across mission evidence, vulnerabilities, graph, and wrapper."""
        raw_mission = getattr(mission, "_mission", mission)
        parsed_url = urllib.parse.urlparse(target_url)
        url_path = parsed_url.path or "/"

        technique_titles = {
            GraphQLTechnique.INTROSPECTION.value: "GraphQL Schema Introspection Enabled",
            GraphQLTechnique.TYPE_INTROSPECTION.value: "GraphQL Type Introspection Exposed",
            GraphQLTechnique.FIELD_SUGGESTIONS.value: "GraphQL Field Suggestion Leakage",
            GraphQLTechnique.QUERY_DEPTH.value: "GraphQL Unbounded Query Depth DoS",
            GraphQLTechnique.FRAGMENT_RECURSION.value: "GraphQL Fragment Recursion DoS",
            GraphQLTechnique.BATCHING_ARRAY.value: "GraphQL HTTP Query Array Batching",
            GraphQLTechnique.BATCHING_ALIAS.value: "GraphQL Alias Multiplexing Abuse",
            GraphQLTechnique.FIELD_ACCESS_CONTROL.value: "GraphQL Broken Field-Level Access Control",
            GraphQLTechnique.INJECTION_SQLI.value: "GraphQL Argument SQL Injection",
            GraphQLTechnique.INJECTION_CMDI.value: "GraphQL Argument Command Injection",
        }
        title_base = technique_titles.get(result.technique, f"GraphQL Vulnerability ({result.technique})")
        title = f"{title_base}: {target_url}"

        description = (
            f"Confirmed {title_base} on {target_url} via {result.mutation_strategy} mutation. "
            f"Signature: {result.matched_signature}. Evidence snippet: {result.evidence_snippet[:150]}"
        )

        cwe_map = {
            GraphQLTechnique.INTROSPECTION.value: "CWE-200",
            GraphQLTechnique.TYPE_INTROSPECTION.value: "CWE-200",
            GraphQLTechnique.FIELD_SUGGESTIONS.value: "CWE-200",
            GraphQLTechnique.QUERY_DEPTH.value: "CWE-400",
            GraphQLTechnique.FRAGMENT_RECURSION.value: "CWE-674",
            GraphQLTechnique.BATCHING_ARRAY.value: "CWE-799",
            GraphQLTechnique.BATCHING_ALIAS.value: "CWE-799",
            GraphQLTechnique.FIELD_ACCESS_CONTROL.value: "CWE-285",
            GraphQLTechnique.INJECTION_SQLI.value: "CWE-89",
            GraphQLTechnique.INJECTION_CMDI.value: "CWE-78",
        }
        cwe_id = cwe_map.get(result.technique, "CWE-200")

        cvss_scores = {
            GraphQLSeverity.CRITICAL.value: 9.8,
            GraphQLSeverity.HIGH.value: 8.6,
            GraphQLSeverity.MEDIUM.value: 5.3,
            GraphQLSeverity.LOW.value: 4.3,
            GraphQLSeverity.INFO.value: 0.0,
        }
        cvss_score = cvss_scores.get(result.severity, 5.3)

        ev = Evidence(
            mission_id=getattr(raw_mission, "id", ""),
            source_type="LOG",
            created_by="SYSTEM_GENERATED",
            title=title,
            description=description,
            category="graphql_security",
            value=target_url,
            source=target_url,
            status="CONFIRMED",
            confidence=result.confidence,
            severity=result.severity,
            provenance=ProvenanceData(
                step_id="graphql_security_collector",
            ),
            tags=[
                "graphql",
                "graphql_security",
                result.technique,
                result.mutation_strategy,
                result.template_id,
                cwe_id.lower(),
            ],
            metadata={
                "url": target_url,
                "host": base_url,
                "path": url_path,
                "category": "graphql_security",
                "severity": result.severity,
                "confidence": result.confidence,
                "vulnerability_type": result.technique,
                "technique": result.technique,
                "mutation_strategy": result.mutation_strategy,
                "matched_signature": result.matched_signature,
                "template_id": result.template_id,
                "status_code": result.status_code,
                "evidence_snippet": result.evidence_snippet[:250],
                "payload": result.payload[:300],
                "cwe_id": cwe_id,
                "cvss_score": cvss_score,
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
                "name": title_base,
                "template_id": result.template_id,
                "severity": result.severity,
                "host": base_url,
                "url": target_url,
                "description": description,
                "technique": result.technique,
                "mutation_strategy": result.mutation_strategy,
                "cwe_id": cwe_id,
            })

        # 3. KnowledgeGraph Node & Edge Expansion
        graph = getattr(raw_mission, "attack_surface_graph", None) or getattr(raw_mission, "graph", None)
        if graph is not None and hasattr(graph, "add") and hasattr(graph, "connect"):
            lh_id = f"live_host:{base_url}"
            ep_id = f"endpoint:{target_url}"
            vuln_id = f"vulnerability:{result.template_id}:{target_url}:{result.technique}"

            graph.add(Node(id=lh_id, type="live_host", value=base_url, metadata={"url": base_url}))
            graph.add(Node(id=ep_id, type="endpoint", value=target_url, metadata={"url": target_url, "status_code": result.status_code}))
            graph.add(Node(id=vuln_id, type="vulnerability", value=title_base, metadata=ev.metadata))

            graph.connect(lh_id, ep_id, edge_type="HAS_ENDPOINT")
            graph.connect(lh_id, vuln_id, edge_type="HAS_VULNERABILITY")
            graph.connect(ep_id, vuln_id, edge_type="HAS_VULNERABILITY")

        # 4. ControlledMission Wrapper publish
        if mission is not raw_mission and hasattr(mission, "publish_finding"):
            try:
                mission.publish_finding(ev.evidence_id, ev)
            except Exception:
                pass

        return ev

    def collect(self, mission: Any) -> List[Evidence]:
        """
        Executes active GraphQL security testing against discovered candidate endpoints.
        """
        candidates = self._discover_candidate_endpoints(mission)
        if not candidates:
            logger.info("GraphQLSecurityCollector: No candidate GraphQL endpoints found.")
            return []

        detected_evidence: List[Evidence] = []
        confirmed_findings: Set[str] = set()

        strategies_to_test = [
            GraphQLMutationStrategy.STANDARD,
            GraphQLMutationStrategy.METHOD_SWAPPING,
            GraphQLMutationStrategy.CONTENT_TYPE_MANIPULATION,
            GraphQLMutationStrategy.QUERY_OBFUSCATION,
            GraphQLMutationStrategy.ALIAS_POLLUTION,
            GraphQLMutationStrategy.VARIABLE_EXTRACTION,
            GraphQLMutationStrategy.DIRECTIVE_BYPASS,
        ]

        for cand in candidates:
            target_url = cand["url"]
            headers = cand.get("headers") or {}
            cookies = cand.get("cookies") or {}
            parsed_url = urllib.parse.urlparse(target_url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"

            # Step 0: Baseline probe
            baseline_query = self.payload_generator.build_baseline_query()
            baseline_resp = self._execute_request(
                mission=mission,
                method="POST",
                url=target_url,
                json_data={"query": baseline_query},
                headers={"Content-Type": "application/json", **headers},
                cookies=cookies,
            )

            # Step 1: Introspection & Type Introspection Probes across mutation strategies
            introspection_query = self.payload_generator.build_introspection_query(full=True)
            for strat in strategies_to_test:
                f_key = f"{target_url}:{GraphQLTechnique.INTROSPECTION.value}:{strat.value}"
                if f_key in confirmed_findings:
                    continue

                resp = self._dispatch_mutation(
                    mission=mission,
                    target_url=target_url,
                    query=introspection_query,
                    strategy=strat,
                    base_headers=headers,
                    cookies=cookies,
                )
                if resp:
                    res = self.analyzer.analyze_introspection(
                        response=resp,
                        baseline_response=baseline_resp,
                        technique=GraphQLTechnique.INTROSPECTION.value,
                        mutation_strategy=strat.value,
                        payload=introspection_query,
                        endpoint_url=target_url,
                    )
                    if res and res.is_valid_finding:
                        ev = self._create_evidence_and_update_state(
                            mission=mission,
                            target_url=target_url,
                            base_url=base_url,
                            result=res,
                        )
                        detected_evidence.append(ev)
                        confirmed_findings.add(f_key)
                        break

            # Targeted Type Introspection Probe
            type_query = self.payload_generator.build_type_introspection_query("Query")
            resp_type = self._dispatch_mutation(
                mission=mission,
                target_url=target_url,
                query=type_query,
                strategy=GraphQLMutationStrategy.STANDARD,
                base_headers=headers,
                cookies=cookies,
            )
            if resp_type:
                res_type = self.analyzer.analyze_introspection(
                    response=resp_type,
                    baseline_response=baseline_resp,
                    technique=GraphQLTechnique.TYPE_INTROSPECTION.value,
                    mutation_strategy=GraphQLMutationStrategy.STANDARD.value,
                    payload=type_query,
                    endpoint_url=target_url,
                )
                if res_type and res_type.is_valid_finding:
                    f_key = f"{target_url}:{GraphQLTechnique.TYPE_INTROSPECTION.value}"
                    if f_key not in confirmed_findings:
                        ev = self._create_evidence_and_update_state(
                            mission=mission,
                            target_url=target_url,
                            base_url=base_url,
                            result=res_type,
                        )
                        detected_evidence.append(ev)
                        confirmed_findings.add(f_key)

            # Step 2: Field Suggestion Leakage Probes
            for probe in self.payload_generator.build_suggestion_probes():
                f_key = f"{target_url}:{GraphQLTechnique.FIELD_SUGGESTIONS.value}:{probe['name']}"
                if f_key in confirmed_findings:
                    continue

                resp = self._dispatch_mutation(
                    mission=mission,
                    target_url=target_url,
                    query=probe["query"],
                    strategy=GraphQLMutationStrategy.STANDARD,
                    base_headers=headers,
                    cookies=cookies,
                )
                if resp:
                    res = self.analyzer.analyze_field_suggestions(
                        response=resp,
                        baseline_response=baseline_resp,
                        mutation_strategy=GraphQLMutationStrategy.STANDARD.value,
                        payload=probe["query"],
                        endpoint_url=target_url,
                    )
                    if res and res.is_valid_finding:
                        ev = self._create_evidence_and_update_state(
                            mission=mission,
                            target_url=target_url,
                            base_url=base_url,
                            result=res,
                        )
                        detected_evidence.append(ev)
                        confirmed_findings.add(f_key)
                        break

            # Step 3: Query Depth Probes (5, 10, 15)
            for depth in (5, 10, 15):
                f_key = f"{target_url}:{GraphQLTechnique.QUERY_DEPTH.value}:{depth}"
                if f_key in confirmed_findings:
                    continue

                depth_query = self.payload_generator.build_depth_query(depth=depth)
                resp = self._dispatch_mutation(
                    mission=mission,
                    target_url=target_url,
                    query=depth_query,
                    strategy=GraphQLMutationStrategy.STANDARD,
                    base_headers=headers,
                    cookies=cookies,
                )
                if resp:
                    res = self.analyzer.analyze_query_depth(
                        response=resp,
                        depth=depth,
                        baseline_response=baseline_resp,
                        mutation_strategy=GraphQLMutationStrategy.STANDARD.value,
                        payload=depth_query,
                        endpoint_url=target_url,
                    )
                    if res and res.is_valid_finding:
                        ev = self._create_evidence_and_update_state(
                            mission=mission,
                            target_url=target_url,
                            base_url=base_url,
                            result=res,
                        )
                        detected_evidence.append(ev)
                        confirmed_findings.add(f_key)

            # Step 4: Fragment Recursion Probes
            frag_query = self.payload_generator.build_fragment_cycle_query()
            f_key = f"{target_url}:{GraphQLTechnique.FRAGMENT_RECURSION.value}"
            if f_key not in confirmed_findings:
                resp = self._dispatch_mutation(
                    mission=mission,
                    target_url=target_url,
                    query=frag_query,
                    strategy=GraphQLMutationStrategy.STANDARD,
                    base_headers=headers,
                    cookies=cookies,
                )
                if resp:
                    elapsed = getattr(resp, "elapsed", 0.0) or 0.0
                    res = self.analyzer.analyze_fragment_recursion(
                        response=resp,
                        baseline_response=baseline_resp,
                        mutation_strategy=GraphQLMutationStrategy.STANDARD.value,
                        payload=frag_query,
                        endpoint_url=target_url,
                        elapsed=elapsed,
                    )
                    if res and res.is_valid_finding:
                        ev = self._create_evidence_and_update_state(
                            mission=mission,
                            target_url=target_url,
                            base_url=base_url,
                            result=res,
                        )
                        detected_evidence.append(ev)
                        confirmed_findings.add(f_key)

            # Step 5: Batching & Multiplexing Probes
            # 5A: HTTP Query Array Batching
            batch_payload = self.payload_generator.build_batch_array_payload(count=3)
            f_key = f"{target_url}:{GraphQLTechnique.BATCHING_ARRAY.value}"
            if f_key not in confirmed_findings:
                resp = self._execute_request(
                    mission=mission,
                    method="POST",
                    url=target_url,
                    json_data=batch_payload,
                    headers={"Content-Type": "application/json", **headers},
                    cookies=cookies,
                )
                if resp:
                    res = self.analyzer.analyze_batching_array(
                        response=resp,
                        batch_size=3,
                        baseline_response=baseline_resp,
                        mutation_strategy=GraphQLMutationStrategy.STANDARD.value,
                        payload=json.dumps(batch_payload),
                        endpoint_url=target_url,
                    )
                    if res and res.is_valid_finding:
                        ev = self._create_evidence_and_update_state(
                            mission=mission,
                            target_url=target_url,
                            base_url=base_url,
                            result=res,
                        )
                        detected_evidence.append(ev)
                        confirmed_findings.add(f_key)

            # 5B: Alias Multiplexing
            alias_query = self.payload_generator.build_alias_multiplexing_query(alias_count=20)
            f_key = f"{target_url}:{GraphQLTechnique.BATCHING_ALIAS.value}"
            if f_key not in confirmed_findings:
                resp = self._dispatch_mutation(
                    mission=mission,
                    target_url=target_url,
                    query=alias_query,
                    strategy=GraphQLMutationStrategy.STANDARD,
                    base_headers=headers,
                    cookies=cookies,
                )
                if resp:
                    res = self.analyzer.analyze_alias_multiplexing(
                        response=resp,
                        alias_count=20,
                        baseline_response=baseline_resp,
                        mutation_strategy=GraphQLMutationStrategy.STANDARD.value,
                        payload=alias_query,
                        endpoint_url=target_url,
                    )
                    if res and res.is_valid_finding:
                        ev = self._create_evidence_and_update_state(
                            mission=mission,
                            target_url=target_url,
                            base_url=base_url,
                            result=res,
                        )
                        detected_evidence.append(ev)
                        confirmed_findings.add(f_key)

            # Step 6: Field-Level Access Control (BOPLA) Probes
            for auth_probe in self.payload_generator.build_field_authorization_probes():
                f_name = auth_probe["field"]
                f_key = f"{target_url}:{GraphQLTechnique.FIELD_ACCESS_CONTROL.value}:{f_name}"
                if f_key in confirmed_findings:
                    continue

                resp = self._dispatch_mutation(
                    mission=mission,
                    target_url=target_url,
                    query=auth_probe["query"],
                    strategy=GraphQLMutationStrategy.STANDARD,
                    base_headers=headers,
                    cookies=cookies,
                )
                if resp:
                    res = self.analyzer.analyze_field_access_control(
                        response=resp,
                        sensitive_field=f_name,
                        baseline_response=baseline_resp,
                        mutation_strategy=GraphQLMutationStrategy.STANDARD.value,
                        payload=auth_probe["query"],
                        endpoint_url=target_url,
                    )
                    if res and res.is_valid_finding:
                        ev = self._create_evidence_and_update_state(
                            mission=mission,
                            target_url=target_url,
                            base_url=base_url,
                            result=res,
                        )
                        detected_evidence.append(ev)
                        confirmed_findings.add(f_key)

            # Step 7: Argument Injection Probes (SQLi & CmdI)
            for sqli_probe in self.payload_generator.build_sqli_probes():
                f_key = f"{target_url}:{GraphQLTechnique.INJECTION_SQLI.value}:{sqli_probe['name']}"
                if f_key in confirmed_findings:
                    continue

                resp = self._dispatch_mutation(
                    mission=mission,
                    target_url=target_url,
                    query=sqli_probe["query"],
                    strategy=GraphQLMutationStrategy.STANDARD,
                    base_headers=headers,
                    cookies=cookies,
                )
                if resp:
                    elapsed = getattr(resp, "elapsed", 0.0) or 0.0
                    res = self.analyzer.analyze_injection(
                        response=resp,
                        injection_type="sqli",
                        baseline_response=baseline_resp,
                        mutation_strategy=GraphQLMutationStrategy.STANDARD.value,
                        payload=sqli_probe["payload"],
                        endpoint_url=target_url,
                        elapsed=elapsed,
                    )
                    if res and res.is_valid_finding:
                        ev = self._create_evidence_and_update_state(
                            mission=mission,
                            target_url=target_url,
                            base_url=base_url,
                            result=res,
                        )
                        detected_evidence.append(ev)
                        confirmed_findings.add(f_key)
                        break

            for cmdi_probe in self.payload_generator.build_cmdi_probes():
                f_key = f"{target_url}:{GraphQLTechnique.INJECTION_CMDI.value}:{cmdi_probe['name']}"
                if f_key in confirmed_findings:
                    continue

                resp = self._dispatch_mutation(
                    mission=mission,
                    target_url=target_url,
                    query=cmdi_probe["query"],
                    strategy=GraphQLMutationStrategy.STANDARD,
                    base_headers=headers,
                    cookies=cookies,
                )
                if resp:
                    elapsed = getattr(resp, "elapsed", 0.0) or 0.0
                    res = self.analyzer.analyze_injection(
                        response=resp,
                        injection_type="cmdi",
                        baseline_response=baseline_resp,
                        mutation_strategy=GraphQLMutationStrategy.STANDARD.value,
                        payload=cmdi_probe["payload"],
                        endpoint_url=target_url,
                        elapsed=elapsed,
                    )
                    if res and res.is_valid_finding:
                        ev = self._create_evidence_and_update_state(
                            mission=mission,
                            target_url=target_url,
                            base_url=base_url,
                            result=res,
                        )
                        detected_evidence.append(ev)
                        confirmed_findings.add(f_key)
                        break

        return detected_evidence

    def execute(self, mission: Any) -> List[Evidence]:
        """Plugin / Specialist adapter execution entry point."""
        return self.collect(mission)

GraphQLCollector = GraphQLSecurityCollector
