"""request_smuggling: Collector orchestration."""
from __future__ import annotations

import logging
import urllib.parse
from typing import Any, List, Optional, Set

from argus.collectors.base import BaseCollector
from argus.evidence.model import Evidence, ProvenanceData
from argus.graph.node import Node
from argus.http.client import AuthenticatedHttpClient
from argus.collectors.request_smuggling.models import RequestSmugglingMutationStrategy, RequestSmugglingResult, RequestSmugglingTechnique
from argus.collectors.request_smuggling.payloads import RequestSmugglingPayloadGenerator
from argus.collectors.request_smuggling.probes import RawHttpStreamProber
from argus.collectors.request_smuggling.analyzer import RequestSmugglingSecurityAnalyzer

logger = logging.getLogger(__name__)


class HTTPRequestSmugglingCollector(BaseCollector):
    """
    Collector for actively testing discovered endpoints and reverse proxies for
    HTTP Request Smuggling (CL.TE, TE.CL, TE.TE, HTTP/2 downgrading).
    """

    DEFAULT_SMUGGLING_PATHS: List[str] = [
        "/",
        "/api",
        "/api/v1",
        "/login",
        "/auth",
        "/search",
        "/submit",
        "/graphql",
        "/rest",
    ]

    def __init__(
        self,
        http_client: Optional[AuthenticatedHttpClient] = None,
        prober: Optional[RawHttpStreamProber] = None,
        timeout: float = 10.0,
        timing_threshold: float = 3.0,
    ):
        super().__init__()
        self.http_client = http_client
        self.prober = prober or RawHttpStreamProber(timeout=timeout)
        self.timeout = timeout
        self.timing_threshold = timing_threshold
        self.results: List[RequestSmugglingResult] = []

    def _discover_candidate_endpoints(self, mission: Any) -> List[str]:
        """
        Identifies candidate HTTP endpoints from mission assets (endpoints, live hosts, target).
        """
        raw_mission = getattr(mission, "_raw_mission", getattr(mission, "_mission", mission))
        candidates: Set[str] = set()

        # 1. Existing endpoints
        endpoints = list(getattr(raw_mission, "endpoints", []) or [])
        for ep in endpoints:
            ep_url = str(ep.get("url", ep) if isinstance(ep, dict) else ep).strip()
            if not ep_url:
                continue
            candidates.add(ep_url)

        # 2. Derive base paths from live hosts and target
        base_urls: Set[str] = set()
        live_hosts = list(getattr(raw_mission, "live_hosts", []) or [])
        for lh in live_hosts:
            lh_url = str(lh.get("url", lh) if isinstance(lh, dict) else lh).strip()
            if lh_url:
                base_urls.add(lh_url)

        target = str(getattr(raw_mission, "target", "") or "").strip()
        if target:
            if not target.startswith("http://") and not target.startswith("https://"):
                base_urls.add(f"https://{target}")
                base_urls.add(f"http://{target}")
            else:
                base_urls.add(target)

        for base in base_urls:
            parsed_b = urllib.parse.urlparse(base)
            root_url = f"{parsed_b.scheme}://{parsed_b.netloc}"
            for candidate_path in self.DEFAULT_SMUGGLING_PATHS:
                candidates.add(urllib.parse.urljoin(root_url, candidate_path))

        return sorted(list(candidates))

    def _publish_finding(
        self,
        mission: Any,
        result: RequestSmugglingResult,
        base_url: str,
        target_url: str,
    ) -> Evidence:
        """
        Executes quadruple state updates:
        1. mission.evidence.add(ev)
        2. mission.vulnerabilities.append({...})
        3. mission.attack_surface_graph node & edge creation (HAS_ENDPOINT, HAS_VULNERABILITY)
        4. ControlledMission finding publishing
        """
        raw_mission = getattr(mission, "_raw_mission", getattr(mission, "_mission", mission))
        parsed = urllib.parse.urlparse(target_url)
        url_path = parsed.path or "/"

        cwe_id = result.cwe_id
        cvss_score = result.cvss_score
        tech_upper = result.technique.upper().replace("_", ".")

        title_map = {
            RequestSmugglingTechnique.CL_TE.value: f"HTTP Request Smuggling (CL.TE) Desynchronization: {target_url}",
            RequestSmugglingTechnique.TE_CL.value: f"HTTP Request Smuggling (TE.CL) Desynchronization: {target_url}",
            RequestSmugglingTechnique.TE_TE.value: f"HTTP Request Smuggling (TE.TE) Obfuscation: {target_url}",
            RequestSmugglingTechnique.H2_CL.value: f"HTTP/2 to HTTP/1.1 Request Smuggling (H2.CL): {target_url}",
            RequestSmugglingTechnique.H2_TE.value: f"HTTP/2 to HTTP/1.1 Request Smuggling (H2.TE): {target_url}",
            RequestSmugglingTechnique.H2_CRLF.value: f"HTTP/2 Pseudo-Header CRLF Request Smuggling: {target_url}",
            RequestSmugglingTechnique.DIFFERENTIAL_TIMING.value: f"HTTP Request Boundary Timing Desynchronization: {target_url}",
            RequestSmugglingTechnique.PIPELINE_POISONING.value: f"HTTP Request Smuggling Pipeline Poisoning: {target_url}",
        }
        title_base = title_map.get(result.technique, f"HTTP Request Smuggling Vulnerability ({tech_upper}): {target_url}")

        description = (
            f"HTTP Request Smuggling validation on '{target_url}' identified a desynchronization flaw using technique '{tech_upper}' "
            f"under mutation strategy '{result.mutation_strategy}'.\n"
            f"Evidence: {result.evidence_snippet}\n"
            f"CWE: {cwe_id} (CVSS: {cvss_score})"
        )

        ev = Evidence(
            category="request_smuggling",
            value=f"{result.technique}:{target_url}",
            source="request_smuggling",
            status="CONFIRMED",
            severity=result.severity,
            confidence=result.confidence,
            title=title_base,
            description=description,
            provenance=ProvenanceData(
                step_id="request_smuggling_collector",
            ),
            tags=[
                "http",
                "request_smuggling",
                "http_desync",
                result.technique,
                result.mutation_strategy,
                result.template_id,
                cwe_id.lower(),
            ],
            metadata={
                "url": target_url,
                "host": base_url,
                "path": url_path,
                "category": "request_smuggling",
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
                "delay_delta": result.delay_delta,
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
                "cvss_score": cvss_score,
            })

        # 3. AttackSurfaceGraph Node & Edge Expansion
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

    def _execute_probes(
        self,
        target_url: str,
        base_url: str,
        prober: RawHttpStreamProber,
    ) -> List[RequestSmugglingResult]:
        """
        Executes raw stream probes against a single candidate endpoint.
        """
        findings: List[RequestSmugglingResult] = []
        parsed = urllib.parse.urlparse(target_url)
        host = parsed.netloc or parsed.hostname or "target.example.com"
        path = parsed.path or "/"

        # 1. Baseline Latency Probe
        base_probe = RequestSmugglingPayloadGenerator.build_baseline_probe(host, path)
        base_resp = prober.send_raw_probe(target_url, base_probe)
        baseline_elapsed = base_resp.elapsed
        baseline_status = base_resp.status_code or 200

        # If baseline completely failed with connection error, abort
        if base_resp.error and base_resp.status_code == 0 and not base_resp.timed_out:
            logger.debug(f"Baseline probe failed for {target_url}: {base_resp.error}")
            return findings

        # 2. CL.TE Timing Probe
        cl_te_timing = RequestSmugglingPayloadGenerator.build_cl_te_timing_probe(host, path)
        resp_cl_te = prober.send_raw_probe(target_url, cl_te_timing)
        res_cl_te_t = RequestSmugglingSecurityAnalyzer.analyze_timing_response(
            endpoint_url=target_url,
            technique=RequestSmugglingTechnique.CL_TE.value,
            strategy=RequestSmugglingMutationStrategy.STANDARD.value,
            baseline_elapsed=baseline_elapsed,
            injected_elapsed=resp_cl_te.elapsed,
            threshold=self.timing_threshold,
            status_code=resp_cl_te.status_code,
            payload=cl_te_timing,
            error_message=resp_cl_te.error,
        )
        if res_cl_te_t:
            findings.append(res_cl_te_t)

        # 3. TE.CL Timing Probe
        te_cl_timing = RequestSmugglingPayloadGenerator.build_te_cl_timing_probe(host, path)
        resp_te_cl = prober.send_raw_probe(target_url, te_cl_timing)
        res_te_cl_t = RequestSmugglingSecurityAnalyzer.analyze_timing_response(
            endpoint_url=target_url,
            technique=RequestSmugglingTechnique.TE_CL.value,
            strategy=RequestSmugglingMutationStrategy.STANDARD.value,
            baseline_elapsed=baseline_elapsed,
            injected_elapsed=resp_te_cl.elapsed,
            threshold=self.timing_threshold,
            status_code=resp_te_cl.status_code,
            payload=te_cl_timing,
            error_message=resp_te_cl.error,
        )
        if res_te_cl_t:
            findings.append(res_te_cl_t)

        # 4. CL.TE 2-Request Pipeline Confirmation Probe
        atk_cl_te, fol_cl_te = RequestSmugglingPayloadGenerator.build_cl_te_pipeline_probe(host, path)
        atk_r1, fol_r1 = prober.send_pipeline_sequence(target_url, atk_cl_te, fol_cl_te)
        res_cl_te_pipe = RequestSmugglingSecurityAnalyzer.analyze_pipeline_response(
            endpoint_url=target_url,
            technique=RequestSmugglingTechnique.CL_TE.value,
            strategy=RequestSmugglingMutationStrategy.STANDARD.value,
            attack_resp=atk_r1,
            follow_up_resp=fol_r1,
            baseline_status=baseline_status,
            payload=atk_cl_te,
        )
        if res_cl_te_pipe:
            findings.append(res_cl_te_pipe)

        # 5. TE.CL 2-Request Pipeline Confirmation Probe
        atk_te_cl, fol_te_cl = RequestSmugglingPayloadGenerator.build_te_cl_pipeline_probe(host, path)
        atk_r2, fol_r2 = prober.send_pipeline_sequence(target_url, atk_te_cl, fol_te_cl)
        res_te_cl_pipe = RequestSmugglingSecurityAnalyzer.analyze_pipeline_response(
            endpoint_url=target_url,
            technique=RequestSmugglingTechnique.TE_CL.value,
            strategy=RequestSmugglingMutationStrategy.STANDARD.value,
            attack_resp=atk_r2,
            follow_up_resp=fol_r2,
            baseline_status=baseline_status,
            payload=atk_te_cl,
        )
        if res_te_cl_pipe:
            findings.append(res_te_cl_pipe)

        # 6. TE.TE Obfuscation Mutations
        te_te_mutations = RequestSmugglingPayloadGenerator.generate_te_te_mutations(host, path)
        for strategy, atk_probe, fol_probe, desc in te_te_mutations:
            atk_r, fol_r = prober.send_pipeline_sequence(target_url, atk_probe, fol_probe)
            res_te_te = RequestSmugglingSecurityAnalyzer.analyze_pipeline_response(
                endpoint_url=target_url,
                technique=RequestSmugglingTechnique.TE_TE.value,
                strategy=strategy.value,
                attack_resp=atk_r,
                follow_up_resp=fol_r,
                baseline_status=baseline_status,
                payload=atk_probe,
            )
            if res_te_te:
                findings.append(res_te_te)
                break  # Confirmed on this mutation strategy

        return findings

    def collect(self, mission: Any) -> List[Evidence]:
        """
        Executes HTTP request smuggling detection against discovered mission endpoints.
        """
        candidate_endpoints = self._discover_candidate_endpoints(mission)
        if not candidate_endpoints:
            logger.info("No candidate endpoints discovered for HTTP request smuggling analysis.")
            return []

        evidences: List[Evidence] = []
        prober = self.prober

        for target_url in candidate_endpoints:
            parsed = urllib.parse.urlparse(target_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else target_url

            results = self._execute_probes(target_url, base_url, prober)
            for res in results:
                ev = self._publish_finding(mission, res, base_url, target_url)
                evidences.append(ev)
                self.results.append(res)

        return evidences

    def execute(self, mission: Any) -> List[Evidence]:
        """Alias for collect(mission) conforming to standard collector execution interface."""
        return self.collect(mission)

RequestSmugglingCollector = HTTPRequestSmugglingCollector
