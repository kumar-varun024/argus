"""Active SSTI fuzzing collector."""
from __future__ import annotations

import logging
import urllib.parse
from typing import Any, List, Optional, Set, Tuple

from argus.collectors.base import BaseCollector
from argus.evidence.model import Evidence, ProvenanceData
from argus.graph.node import Node
from argus.collectors.ssti.models import SSTIResult
from argus.collectors.ssti.payloads import SSTIPayloadGenerator
from argus.collectors.ssti.analyzer import SSTISecurityAnalyzer
from argus.collectors.ssti.probes import SSTIProber

logger = logging.getLogger(__name__)


class SSTICollector(BaseCollector):
    """
    Active Collector for discovering and verifying Server-Side Template Injection (SSTI)
    across web endpoints using AuthenticatedHttpClient.
    """

    def __init__(
        self,
        http_client: Optional[Any] = None,
        generator: Optional[SSTIPayloadGenerator] = None,
        analyzer: Optional[SSTISecurityAnalyzer] = None,
        prober: Optional[SSTIProber] = None,
        max_candidates: int = 25,
    ) -> None:
        self.http_client = http_client
        self.generator = generator or SSTIPayloadGenerator()
        self.analyzer = analyzer or SSTISecurityAnalyzer()
        self.prober = prober or SSTIProber(http_client=self.http_client)
        self.max_candidates = max_candidates
        self.results: List[SSTIResult] = []

    def _discover_candidate_endpoints(self, mission: Any) -> List[str]:
        """
        Discovers candidate endpoints from mission endpoints, live hosts, target,
        and common template rendering paths.
        """
        candidates: Set[str] = set()
        raw_mission = getattr(mission, "_raw_mission", getattr(mission, "_mission", mission))

        # 1. Mission endpoints
        endpoints = getattr(raw_mission, "endpoints", []) or []
        for ep in endpoints:
            if isinstance(ep, str):
                candidates.add(ep)
            elif hasattr(ep, "url"):
                candidates.add(ep.url)
            elif isinstance(ep, dict) and "url" in ep:
                candidates.add(ep["url"])

        # 2. Live hosts & target fallback paths
        live_hosts = getattr(raw_mission, "live_hosts", []) or []
        target = getattr(raw_mission, "target", None)
        base_urls: Set[str] = set()

        for lh in live_hosts:
            if isinstance(lh, str):
                base_urls.add(lh)
            elif hasattr(lh, "url"):
                base_urls.add(lh.url)
            elif isinstance(lh, dict) and "url" in lh:
                base_urls.add(lh["url"])

        if target and isinstance(target, str):
            base_urls.add(target)

        template_probe_paths = [
            "/template",
            "/render",
            "/preview",
            "/email/preview",
            "/pdf/generate",
            "/profile/card",
            "/view",
            "/greeting",
            "/hello",
        ]

        for base in base_urls:
            parsed = urllib.parse.urlparse(base)
            root = f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else base
            for path in template_probe_paths:
                candidates.add(urllib.parse.urljoin(root, path))

        return list(candidates)[: self.max_candidates]

    def _extract_injection_points(self, url: str) -> List[Tuple[str, str]]:
        """
        Extracts candidate injection parameters: (parameter_name, parameter_type).
        """
        points: List[Tuple[str, str]] = []
        parsed = urllib.parse.urlparse(url)

        # GET query parameters
        if parsed.query:
            qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            for param in qs.keys():
                points.append((param, "query"))

        # Common template parameter defaults if no query params
        if not points:
            for p in ("template", "name", "q", "content", "msg", "view", "page", "preview"):
                points.append((p, "query"))

        # Always add body / json candidate
        points.append(("template", "body"))
        points.append(("content", "json"))

        return points

    def _publish_finding(
        self,
        mission: Any,
        result: SSTIResult,
        base_url: str,
        target_url: str,
    ) -> Evidence:
        """
        Executes Quadruple State Publishing:
        1. raw_mission.evidence.add(ev)
        2. raw_mission.vulnerabilities.append({...})
        3. raw_mission.attack_surface_graph (Nodes & Edges)
        4. ControlledMission.publish_finding(ev_id, ev)
        """
        raw_mission = getattr(mission, "_raw_mission", getattr(mission, "_mission", mission))
        parsed = urllib.parse.urlparse(target_url)
        url_path = parsed.path or "/"

        title = f"Server-Side Template Injection ({result.engine.title()}) in {result.parameter or 'endpoint'}"
        description = (
            f"Server-Side Template Injection ({result.engine}) verified at {target_url} via {result.technique}. "
            f"Payload '{result.payload}' evaluated successfully. "
            f"Evidence: {result.evidence_snippet}"
        )

        ev = Evidence(
            category="ssti",
            value=f"ssti:{target_url}:{result.parameter}:{result.technique}",
            source="ssti",
            status="CONFIRMED",
            confidence=result.confidence,
            title=title,
            description=description,
            severity=result.severity,
            provenance=ProvenanceData(
                observation_id="SSTICollector",
                step_id="ssti_collector",
            ),
            tags=["ssti", "template_injection", result.engine, result.technique],
            metadata={
                "url": target_url,
                "host": base_url,
                "path": url_path,
                "category": "ssti",
                "severity": result.severity,
                "confidence": result.confidence,
                "vulnerability_type": "ssti",
                "technique": result.technique,
                "engine": result.engine,
                "strategy": result.mutation_strategy,
                "mutation_strategy": result.mutation_strategy,
                "matched_signature": result.matched_signature,
                "template_id": result.template_id,
                "status_code": result.status_code,
                "evidence_snippet": result.evidence_snippet[:250],
                "payload": str(result.payload)[:300],
                "parameter": result.parameter or "template",
                "parameter_type": result.parameter_type,
                "cwe_id": result.cwe_id,
                "cvss_score": result.cvss_score,
                "delay_delta": result.delay_delta,
                "expected_canary": result.expected_canary,
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
                "name": title,
                "template_id": result.template_id,
                "severity": result.severity,
                "host": base_url,
                "url": target_url,
                "description": description,
                "technique": result.technique,
                "engine": result.engine,
                "parameter": result.parameter,
                "strategy": result.mutation_strategy,
                "cwe_id": result.cwe_id,
                "cvss_score": result.cvss_score,
            })

        # 3. AttackSurfaceGraph Node & Edge Expansion
        graph = getattr(raw_mission, "attack_surface_graph", None) or getattr(raw_mission, "graph", None)
        if graph is not None and hasattr(graph, "add") and hasattr(graph, "connect"):
            lh_id = f"live_host:{base_url}"
            ep_id = f"endpoint:{target_url}"
            vuln_id = f"vulnerability:{result.template_id}:{target_url}:{result.parameter or result.technique}"

            graph.add(Node(id=lh_id, type="live_host", value=base_url, metadata={"url": base_url}))
            graph.add(Node(id=ep_id, type="endpoint", value=target_url, metadata={"url": target_url, "status_code": result.status_code}))
            graph.add(Node(id=vuln_id, type="vulnerability", value=title, metadata=ev.metadata))

            graph.connect(lh_id, ep_id, edge_type="HAS_ENDPOINT")
            graph.connect(lh_id, vuln_id, edge_type="HAS_VULNERABILITY")
            graph.connect(ep_id, vuln_id, edge_type="HAS_VULNERABILITY")

        # 4. ControlledMission wrapper publish
        if mission is not raw_mission and hasattr(mission, "publish_finding"):
            try:
                mission.publish_finding(ev.evidence_id, ev)
            except Exception:
                pass

        return ev

    def collect(self, mission: Any) -> List[Evidence]:
        """
        Executes active SSTI probes across candidate endpoints and injection points.
        """
        discovered_candidates = self._discover_candidate_endpoints(mission)
        evidence_list: List[Evidence] = []
        raw_mission = getattr(mission, "_raw_mission", getattr(mission, "_mission", mission))

        # Ensure prober has http_client
        if self.prober.http_client is None and self.http_client is not None:
            self.prober.http_client = self.http_client

        for target_url in discovered_candidates:
            parsed = urllib.parse.urlparse(target_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else target_url

            # Measure baseline response
            baseline_resp = self.prober.measure_baseline(target_url)
            baseline_body = baseline_resp.body
            baseline_elapsed = baseline_resp.elapsed

            injection_points = self._extract_injection_points(target_url)

            endpoint_vulnerable = False
            for param, ptype in injection_points:
                if endpoint_vulnerable:
                    break

                probes = self.generator.build_all_probes(
                    target_url=target_url,
                    parameter=param,
                    parameter_type=ptype,
                )

                for probe in probes:
                    resp = self.prober.execute_probe(probe)
                    res = self.analyzer.analyze_probe_response(
                        probe=probe,
                        response=resp,
                        baseline_body=baseline_body,
                        baseline_elapsed=baseline_elapsed,
                    )

                    if res is not None:
                        self.results.append(res)
                        ev = self._publish_finding(mission, res, base_url, target_url)
                        evidence_list.append(ev)
                        endpoint_vulnerable = True
                        break

        return evidence_list

    # Pipeline runner compatibility alias
    execute = collect


# Backwards compatibility alias
ServerSideTemplateInjectionCollector = SSTICollector

