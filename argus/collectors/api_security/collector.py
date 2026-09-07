"""api_security: Collector orchestration."""
from __future__ import annotations

import urllib.parse
import uuid
from typing import Any, List, Optional, Set

from argus.collectors.base import BaseCollector
from argus.evidence.model import Evidence, ProvenanceData
from argus.graph.node import Node
from argus.collectors.api_security.models import APISecurityResult
from argus.collectors.api_security.payloads import APISecurityPayloadGenerator
from argus.collectors.api_security.probes import APISecurityProber
from argus.collectors.api_security.analyzer import APISecurityAnalyzer


class APISecurityCollector(BaseCollector):
    """
    Active security collector for API (REST/gRPC) vulnerabilities in ARGUS.
    Orchestrates probe generation, request dispatch via AuthenticatedHttpClient,
    response analysis, and Quadruple State Publishing.
    """

    def __init__(
        self,
        http_client: Optional[Any] = None,
        prober: Optional[APISecurityProber] = None,
        generator: Optional[APISecurityPayloadGenerator] = None,
        analyzer: Optional[APISecurityAnalyzer] = None,
        timeout: float = 10.0,
        max_probes_per_endpoint: int = 50,
        client: Optional[Any] = None,
    ) -> None:
        active_client = http_client or client
        self.prober = prober or APISecurityProber(client=active_client, timeout=timeout)
        self.generator = generator or APISecurityPayloadGenerator()
        self.analyzer = analyzer or APISecurityAnalyzer()
        self.timeout = timeout
        self.max_probes_per_endpoint = max_probes_per_endpoint

    def _discover_candidate_endpoints(self, mission: Any) -> List[str]:
        """Discovers candidate API endpoints from mission state."""
        raw_mission = getattr(mission, "_raw_mission", getattr(mission, "_mission", mission))
        candidates: Set[str] = set()

        # 0. From mission.inputs
        inputs = getattr(mission, "inputs", None) or getattr(raw_mission, "inputs", None) or {}
        if isinstance(inputs, dict):
            for ep in inputs.get("endpoints", []) or []:
                if isinstance(ep, dict):
                    url = ep.get("url") or ep.get("path")
                    if url:
                        candidates.add(str(url))
                elif isinstance(ep, str):
                    candidates.add(ep)

        # 1. From mission.endpoints
        for ep in getattr(raw_mission, "endpoints", []) or []:
            if isinstance(ep, dict):
                url = ep.get("url") or ep.get("path")
                if url:
                    candidates.add(str(url))
            elif isinstance(ep, str):
                candidates.add(ep)

        # 2. From mission.live_hosts (fallback)
        if not candidates:
            for lh in getattr(raw_mission, "live_hosts", []) or []:
                if isinstance(lh, dict):
                    url = lh.get("url")
                    if url:
                        candidates.add(str(url))
                elif isinstance(lh, str):
                    candidates.add(lh)

        # 3. From mission.target (fallback)
        if not candidates:
            target = getattr(raw_mission, "target", "")
            if target:
                if not str(target).startswith("http://") and not str(target).startswith("https://"):
                    candidates.add(f"https://{target}")
                else:
                    candidates.add(str(target))

        # 4. From mission.evidence (fallback)
        if not candidates:
            evidence_list = getattr(raw_mission, "evidence", [])
            if hasattr(evidence_list, "all"):
                evidence_items = evidence_list.all()
            elif isinstance(evidence_list, (list, tuple, set)):
                evidence_items = list(evidence_list)
            else:
                evidence_items = []

            for ev in evidence_items:
                meta = getattr(ev, "metadata", {}) or {}
                if isinstance(meta, dict):
                    url = meta.get("url") or meta.get("endpoint")
                    if url and ("http://" in str(url) or "https://" in str(url)):
                        candidates.add(str(url))

        # Normalize valid candidate URLs
        valid_urls = []
        for url in candidates:
            if url and (url.startswith("http://") or url.startswith("https://")):
                valid_urls.append(url)
            elif url and not url.startswith("http://") and not url.startswith("https://") and "." in url:
                valid_urls.append(f"https://{url}")

        return valid_urls

    def _emit_evidence(
        self,
        mission: Any,
        result: APISecurityResult,
        target_url: str,
        base_url: str,
    ) -> Evidence:
        """Publishes validated API Security finding with Quadruple State Mutation."""
        title = f"API Security Vulnerability: {result.technique} on {target_url}"
        description = (
            f"{result.description} Parameter: {result.parameter}, "
            f"Strategy: {result.mutation_strategy}, CWE: {result.cwe_id}"
        )
        raw_mission = getattr(mission, "_raw_mission", getattr(mission, "_mission", mission))

        ev = Evidence(
            category="api_security",
            value=f"api_security:{result.template_id}:{target_url}:{result.parameter or 'endpoint'}",
            source="api_security",
            status="CONFIRMED",
            confidence=result.confidence,
            severity=result.severity,
            title=title,
            description=description,
            provenance=ProvenanceData(
                observation_id=str(uuid.uuid4()),
                step_id=f"step_{result.technique}",
            ),
            tags=["api_security", "rest_security", str(result.vulnerability_type), result.mutation_strategy],
            metadata={
                "url": target_url,
                "host": base_url,
                "template_id": result.template_id,
                "technique": result.technique,
                "vulnerability_type": str(result.vulnerability_type),
                "parameter": result.parameter,
                "tested_parameter": result.parameter,
                "mutation_strategy": result.mutation_strategy,
                "strategy": result.mutation_strategy,
                "status_code": result.status_code,
                "evidence_snippet": result.evidence_snippet[:250],
                "cwe_id": result.cwe_id,
                "cvss_score": result.cvss_score,
                "is_valid_finding": result.is_valid_finding,
                **result.metadata,
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
                "parameter": result.parameter,
                "strategy": result.mutation_strategy,
                "cwe_id": result.cwe_id,
                "cvss_score": result.cvss_score,
            })

        # 3. Attack Surface Knowledge Graph Expansion
        graph = getattr(raw_mission, "attack_surface_graph", None) or getattr(raw_mission, "graph", None)
        if graph is not None and hasattr(graph, "add") and hasattr(graph, "connect"):
            lh_id = f"live_host:{base_url}"
            ep_id = f"endpoint:{target_url}"
            vuln_id = f"vulnerability:{result.template_id}:{target_url}:{result.parameter or 'endpoint'}"

            parsed_b = urllib.parse.urlparse(base_url)
            graph.add(Node(id=lh_id, type="live_host", value=base_url, metadata={"url": base_url, "host": parsed_b.hostname or base_url}))
            graph.add(Node(id=ep_id, type="endpoint", value=target_url, metadata={"url": target_url, "status_code": result.status_code}))
            graph.add(Node(id=vuln_id, type="vulnerability", value=title, metadata=ev.metadata))

            graph.connect(lh_id, ep_id, edge_type="HAS_ENDPOINT")
            graph.connect(lh_id, vuln_id, edge_type="HAS_VULNERABILITY")
            graph.connect(ep_id, vuln_id, edge_type="HAS_VULNERABILITY")

        # 4. ControlledMission wrapper notification
        if hasattr(mission, "publish_finding"):
            try:
                mission.publish_finding(ev.evidence_id, ev)
            except Exception:
                pass

        return ev

    def collect(self, mission: Any) -> List[Evidence]:
        """Collects API Security findings across all discovered candidate endpoints."""
        endpoints = self._discover_candidate_endpoints(mission)
        collected_evidence: List[Evidence] = []

        for target_url in endpoints:
            parsed = urllib.parse.urlparse(target_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else target_url

            all_probes = self.generator.generate_all_probes(target_url)
            probes_to_run = all_probes[:self.max_probes_per_endpoint]

            for probe in probes_to_run:
                resp = self.prober.execute_probe(mission, target_url, probe)
                result = self.analyzer.evaluate_probe(probe, resp, target_url)
                if result and result.is_valid_finding:
                    ev = self._emit_evidence(mission, result, target_url, base_url)
                    collected_evidence.append(ev)

        return collected_evidence

    def execute(self, mission: Any) -> List[Evidence]:
        """Plugin execution alias for collect()."""
        return self.collect(mission)

APISecurityTestingCollector = APISecurityCollector

RESTSecurityCollector = APISecurityCollector

APIVulnerabilityCollector = APISecurityCollector

BOLACollector = APISecurityCollector

IDORCollector = APISecurityCollector

MassAssignmentCollector = APISecurityCollector

RateLimitCollector = APISecurityCollector

ExcessiveDataExposureCollector = APISecurityCollector

MethodTamperingCollector = APISecurityCollector
