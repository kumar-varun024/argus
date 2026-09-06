"""cache_security: Collector orchestration."""
from __future__ import annotations

import urllib.parse
import uuid
from typing import Any, List, Optional, Set

from argus.collectors.base import BaseCollector
from argus.evidence.model import Evidence, ProvenanceData
from argus.graph.node import Node
from argus.collectors.cache_security.models import CacheSecurityResult, CacheVulnerabilityType
from argus.collectors.cache_security.payloads import CacheSecurityPayloadGenerator
from argus.collectors.cache_security.probes import CacheSecurityProber
from argus.collectors.cache_security.analyzer import CacheSecurityAnalyzer


class CacheSecurityCollector(BaseCollector):
    """
    Active Web Cache Poisoning and Web Cache Deception Collector for ARGUS.
    """

    def __init__(self, prober: Optional[CacheSecurityProber] = None, timeout: float = 10.0):
        self.prober = prober or CacheSecurityProber(timeout=timeout)
        self.generator = CacheSecurityPayloadGenerator()
        self.analyzer = CacheSecurityAnalyzer()

    def _discover_candidate_endpoints(self, mission: Any) -> List[str]:
        """Discovers candidate URLs from mission state."""
        raw_mission = getattr(mission, "_raw_mission", getattr(mission, "_mission", mission))
        candidates: Set[str] = set()

        # 1. From mission.endpoints
        for ep in getattr(raw_mission, "endpoints", []) or []:
            if isinstance(ep, dict):
                url = ep.get("url") or ep.get("path")
                if url:
                    candidates.add(str(url))
            elif isinstance(ep, str):
                candidates.add(ep)

        # 2. From mission.live_hosts
        for lh in getattr(raw_mission, "live_hosts", []) or []:
            if isinstance(lh, dict):
                url = lh.get("url")
                if url:
                    candidates.add(str(url))
            elif isinstance(lh, str):
                candidates.add(lh)

        # 3. From mission.target
        target = getattr(raw_mission, "target", "")
        if target:
            if not target.startswith("http://") and not target.startswith("https://"):
                candidates.add(f"https://{target}")
            else:
                candidates.add(target)

        # 4. From mission.evidence
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

        return list(candidates)

    def _emit_evidence(
        self,
        mission: Any,
        result: CacheSecurityResult,
        target_url: str,
        base_url: str,
    ) -> Evidence:
        """Publishes confirmed vulnerability evidence with Quadruple State Mutation."""
        title = f"Web Cache Security: {result.vector_name} on {target_url}"
        description = (
            f"Confirmed {result.vulnerability_type.value} via strategy {result.strategy.value}. "
            f"Reflected snippet: {result.reflected_snippet[:200]}"
        )
        raw_mission = getattr(mission, "_raw_mission", getattr(mission, "_mission", mission))

        ev = Evidence(
            category="cache_security",
            value=f"cache_security:{result.template_id}:{target_url}:{result.vector_name}",
            source="cache_security",
            status="CONFIRMED",
            confidence=result.confidence,
            severity=result.severity,
            title=title,
            description=description,
            provenance=ProvenanceData(
                observation_id=str(uuid.uuid4()),
                step_id=f"step_{result.vector_name}",
            ),
            tags=["cache_security", result.vulnerability_type.value, result.engine.value],
            metadata={
                "url": target_url,
                "host": base_url,
                "template_id": result.template_id,
                "technique": result.technique,
                "vulnerability_type": result.technique,
                "mutation_strategy": result.mutation_strategy,
                "strategy": result.mutation_strategy,
                "cache_engine": result.cache_engine,
                "engine": result.cache_engine,
                "cache_status_header": result.cache_status_header,
                "status_code": result.status_code,
                "evidence_snippet": result.reflected_snippet[:250],
                "payload": str(result.payload)[:300],
                "parameter": result.vector_name,
                "cwe_id": result.cwe_id,
                "cvss_score": result.cvss_score,
                "cache_buster": result.cache_buster,
                "is_valid_finding": result.is_valid_finding,
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
                "cache_engine": result.cache_engine,
                "parameter": result.vector_name,
                "strategy": result.mutation_strategy,
                "cwe_id": result.cwe_id,
                "cvss_score": result.cvss_score,
            })

        # 3. Attack Surface Knowledge Graph Expansion
        graph = getattr(raw_mission, "attack_surface_graph", None) or getattr(raw_mission, "graph", None)
        if graph is not None and hasattr(graph, "add") and hasattr(graph, "connect"):
            lh_id = f"live_host:{base_url}"
            ep_id = f"endpoint:{target_url}"
            vuln_id = f"vulnerability:{result.template_id}:{target_url}:{result.vector_name}"

            parsed_b = urllib.parse.urlparse(base_url)
            graph.add(Node(id=lh_id, type="live_host", value=base_url, metadata={"url": base_url, "host": parsed_b.hostname or base_url}))
            graph.add(Node(id=ep_id, type="endpoint", value=target_url, metadata={"url": target_url, "status_code": result.status_code}))
            graph.add(Node(id=vuln_id, type="vulnerability", value=title, metadata=ev.metadata))

            graph.connect(lh_id, ep_id, edge_type="HAS_ENDPOINT")
            graph.connect(lh_id, vuln_id, edge_type="HAS_VULNERABILITY")
            graph.connect(ep_id, vuln_id, edge_type="HAS_VULNERABILITY")

        # 4. ControlledMission wrapper notification
        if mission is not raw_mission and hasattr(mission, "publish_finding"):
            try:
                mission.publish_finding(ev.evidence_id, ev)
            except Exception:
                pass

        return ev

    def collect(self, mission: Any) -> List[Evidence]:
        """Collects web cache security findings across all candidate endpoints."""
        endpoints = self._discover_candidate_endpoints(mission)
        collected_evidence: List[Evidence] = []

        for target_url in endpoints:
            parsed = urllib.parse.urlparse(target_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else target_url

            # Generate probes
            probes = self.generator.generate_all_probes(target_url, is_auth=True)

            for probe in probes:
                responses = self.prober.execute_differential_sequence(target_url, probe)
                result: Optional[CacheSecurityResult] = None

                if probe.vulnerability_type == CacheVulnerabilityType.UNKEYED_HEADER_POISONING:
                    result = self.analyzer.evaluate_unkeyed_header_poisoning(responses, probe)
                elif probe.vulnerability_type in (CacheVulnerabilityType.UNKEYED_PARAM_POISONING, CacheVulnerabilityType.PARAMETER_CLOAKING):
                    result = self.analyzer.evaluate_unkeyed_param_poisoning(responses, probe)
                elif probe.vulnerability_type == CacheVulnerabilityType.WEB_CACHE_DECEPTION:
                    result = self.analyzer.evaluate_web_cache_deception(responses, probe)
                elif probe.vulnerability_type in (CacheVulnerabilityType.FAT_GET_POISONING, CacheVulnerabilityType.METHOD_OVERRIDE_POISONING):
                    result = self.analyzer.evaluate_normalization_flaws(responses, probe)

                if result and result.is_valid_finding:
                    ev = self._emit_evidence(mission, result, target_url, base_url)
                    collected_evidence.append(ev)

        return collected_evidence

    def execute(self, mission: Any) -> List[Evidence]:
        """Plugin execution alias for collect()."""
        return self.collect(mission)

WebCachePoisoningCollector = CacheSecurityCollector

CachePoisoningCollector = CacheSecurityCollector

WebCacheDeceptionCollector = CacheSecurityCollector
