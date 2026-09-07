"""auth_bypass: Collector orchestration."""
from __future__ import annotations

import urllib.parse
import uuid
from typing import Any, List, Optional, Set

from argus.collectors.base import BaseCollector
from argus.evidence.model import Evidence, ProvenanceData
from argus.graph.node import Node
from argus.collectors.auth_bypass.models import AuthBypassResult
from argus.collectors.auth_bypass.payloads import AuthBypassPayloadGenerator
from argus.collectors.auth_bypass.probes import AuthBypassProber
from argus.collectors.auth_bypass.analyzer import AuthBypassAnalyzer


class AuthBypassCollector(BaseCollector):
    """
    Main collector for Authentication Bypass & Credential Attack Detection in ARGUS.
    Orchestrates probe generation, HTTP execution, false positive analysis, and Quadruple State Publishing.
    """

    def __init__(
        self,
        http_client: Optional[Any] = None,
        prober: Optional[AuthBypassProber] = None,
        generator: Optional[AuthBypassPayloadGenerator] = None,
        analyzer: Optional[AuthBypassAnalyzer] = None,
        timeout: float = 10.0,
        max_probes_per_endpoint: int = 50,
        client: Optional[Any] = None,
    ) -> None:
        active_client = http_client or client
        self.prober = prober or AuthBypassProber(client=active_client, timeout=timeout)
        self.generator = generator or AuthBypassPayloadGenerator()
        self.analyzer = analyzer or AuthBypassAnalyzer()
        self.timeout = timeout
        self.max_probes_per_endpoint = max_probes_per_endpoint

    def _discover_candidate_endpoints(self, mission: Any) -> List[str]:
        """
        Discovers candidate endpoints using the 5-tier fallback hierarchy:
        1. mission.inputs.get("endpoints")
        2. raw_mission.endpoints
        3. raw_mission.live_hosts
        4. raw_mission.target
        5. raw_mission.evidence (URLs in metadata)
        """
        raw_mission = getattr(mission, "_raw_mission", getattr(mission, "_mission", mission))
        candidates: List[str] = []

        # 1. Inputs
        if hasattr(mission, "inputs") and isinstance(mission.inputs, dict):
            eps = mission.inputs.get("endpoints") or mission.inputs.get("urls") or mission.inputs.get("endpoint")
            if eps:
                if isinstance(eps, list):
                    candidates.extend([str(e) for e in eps if e])
                else:
                    candidates.append(str(eps))

        # 2. Endpoints
        if not candidates and hasattr(raw_mission, "endpoints") and raw_mission.endpoints:
            for ep in raw_mission.endpoints:
                if isinstance(ep, dict):
                    u = ep.get("url") or ep.get("path")
                    if u:
                        candidates.append(str(u))
                elif isinstance(ep, str):
                    candidates.append(ep)

        # 3. Live hosts
        if not candidates and hasattr(raw_mission, "live_hosts") and raw_mission.live_hosts:
            for h in raw_mission.live_hosts:
                if isinstance(h, dict):
                    u = h.get("url") or h.get("host")
                    if u:
                        candidates.append(str(u))
                elif isinstance(h, str):
                    candidates.append(h)

        # 4. Target
        if not candidates and hasattr(raw_mission, "target") and raw_mission.target:
            candidates.append(str(raw_mission.target))

        # 5. Evidence
        if not candidates and hasattr(raw_mission, "evidence") and raw_mission.evidence:
            ev_list = raw_mission.evidence.all() if hasattr(raw_mission.evidence, "all") else list(raw_mission.evidence)
            for ev in ev_list:
                if hasattr(ev, "metadata") and isinstance(ev.metadata, dict):
                    u = ev.metadata.get("url")
                    if u and isinstance(u, str):
                        candidates.append(u)

        # Normalize URLs
        normalized: List[str] = []
        seen: Set[str] = set()
        for c in candidates:
            c_str = c.strip()
            if not c_str.startswith("http://") and not c_str.startswith("https://"):
                c_str = f"http://{c_str}"
            if c_str not in seen:
                seen.add(c_str)
                normalized.append(c_str)

        return normalized

    def collect(self, mission: Any) -> List[Evidence]:
        """
        Executes authentication bypass analysis across discovered endpoints
        and emits confirmed findings to all Quadruple State sinks.
        """
        endpoints = self._discover_candidate_endpoints(mission)
        collected_evidence: List[Evidence] = []

        for target_url in endpoints:
            parsed = urllib.parse.urlparse(target_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else target_url

            all_probes = self.generator.generate_all_probes(target_url)
            probes_to_run = all_probes[: self.max_probes_per_endpoint]

            for probe in probes_to_run:
                resp = self.prober.execute_probe(mission, target_url, probe)
                result = self.analyzer.evaluate_probe(probe, resp, target_url)
                if result and result.is_valid_finding:
                    ev = self._emit_evidence(mission, result, target_url, base_url)
                    collected_evidence.append(ev)

        return collected_evidence

    def execute(self, mission: Any) -> List[Evidence]:
        """Plugin entry point delegating to collect(mission)."""
        return self.collect(mission)

    def _emit_evidence(
        self,
        mission: Any,
        result: AuthBypassResult,
        target_url: str,
        base_url: str,
    ) -> Evidence:
        """
        Quadruple State Publishing:
        1. raw_mission.evidence.add(ev)
        2. raw_mission.vulnerabilities.append(vuln_dict)
        3. attack_surface_graph.connect() nodes & edges (HAS_ENDPOINT, HAS_VULNERABILITY)
        4. ControlledMission.publish_finding(id, ev)
        """
        title = f"Authentication Vulnerability: {result.technique} on {target_url}"
        description = (
            f"{result.description} Parameter: {result.parameter}, "
            f"Strategy: {result.mutation_strategy}, CWE: {result.cwe_id}"
        )
        raw_mission = getattr(mission, "_raw_mission", getattr(mission, "_mission", mission))

        ev = Evidence(
            category="auth_bypass",
            value=f"auth_bypass:{result.template_id}:{target_url}:{result.parameter or 'endpoint'}",
            source="auth_bypass",
            status="CONFIRMED",
            confidence=result.confidence,
            severity=result.severity,
            title=title,
            description=description,
            provenance=ProvenanceData(
                observation_id=str(uuid.uuid4()),
                step_id=f"step_{result.technique}",
            ),
            tags=["auth_bypass", "authentication", str(result.vulnerability_type), result.mutation_strategy],
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

AuthenticationBypassCollector = AuthBypassCollector

CredentialAttackCollector = AuthBypassCollector

BruteForceCollector = AuthBypassCollector

DefaultCredentialsCollector = AuthBypassCollector

JWTMisconfigurationCollector = AuthBypassCollector

MFABypassCollector = AuthBypassCollector

SessionFixationCollector = AuthBypassCollector

AuthCollector = AuthBypassCollector
