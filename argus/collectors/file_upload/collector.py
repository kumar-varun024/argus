"""file_upload: Collector orchestration."""
from __future__ import annotations

import urllib.parse
import uuid
from typing import Any, List, Optional, Set

from argus.collectors.base import BaseCollector
from argus.evidence.model import Evidence, ProvenanceData
from argus.graph.node import Node
from argus.http.client import AuthenticatedHttpClient
from argus.collectors.file_upload.models import FileUploadResult
from argus.collectors.file_upload.payloads import FileUploadPayloadGenerator
from argus.collectors.file_upload.probes import FileUploadProber
from argus.collectors.file_upload.analyzer import FileUploadAnalyzer


class FileUploadCollector(BaseCollector):
    """
    Active security collector for File Upload Vulnerabilities in ARGUS.
    Orchestrates probe generation, multipart request dispatch, response analysis,
    and quadruple state publishing.
    """

    def __init__(
        self,
        http_client: Optional[Any] = None,
        prober: Optional[FileUploadProber] = None,
        generator: Optional[FileUploadPayloadGenerator] = None,
        analyzer: Optional[FileUploadAnalyzer] = None,
        timeout: float = 10.0,
        max_probes_per_endpoint: int = 50,
        client: Optional[Any] = None,
    ):
        effective_client = client or http_client or AuthenticatedHttpClient(timeout=timeout)
        self.http_client = effective_client
        self.prober = prober or FileUploadProber(client=self.http_client, timeout=timeout)
        self.generator = generator or FileUploadPayloadGenerator()
        self.analyzer = analyzer or FileUploadAnalyzer()
        self.timeout = timeout
        self.max_probes_per_endpoint = max_probes_per_endpoint

    def _discover_candidate_endpoints(self, mission: Any) -> List[str]:
        """Discovers candidate file upload endpoints from mission state."""
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

        # 2. From mission.live_hosts (fallback if no explicit endpoints found)
        if not candidates:
            for lh in getattr(raw_mission, "live_hosts", []) or []:
                if isinstance(lh, dict):
                    url = lh.get("url")
                    if url:
                        candidates.add(str(url))
                elif isinstance(lh, str):
                    candidates.add(lh)

        # 3. From mission.target (fallback if no explicit endpoints or live_hosts found)
        if not candidates:
            target = getattr(raw_mission, "target", "")
            if target:
                if not str(target).startswith("http://") and not str(target).startswith("https://"):
                    candidates.add(f"https://{target}")
                else:
                    candidates.add(str(target))

        # 4. From mission.evidence (fallback if still empty)
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
        result: FileUploadResult,
        target_url: str,
        base_url: str,
    ) -> Evidence:
        """Publishes validated File Upload finding with Quadruple State Mutation."""
        title = f"File Upload Vulnerability: {result.technique} on {target_url}"
        description = (
            f"{result.description} Filename: {result.filename}, "
            f"Content-Type: {result.content_type}, Strategy: {result.mutation_strategy}"
        )
        raw_mission = getattr(mission, "_raw_mission", getattr(mission, "_mission", mission))

        ev = Evidence(
            category="file_upload",
            value=f"file_upload:{result.template_id}:{target_url}:{result.filename}",
            source="file_upload",
            status="CONFIRMED",
            confidence=result.confidence,
            severity=result.severity,
            title=title,
            description=description,
            provenance=ProvenanceData(
                observation_id=str(uuid.uuid4()),
                step_id=f"step_{result.technique}",
            ),
            tags=["file_upload", "upload_security", str(result.vulnerability_type), result.mutation_strategy],
            metadata={
                "url": target_url,
                "host": base_url,
                "template_id": result.template_id,
                "technique": result.technique,
                "vulnerability_type": str(result.vulnerability_type),
                "filename": result.filename,
                "content_type": result.content_type,
                "mutation_strategy": result.mutation_strategy,
                "strategy": result.mutation_strategy,
                "target_runtime": result.target_runtime,
                "canary_token": result.canary_token,
                "storage_path": result.storage_path,
                "uploaded_file_url": result.uploaded_file_url,
                "status_code": result.status_code,
                "evidence_snippet": result.evidence_snippet[:250],
                "parameter": result.filename,
                "cwe_id": result.cwe_id,
                "cvss_score": result.cvss_score,
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
                "filename": result.filename,
                "parameter": result.filename,
                "strategy": result.mutation_strategy,
                "cwe_id": result.cwe_id,
                "cvss_score": result.cvss_score,
            })

        # 3. Attack Surface Knowledge Graph Expansion
        graph = getattr(raw_mission, "attack_surface_graph", None) or getattr(raw_mission, "graph", None)
        if graph is not None and hasattr(graph, "add") and hasattr(graph, "connect"):
            lh_id = f"live_host:{base_url}"
            ep_id = f"endpoint:{target_url}"
            vuln_id = f"vulnerability:{result.template_id}:{target_url}:{result.filename}"

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
        """Collects File Upload findings across all discovered candidate endpoints."""
        endpoints = self._discover_candidate_endpoints(mission)
        collected_evidence: List[Evidence] = []
        all_probes = self.generator.generate_all_probes()

        for target_url in endpoints:
            parsed = urllib.parse.urlparse(target_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else target_url

            probes_to_run = all_probes[:self.max_probes_per_endpoint]
            for probe in probes_to_run:
                resp = self.prober.execute_upload(mission, target_url, probe)
                result = self.analyzer.evaluate_probe(probe, resp, target_url)
                if result and result.is_valid_finding:
                    ev = self._emit_evidence(mission, result, target_url, base_url)
                    collected_evidence.append(ev)

        return collected_evidence

    def execute(self, mission: Any) -> List[Evidence]:
        """Plugin execution alias for collect()."""
        return self.collect(mission)

UploadVulnerabilityCollector = FileUploadCollector

FileUploadSecurityCollector = FileUploadCollector

UnrestrictedFileUploadCollector = FileUploadCollector

ArbitraryFileUploadCollector = FileUploadCollector
