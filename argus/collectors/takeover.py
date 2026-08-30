from __future__ import annotations
import logging
from typing import Optional, List, Any
import urllib.parse
import httpx

from argus.collectors.base import BaseCollector
from argus.evidence.model import Evidence
from argus.graph.node import Node
from argus.recon.takeover_fingerprints import (
    TakeoverSignature,
    TAKEOVER_SIGNATURES,
    find_signature_by_cname,
)
from argus.runtime.local import LocalRuntime
from argus.tools.dnsx import DNSXTool, DNSResult

logger = logging.getLogger(__name__)


class SubdomainTakeoverCollector(BaseCollector):
    """Collector that detects potential subdomain takeovers via CNAME analysis and fingerprint verification."""

    def __init__(
        self,
        dns_tool: Optional[DNSXTool] = None,
        signatures: Optional[List[TakeoverSignature]] = None,
        runtime: Optional[LocalRuntime] = None,
        http_client: Optional[Any] = None,
    ):
        self.runtime = runtime or LocalRuntime()
        self.dns_tool = dns_tool or DNSXTool(runtime=self.runtime)
        self.signatures = signatures or TAKEOVER_SIGNATURES
        self.http_client = http_client

    def _probe_http(self, subdomain: str) -> tuple[Optional[int], str]:
        """Probes a subdomain via HTTP/HTTPS to retrieve status code and response body."""
        for scheme in ("https", "http"):
            url = f"{scheme}://{subdomain}"
            try:
                if self.http_client and hasattr(self.http_client, "get"):
                    # Use provided client
                    resp = self.http_client.get(url, timeout=5.0)
                    status_code = getattr(resp, "status_code", None)
                    body = getattr(resp, "text", "") or getattr(resp, "body", "") or ""
                    return status_code, str(body)
                else:
                    with httpx.Client(verify=False, follow_redirects=True, timeout=5.0) as client:
                        resp = client.get(url)
                        return resp.status_code, resp.text
            except Exception as e:
                logger.debug(f"HTTP probe for {url} failed: {e}")
                continue
        return None, ""

    def collect(self, mission: Any) -> List[Evidence]:
        """Executes subdomain takeover analysis on the mission targets."""
        subdomains = []
        raw_subs = getattr(mission, "subdomains", []) or []
        for s in raw_subs:
            if isinstance(s, dict):
                h = s.get("hostname") or s.get("host")
                if h:
                    subdomains.append(str(h))
            elif isinstance(s, str) and s:
                subdomains.append(s)

        if not subdomains and getattr(mission, "target", None):
            subdomains.append(str(mission.target))

        if not subdomains:
            logger.info("No subdomains available for takeover collection.")
            return []

        logger.info(f"Running Subdomain Takeover Analysis on {len(subdomains)} host(s)...")

        dns_results: List[DNSResult] = self.dns_tool.resolve(subdomains, cname=True, rcode=True)
        detected_evidence: List[Evidence] = []

        # Index DNS results by host
        dns_map = {res.host: res for res in dns_results}

        for subdomain in subdomains:
            dns_res = dns_map.get(subdomain)
            if not dns_res:
                continue

            cnames = dns_res.cname
            if not cnames:
                continue

            for cname in cnames:
                matching_sigs = [s for s in self.signatures if s.matches_cname(cname)]
                for sig in matching_sigs:
                    is_vulnerable = False
                    matched_fp = None
                    status_code = None

                    # Check for NXDOMAIN indicator
                    if sig.nxdomain and (dns_res.status_code == "NXDOMAIN" or not dns_res.a):
                        is_vulnerable = True
                        matched_fp = "NXDOMAIN status"

                    # If body fingerprints exist, probe over HTTP/S
                    if sig.fingerprints:
                        status_code, body = self._probe_http(subdomain)
                        for fp in sig.fingerprints:
                            if fp.lower() in body.lower():
                                is_vulnerable = True
                                matched_fp = fp
                                break
                    elif not sig.nxdomain:
                        # Fallback if no specific body fingerprints: check HTTP response
                        status_code, body = self._probe_http(subdomain)
                        if status_code and sig.matches_status(status_code):
                            is_vulnerable = True
                            matched_fp = f"Status code {status_code}"

                    if is_vulnerable:
                        template_id = f"subdomain-takeover-{sig.service.lower().replace(' ', '-')}"
                        evidence_title = f"Subdomain Takeover: {subdomain} ({sig.service})"
                        evidence_desc = (
                            f"Subdomain {subdomain} points via CNAME {cname} to dangling "
                            f"{sig.service} service. Fingerprint: {matched_fp or 'matched'}."
                        )

                        ev = Evidence(
                            mission_id=getattr(mission, "id", ""),
                            source_type="LOG",
                            created_by="SYSTEM_GENERATED",
                            title=evidence_title,
                            description=evidence_desc,
                            category="subdomain_takeover",
                            value=subdomain,
                            source=f"cname:{cname}",
                            status="CONFIRMED",
                            confidence=0.95,
                            severity=sig.severity,
                            metadata={
                                "subdomain": subdomain,
                                "cname": cname,
                                "service": sig.service,
                                "fingerprint_matched": matched_fp,
                                "status_code": status_code,
                                "severity": sig.severity,
                                "template_id": template_id,
                                "host": subdomain,
                            },
                        )

                        # Add to mission evidence
                        if hasattr(mission, "evidence") and mission.evidence is not None:
                            if hasattr(mission.evidence, "add"):
                                mission.evidence.add(ev)
                            elif isinstance(mission.evidence, list):
                                mission.evidence.append(ev)

                        # Add to mission vulnerabilities
                        if hasattr(mission, "vulnerabilities") and isinstance(mission.vulnerabilities, list):
                            vuln_entry = {
                                "name": f"Subdomain Takeover ({sig.service})",
                                "template_id": template_id,
                                "severity": sig.severity,
                                "host": subdomain,
                                "cname": cname,
                                "service": sig.service,
                                "description": evidence_desc,
                            }
                            mission.vulnerabilities.append(vuln_entry)

                        # Update attack surface graph if present
                        graph = getattr(mission, "attack_surface_graph", None) or getattr(mission, "graph", None)
                        if graph is not None and hasattr(graph, "add") and hasattr(graph, "connect"):
                            sub_id = f"subdomain:{subdomain}"
                            vuln_id = f"vulnerability:{template_id}:{subdomain}"
                            cname_id = f"cname:{cname}"

                            graph.add(Node(id=sub_id, type="subdomain", value=subdomain, metadata={"hostname": subdomain}))
                            graph.add(Node(id=cname_id, type="cname", value=cname, metadata={"cname": cname, "service": sig.service}))
                            graph.add(
                                Node(
                                    id=vuln_id,
                                    type="vulnerability",
                                    value=f"Subdomain Takeover ({sig.service})",
                                    metadata=ev.metadata,
                                )
                            )
                            graph.connect(sub_id, cname_id, edge_type="POINTS_TO_CNAME")
                            graph.connect(sub_id, vuln_id, edge_type="HAS_VULNERABILITY")

                        detected_evidence.append(ev)

        logger.info(f"Subdomain Takeover Analysis complete: {len(detected_evidence)} vulnerable target(s) identified.")
        return detected_evidence
