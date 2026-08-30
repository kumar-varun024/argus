"""
Access Control & IDOR Collector.

Performs active authorization testing across configured TestIdentities to detect:
1. Horizontal Privilege Escalation / Insecure Direct Object References (IDOR).
2. Vertical Privilege Escalation (unprivileged/guest access to administrative routes).
3. Reverse Proxy / WAF Access Control Header Bypasses (X-Original-URL, X-Rewrite-URL, X-Forwarded-Host).

Emits high-confidence Evidence(category="broken_access_control"), updates mission state,
and connects attack surface graph nodes with HAS_VULNERABILITY edges.
"""
from __future__ import annotations

import logging
import re
import urllib.parse
from typing import Any, Dict, List, Optional, Set, Tuple

from argus.analyzers.response_discrepancy import (
    ResponseDiscrepancyAnalyzer,
    DiscrepancyVerdict,
)
from argus.collectors.base import BaseCollector
from argus.evidence.model import Evidence, ProvenanceData
from argus.graph.node import Node
from argus.http.client import HttpResponse
from argus.http.coordinator import MultiIdentitySessionCoordinator
from argus.models.test_identity import TestIdentity

logger = logging.getLogger(__name__)

# Patterns identifying candidate endpoints with resource/user identifiers
HORIZONTAL_PATH_PATTERNS = [
    re.compile(r"/(?:(?:api(?:/v\d+)?/)?|(?:[a-zA-Z0-9_\-]+/)+)?(?:users?|accounts?|profiles?|orders?|invoices?|customers?|documents?|items?|patients?|members?)/([^/?#]+)", re.IGNORECASE),
    re.compile(r"/(?:[a-zA-Z0-9_\-]+)/([a-zA-Z0-9_\-]+|\d+)(?:/|$|\?)", re.IGNORECASE),
]

QUERY_ID_PARAM_REGEX = re.compile(
    r"[?&](?:id|ids|user_id|userId|account_id|accountId|order_id|orderId|uid|doc_id|docId|customer_id)(?:\[\])?=([^&#]+)",
    re.IGNORECASE,
)

# Patterns identifying administrative / restricted routes
VERTICAL_ADMIN_PATTERNS = [
    re.compile(r"/(?:api(?:/v\d+)?)?/(?:admin|management|superuser|root|system|settings/admin|dashboard/admin)(?:/.*)?$", re.IGNORECASE),
    re.compile(r"/(?:admin|dashboard|management|console|superuser|root|system-settings)(?:/.*)?$", re.IGNORECASE),
]

DEFAULT_ADMIN_PROBE_PATHS = [
    "/admin",
    "/admin/dashboard",
    "/admin/users",
    "/api/admin/users",
    "/api/admin/system",
    "/management/users",
]


class AccessControlCollector(BaseCollector):
    """
    Automated Access Control and IDOR engine.
    Orchestrates multi-identity sessions, verifies response discrepancies,
    emits confirmed Broken Access Control evidence, and builds graph edges.
    """

    def __init__(
        self,
        coordinator: Optional[MultiIdentitySessionCoordinator] = None,
        analyzer: Optional[ResponseDiscrepancyAnalyzer] = None,
        http_client: Optional[Any] = None,
    ):
        self.coordinator = coordinator or MultiIdentitySessionCoordinator()
        self.analyzer = analyzer or ResponseDiscrepancyAnalyzer()
        self.custom_http_client = http_client

    def _execute(
        self,
        identity: Optional[TestIdentity],
        mission: Any,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        **kwargs,
    ) -> HttpResponse:
        """Dispatches an HTTP request respecting custom mock client or session coordinator."""
        if self.custom_http_client is not None:
            if hasattr(self.custom_http_client, "execute_as"):
                return self.custom_http_client.execute_as(
                    identity=identity,
                    mission=mission,
                    method=method,
                    url=url,
                    headers=headers,
                    **kwargs,
                )
            req_headers = dict(headers or {})
            if identity:
                req_headers.update(identity.get_auth_headers())
            req_cookies = dict(identity.get_cookies()) if identity else {}
            try:
                return self.custom_http_client.get(mission, url, headers=req_headers, cookies=req_cookies, **kwargs)
            except TypeError:
                return self.custom_http_client.get(url, headers=req_headers, cookies=req_cookies, **kwargs)

        return self.coordinator.execute_as(
            identity=identity,
            mission=mission,
            method=method,
            url=url,
            headers=headers,
            **kwargs,
        )

    def _extract_candidate_endpoints(self, mission: Any) -> List[str]:
        """Extracts and normalizes unique candidate endpoint URLs from mission assets."""
        endpoints: Set[str] = set()

        # 1. Direct endpoints
        for ep in getattr(mission, "endpoints", []) or []:
            if isinstance(ep, dict):
                u = ep.get("url") or ep.get("path")
                if u:
                    endpoints.add(str(u))
            elif isinstance(ep, str) and ep:
                endpoints.add(ep)

        # 2. Live hosts with base URLs
        live_hosts: List[str] = []
        for h in getattr(mission, "live_hosts", []) or []:
            if isinstance(h, dict):
                u = h.get("url") or h.get("host")
                if u:
                    live_hosts.append(self._normalize_base_url(str(u)))
            elif isinstance(h, str) and h:
                live_hosts.append(self._normalize_base_url(h))

        # Target fallback
        target = getattr(mission, "target", None)
        if not live_hosts and target:
            live_hosts.append(self._normalize_base_url(str(target)))

        # Prepend base URLs to relative endpoints
        normalized_endpoints: Set[str] = set()
        for ep in endpoints:
            if ep.startswith("http://") or ep.startswith("https://"):
                normalized_endpoints.add(ep)
            else:
                for base in live_hosts:
                    full = urllib.parse.urljoin(base.rstrip("/") + "/", ep.lstrip("/"))
                    normalized_endpoints.add(full)

        # Also add default administrative probing paths for live hosts
        for base in live_hosts:
            for p in DEFAULT_ADMIN_PROBE_PATHS:
                normalized_endpoints.add(urllib.parse.urljoin(base.rstrip("/") + "/", p.lstrip("/")))

        return sorted(list(normalized_endpoints))

    def _normalize_base_url(self, raw_url: str) -> str:
        clean = raw_url.strip()
        if not clean.startswith("http://") and not clean.startswith("https://"):
            clean = f"https://{clean}"
        parsed = urllib.parse.urlparse(clean)
        scheme = parsed.scheme or "https"
        netloc = parsed.netloc or parsed.path.split("/")[0]
        return f"{scheme}://{netloc}"

    def _extract_base_host(self, url: str) -> str:
        parsed = urllib.parse.urlparse(url)
        scheme = parsed.scheme or "https"
        netloc = parsed.netloc or parsed.path.split("/")[0]
        return f"{scheme}://{netloc}"

    def _emit_evidence_and_update_graph(
        self,
        mission: Any,
        title: str,
        description: str,
        target_url: str,
        template_id: str,
        verdict: DiscrepancyVerdict,
        severity: str = "critical",
    ) -> Evidence:
        """Helper to create Evidence, append to mission, and update KnowledgeGraph."""
        base_host = self._extract_base_host(target_url)

        metadata = {
            "url": target_url,
            "host": base_host,
            "template_id": template_id,
            "category": "broken_access_control",
            "severity": severity,
            "discrepancy_type": verdict.discrepancy_type,
            "confidence": verdict.confidence,
            "reason": verdict.reason,
            "leaked_data": verdict.leaked_data,
            "similarity_score": verdict.similarity_score,
            "primary_status": verdict.primary_status,
            "secondary_status": verdict.secondary_status,
        }
        metadata.update(verdict.metadata)

        ev = Evidence(
            mission_id=getattr(mission, "id", ""),
            source_type="LOG",
            created_by="SYSTEM_GENERATED",
            title=title,
            description=description,
            category="broken_access_control",
            value=target_url,
            source=target_url,
            status="CONFIRMED",
            confidence=verdict.confidence,
            severity=severity,
            provenance=ProvenanceData(step_id="access_control_collector"),
            tags=["broken_access_control", "idor", verdict.discrepancy_type, template_id],
            metadata=metadata,
        )

        # 1. Mission evidence store
        if hasattr(mission, "evidence") and mission.evidence is not None:
            if hasattr(mission.evidence, "add"):
                mission.evidence.add(ev)
            elif isinstance(mission.evidence, list):
                mission.evidence.append(ev)

        # 2. Mission vulnerabilities list
        if hasattr(mission, "vulnerabilities") and isinstance(mission.vulnerabilities, list):
            mission.vulnerabilities.append({
                "name": title,
                "template_id": template_id,
                "severity": severity,
                "host": base_host,
                "url": target_url,
                "description": description,
                "discrepancy_type": verdict.discrepancy_type,
                "leaked_data": verdict.leaked_data,
            })

        # 3. KnowledgeGraph wiring
        graph = getattr(mission, "attack_surface_graph", None) or getattr(mission, "graph", None)
        if graph is not None and hasattr(graph, "add") and hasattr(graph, "connect"):
            lh_id = f"live_host:{base_host}"
            ep_id = f"endpoint:{target_url}"
            vuln_id = f"vulnerability:{template_id}:{target_url}"

            parsed = urllib.parse.urlparse(target_url)
            graph.add(Node(id=lh_id, type="live_host", value=base_host, metadata={"url": base_host, "host": parsed.hostname}))
            graph.add(Node(id=ep_id, type="endpoint", value=target_url, metadata={"url": target_url}))
            graph.add(Node(id=vuln_id, type="vulnerability", value=title, metadata=metadata))

            graph.connect(lh_id, ep_id, edge_type="HAS_ENDPOINT")
            graph.connect(lh_id, vuln_id, edge_type="HAS_VULNERABILITY")
            graph.connect(ep_id, vuln_id, edge_type="HAS_VULNERABILITY")

        return ev

    def collect(self, mission: Any) -> List[Evidence]:
        """
        Main execution loop for Access Control & IDOR engine.
        Unpacks ControlledMission if needed, runs all 3 test vectors, and returns findings.
        """
        raw_mission = getattr(mission, "_mission", mission)
        identities: List[TestIdentity] = getattr(raw_mission, "test_identities", []) or []
        endpoints = self._extract_candidate_endpoints(raw_mission)

        logger.info(
            f"Running Access Control Collector across {len(endpoints)} endpoint(s) with {len(identities)} identity/identities..."
        )

        all_evidence: List[Evidence] = []

        # Categorize identities
        admin_idents = [i for i in identities if str(i.role).lower() in ("admin", "administrator", "root", "superuser")]
        user_idents = [i for i in identities if str(i.role).lower() not in ("admin", "administrator", "root", "superuser")]

        primary_user = user_idents[0] if user_idents else (identities[0] if identities else None)
        secondary_user = user_idents[1] if len(user_idents) > 1 else None
        admin_ident = admin_idents[0] if admin_idents else (identities[0] if identities and identities[0].role == "admin" else None)

        tested_urls: Set[str] = set()

        # ---------------------------------------------------------------------
        # Vector 1: Horizontal IDOR Testing
        # ---------------------------------------------------------------------
        if primary_user and (secondary_user or len(identities) >= 2 or primary_user.credentials):
            attacker = secondary_user or (admin_ident if admin_ident != primary_user else None) or TestIdentity(id="unauth_user", role="user")

            for ep in endpoints:
                # Check for path parameter ID
                is_horiz_candidate = False
                for pat in HORIZONTAL_PATH_PATTERNS:
                    if pat.search(ep):
                        is_horiz_candidate = True
                        break
                if not is_horiz_candidate and QUERY_ID_PARAM_REGEX.search(ep):
                    is_horiz_candidate = True

                if not is_horiz_candidate:
                    continue

                tested_urls.add(ep)
                resp_owner = self._execute(primary_user, raw_mission, "GET", ep)
                resp_attacker = self._execute(attacker, raw_mission, "GET", ep)

                verdict = self.analyzer.analyze_horizontal(resp_owner, resp_attacker, primary_user, attacker)
                if verdict.is_vulnerable:
                    title = f"Broken Access Control (IDOR): {ep}"
                    desc = f"Insecure Direct Object Reference detected on {ep}. {verdict.reason}"
                    template_id = "idor-horizontal-privilege-escalation"
                    ev = self._emit_evidence_and_update_graph(
                        raw_mission, title, desc, ep, template_id, verdict, severity="critical"
                    )
                    all_evidence.append(ev)

        # ---------------------------------------------------------------------
        # Vector 2: Vertical Privilege Escalation Testing
        # ---------------------------------------------------------------------
        for ep in endpoints:
            is_admin_route = False
            for pat in VERTICAL_ADMIN_PATTERNS:
                if pat.search(ep):
                    is_admin_route = True
                    break

            if not is_admin_route:
                continue

            tested_urls.add(ep)
            unprivileged_tester = primary_user or TestIdentity(id="guest_user", role="user")

            resp_admin = self._execute(admin_ident, raw_mission, "GET", ep) if admin_ident else None
            resp_user = self._execute(unprivileged_tester, raw_mission, "GET", ep)

            verdict = self.analyzer.analyze_vertical(
                resp_admin, resp_user, admin_ident, unprivileged_tester, endpoint_path=ep
            )
            if verdict.is_vulnerable:
                title = f"Vertical Privilege Escalation: {ep}"
                desc = f"Administrative route {ep} is accessible to unprivileged identity ({unprivileged_tester.role}). {verdict.reason}"
                template_id = "vertical-privilege-escalation"
                ev = self._emit_evidence_and_update_graph(
                    raw_mission, title, desc, ep, template_id, verdict, severity="critical"
                )
                all_evidence.append(ev)

        # ---------------------------------------------------------------------
        # Vector 3: Reverse Proxy Header Bypass Testing
        # ---------------------------------------------------------------------
        for ep in endpoints:
            # Test endpoints that appear restricted or were not tested yet
            is_admin_candidate = any(p.search(ep) for p in VERTICAL_ADMIN_PATTERNS)
            if not is_admin_candidate and ep in tested_urls:
                continue

            parsed = urllib.parse.urlparse(ep)
            ep_path = parsed.path or "/"

            # Baseline unauthenticated / default request
            baseline_resp = self._execute(None, raw_mission, "GET", ep)
            if baseline_resp.status_code in (401, 403, 404):
                base_url = self._extract_base_host(ep)
                bypass_candidates = [
                    ("X-Original-URL", ep_path, base_url),
                    ("X-Rewrite-URL", ep_path, base_url),
                    ("X-Forwarded-Host", "127.0.0.1", ep),
                    ("X-Custom-IP-Authorization", "127.0.0.1", ep),
                ]

                for header_name, header_val, target_request_url in bypass_candidates:
                    bypass_resp = self._execute(
                        None,
                        raw_mission,
                        "GET",
                        target_request_url,
                        headers={header_name: header_val},
                    )
                    verdict = self.analyzer.analyze_header_bypass(
                        baseline_resp, bypass_resp, header_name, header_val
                    )
                    if verdict.is_vulnerable:
                        title = f"Access Control Header Bypass: {header_name} on {ep}"
                        desc = f"Header injection '{header_name}: {header_val}' bypassed access controls on {ep}. {verdict.reason}"
                        template_id = f"header-bypass-{header_name.lower().replace('-', '_')}"
                        ev = self._emit_evidence_and_update_graph(
                            raw_mission, title, desc, ep, template_id, verdict, severity="high"
                        )
                        all_evidence.append(ev)
                        break

        logger.info(f"Access Control testing completed. Identified {len(all_evidence)} vulnerability finding(s).")
        return all_evidence

    def execute(self, mission: Any) -> List[Evidence]:
        """Plugin/Specialist adapter interface."""
        return self.collect(mission)
