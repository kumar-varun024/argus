"""business_logic: Collector orchestration."""
from __future__ import annotations

import urllib.parse
from typing import Any, Callable, List, Optional, Set

from argus.collectors.base import BaseCollector
from argus.evidence.model import Evidence, ProvenanceData
from argus.graph.node import Node
from argus.http.client import AuthenticatedHttpClient
from argus.collectors.business_logic.models import BusinessLogicResult, BusinessLogicTechnique
from argus.collectors.business_logic.payloads import BusinessLogicPayloadGenerator
from argus.collectors.business_logic.probes import StatefulWorkflowProber
from argus.collectors.business_logic.analyzer import BusinessLogicSecurityAnalyzer


class BusinessLogicCollector(BaseCollector):
    """
    Business Logic Flaws & State Machine Security Detection Collector.

    Discovers candidate business endpoints, orchestrates stateful probing,
    and publishes confirmed findings via Quadruple State Publishing.
    """

    DEFAULT_CANDIDATE_PATHS = [
        "/api/checkout",
        "/api/v1/checkout",
        "/checkout",
        "/checkout/pay",
        "/checkout/fulfill",
        "/checkout/complete",
        "/api/cart",
        "/api/cart/add",
        "/api/cart/apply-coupon",
        "/cart/discount",
        "/api/users/profile",
        "/api/v1/users/me",
        "/api/users/role",
        "/api/account/upgrade",
        "/api/register",
        "/api/order/create",
        "/api/order/verify",
        "/api/subscription/upgrade",
        "/api/coupon/redeem",
    ]

    def __init__(
        self,
        http_client: Optional[AuthenticatedHttpClient] = None,
        generator: Optional[BusinessLogicPayloadGenerator] = None,
        analyzer: Optional[BusinessLogicSecurityAnalyzer] = None,
        prober: Optional[StatefulWorkflowProber] = None,
        transport_adapter: Optional[Callable[..., Any]] = None,
    ):
        self.http_client = http_client
        self.generator = generator or BusinessLogicPayloadGenerator()
        self.analyzer = analyzer or BusinessLogicSecurityAnalyzer()
        self.prober = prober or StatefulWorkflowProber(http_client=http_client, transport_adapter=transport_adapter)
        self.results: List[BusinessLogicResult] = []

    def _discover_candidate_endpoints(self, mission: Any) -> List[str]:
        """Discovers candidate business logic and state machine endpoints from mission."""
        candidates: Set[str] = set()
        raw_mission = getattr(mission, "_raw_mission", getattr(mission, "_mission", mission))

        # 1. Inspect mission.endpoints
        endpoints = getattr(raw_mission, "endpoints", []) or []
        for ep in endpoints:
            url_str = ep.get("url", ep) if isinstance(ep, dict) else str(ep)
            parsed = urllib.parse.urlparse(url_str)
            path_lower = parsed.path.lower()
            if any(k in path_lower for k in ("checkout", "cart", "pay", "order", "coupon", "promo", "voucher", "upgrade", "role", "profile", "account", "register", "step", "fulfill", "billing")):
                candidates.add(url_str)

        # 2. Inspect mission.live_hosts
        live_hosts = getattr(raw_mission, "live_hosts", []) or []
        for lh in live_hosts:
            host_str = lh.get("url", lh) if isinstance(lh, dict) else str(lh)
            parsed = urllib.parse.urlparse(host_str)
            base = f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else host_str
            for p in self.DEFAULT_CANDIDATE_PATHS:
                candidates.add(urllib.parse.urljoin(base, p))

        # 3. Fallback to mission.target
        target = getattr(raw_mission, "target", "") or ""
        if not candidates and target:
            base = target if target.startswith("http") else f"https://{target}"
            parsed_b = urllib.parse.urlparse(base)
            root_url = f"{parsed_b.scheme}://{parsed_b.netloc}" if parsed_b.netloc else base
            for candidate_path in self.DEFAULT_CANDIDATE_PATHS:
                candidates.add(urllib.parse.urljoin(root_url, candidate_path))

        return sorted(list(candidates))

    def _publish_finding(
        self,
        mission: Any,
        result: BusinessLogicResult,
        base_url: str,
        target_url: str,
    ) -> Evidence:
        """
        Executes Quadruple State Updates:
        1. raw_mission.evidence.add(ev)
        2. raw_mission.vulnerabilities.append({...})
        3. raw_mission.attack_surface_graph node & edge creation (HAS_ENDPOINT, HAS_VULNERABILITY)
        4. ControlledMission finding publishing
        """
        raw_mission = getattr(mission, "_raw_mission", getattr(mission, "_mission", mission))
        parsed = urllib.parse.urlparse(target_url)
        url_path = parsed.path or "/"

        cwe_id = result.cwe_id
        cvss_score = result.cvss_score
        tech_title = result.technique.replace("_", " ").title()

        title_map = {
            BusinessLogicTechnique.PRICE_TAMPERING.value: f"Business Logic Price & Quantity Tampering: {target_url}",
            BusinessLogicTechnique.WORKFLOW_STEP_SKIP.value: f"Multi-Step Workflow State Transition Skip: {target_url}",
            BusinessLogicTechnique.MASS_ASSIGNMENT.value: f"Mass Assignment Privilege Escalation: {target_url}",
            BusinessLogicTechnique.COUPON_STACKING.value: f"Coupon Stacking & Idempotency Abuse: {target_url}",
            BusinessLogicTechnique.DIFFERENTIAL_STATE_VERIFICATION.value: f"Differential Business Logic State Invariant Violation: {target_url}",
        }
        title_base = title_map.get(result.technique, f"Business Logic Vulnerability ({tech_title}): {target_url}")

        description = (
            f"Business Logic & State Machine validation on '{target_url}' identified a vulnerability using technique '{result.technique}' "
            f"under strategy '{result.strategy}'.\n"
            f"Evidence: {result.evidence_snippet}\n"
            f"CWE: {cwe_id} (CVSS: {cvss_score})"
        )

        ev = Evidence(
            category="business_logic",
            value=f"{result.technique}:{target_url}",
            source="business_logic",
            status="CONFIRMED",
            severity=result.severity,
            confidence=result.confidence,
            title=title_base,
            description=description,
            provenance=ProvenanceData(
                step_id="business_logic_collector",
            ),
            tags=[
                "business_logic",
                "state_machine",
                result.technique,
                result.strategy,
                result.template_id,
                cwe_id.lower(),
            ],
            metadata={
                "url": target_url,
                "host": base_url,
                "path": url_path,
                "category": "business_logic",
                "severity": result.severity,
                "confidence": result.confidence,
                "vulnerability_type": result.technique,
                "technique": result.technique,
                "strategy": result.strategy,
                "mutation_strategy": result.strategy,
                "matched_signature": result.matched_signature,
                "template_id": result.template_id,
                "status_code": result.status_code,
                "evidence_snippet": result.evidence_snippet[:250],
                "payload": str(result.payload)[:300],
                "parameter": result.parameter or "business_logic_param",
                "cwe_id": cwe_id,
                "cvss_score": cvss_score,
                "pre_state": str(result.pre_state),
                "post_state": str(result.post_state),
                "state_delta": str(result.state_delta),
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
                "strategy": result.strategy,
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

        # 4. ControlledMission wrapper publish
        if mission is not raw_mission and hasattr(mission, "publish_finding"):
            try:
                mission.publish_finding(ev.evidence_id, ev)
            except Exception:
                pass

        return ev

    def collect(self, mission: Any) -> List[Evidence]:
        """
        Executes active business logic & state machine probes across candidate endpoints.
        """
        discovered_candidates = self._discover_candidate_endpoints(mission)
        evidence_list: List[Evidence] = []
        raw_mission = getattr(mission, "_raw_mission", getattr(mission, "_mission", mission))

        for target_url in discovered_candidates:
            parsed = urllib.parse.urlparse(target_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else target_url
            path_lower = parsed.path.lower()

            # 1. Price / Quantity parameter tampering probe
            if any(k in path_lower for k in ("checkout", "cart", "pay", "order", "price", "amount")):
                probes = self.generator.build_price_tampering_payloads(target_url)
                for probe in probes:
                    resp = self.prober.execute_probe(probe)
                    res = self.analyzer.analyze_price_tampering(target_url, probe, resp)
                    if res is not None:
                        self.results.append(res)
                        ev = self._publish_finding(mission, res, base_url, target_url)
                        evidence_list.append(ev)
                        break

            # 2. Mass Assignment probe
            if any(k in path_lower for k in ("user", "profile", "account", "role", "register", "member")):
                probes = self.generator.build_mass_assignment_payloads(target_url)
                for probe in probes:
                    resp = self.prober.execute_probe(probe)
                    res = self.analyzer.analyze_mass_assignment(target_url, probe, resp)
                    if res is not None:
                        self.results.append(res)
                        ev = self._publish_finding(mission, res, base_url, target_url)
                        evidence_list.append(ev)
                        break

            # 3. Coupon Stacking probe
            if any(k in path_lower for k in ("coupon", "discount", "promo", "voucher", "redeem")):
                probes = self.generator.build_coupon_stacking_payloads(target_url)
                responses = [self.prober.execute_probe(p) for p in probes]
                res = self.analyzer.analyze_coupon_stacking(target_url, responses)
                if res is not None:
                    self.results.append(res)
                    ev = self._publish_finding(mission, res, base_url, target_url)
                    evidence_list.append(ev)

            # 4. Multi-Step Workflow Skip probe
            if any(k in path_lower for k in ("fulfill", "complete", "step", "verify", "finish")):
                seq = self.generator.build_workflow_skip_sequence(base_url)
                responses = self.prober.execute_workflow(seq)
                res = self.analyzer.analyze_workflow_step_skip(target_url, seq, responses)
                if res is not None:
                    self.results.append(res)
                    ev = self._publish_finding(mission, res, base_url, target_url)
                    evidence_list.append(ev)

        return evidence_list

    # Pipeline runner compatibility alias
    execute = collect

BusinessLogicFlawsCollector = BusinessLogicCollector
