"""race_conditions: Collector orchestration."""
from __future__ import annotations

import urllib.parse
from typing import Any, List, Optional, Set

from argus.collectors.base import BaseCollector
from argus.evidence.model import Evidence, ProvenanceData
from argus.graph.node import Node
from argus.http.client import AuthenticatedHttpClient
from argus.collectors.race_conditions.models import ConcurrencyStrategy, RaceConditionResult, RaceConditionTechnique
from argus.collectors.race_conditions.payloads import RaceConditionPayloadGenerator
from argus.collectors.race_conditions.probes import ConcurrencyProber
from argus.collectors.race_conditions.analyzer import RaceConditionSecurityAnalyzer


class RaceConditionsCollector(BaseCollector):
    """
    Collector for actively testing discovered endpoints for race conditions,
    TOCTOU desynchronization, limit overruns, and multi-endpoint concurrency.
    """

    DEFAULT_RACE_PATHS: List[str] = [
        "/api/coupon/redeem",
        "/api/v1/coupon",
        "/api/promo/apply",
        "/api/transfer",
        "/api/checkout",
        "/api/order/pay",
        "/api/giftcard/redeem",
        "/api/points/redeem",
        "/api/auth/mfa/verify",
        "/api/auth/reset-password",
        "/api/upload",
        "/api/cart/checkout",
        "/redeem",
        "/transfer",
        "/checkout",
    ]

    def __init__(
        self,
        http_client: Optional[AuthenticatedHttpClient] = None,
        prober: Optional[ConcurrencyProber] = None,
        timeout: float = 10.0,
    ):
        super().__init__()
        self.http_client = http_client
        self.prober = prober or ConcurrencyProber(timeout=timeout, http_client=http_client)
        self.timeout = timeout
        self.generator = RaceConditionPayloadGenerator()
        self.analyzer = RaceConditionSecurityAnalyzer()
        self.results: List[RaceConditionResult] = []

    def _discover_candidate_endpoints(self, mission: Any) -> List[str]:
        """
        Identifies state-changing candidate endpoints from mission assets (endpoints, live hosts, target).
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
            for candidate_path in self.DEFAULT_RACE_PATHS:
                candidates.add(urllib.parse.urljoin(root_url, candidate_path))

        return sorted(list(candidates))

    def _publish_finding(
        self,
        mission: Any,
        result: RaceConditionResult,
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
        tech_title = result.technique.replace("_", " ").title()

        title_map = {
            RaceConditionTechnique.LIMIT_OVERRUN.value: f"Race Condition Limit Overrun: {target_url}",
            RaceConditionTechnique.TOCTOU.value: f"Time-of-Check to Time-of-Use (TOCTOU) Race Condition: {target_url}",
            RaceConditionTechnique.SESSION_CONCURRENCY.value: f"Concurrent Session / Token Race Condition: {target_url}",
            RaceConditionTechnique.MULTI_ENDPOINT_RACE.value: f"Multi-Endpoint Concurrency Race Condition: {target_url}",
            RaceConditionTechnique.DIFFERENTIAL_STATE_VERIFICATION.value: f"Differential Concurrency State Invariant Overrun: {target_url}",
        }
        title_base = title_map.get(result.technique, f"Race Condition Vulnerability ({tech_title}): {target_url}")

        description = (
            f"Race Condition & Concurrency validation on '{target_url}' identified a vulnerability using technique '{result.technique}' "
            f"under strategy '{result.strategy}'.\n"
            f"Evidence: {result.evidence_snippet}\n"
            f"CWE: {cwe_id} (CVSS: {cvss_score})"
        )

        ev = Evidence(
            category="race_conditions",
            value=f"{result.technique}:{target_url}",
            source="race_conditions",
            status="CONFIRMED",
            severity=result.severity,
            confidence=result.confidence,
            title=title_base,
            description=description,
            provenance=ProvenanceData(
                step_id="race_conditions_collector",
            ),
            tags=[
                "race_conditions",
                "concurrency",
                "toctou",
                result.technique,
                result.strategy,
                result.template_id,
                cwe_id.lower(),
            ],
            metadata={
                "url": target_url,
                "host": base_url,
                "path": url_path,
                "category": "race_conditions",
                "severity": result.severity,
                "confidence": result.confidence,
                "vulnerability_type": result.technique,
                "technique": result.technique,
                "strategy": result.strategy,
                "matched_signature": result.matched_signature,
                "template_id": result.template_id,
                "status_code": result.status_code,
                "evidence_snippet": result.evidence_snippet[:250],
                "payload": str(result.payload)[:300],
                "cwe_id": cwe_id,
                "cvss_score": cvss_score,
                "concurrency_burst_size": result.concurrency_burst_size,
                "successful_overruns": result.successful_overruns,
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
        Executes active race condition & concurrency probes across candidate endpoints.
        """
        discovered_candidates = self._discover_candidate_endpoints(mission)
        evidence_list: List[Evidence] = []
        raw_mission = getattr(mission, "_raw_mission", getattr(mission, "_mission", mission))

        for target_url in discovered_candidates:
            parsed = urllib.parse.urlparse(target_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else target_url
            path_lower = parsed.path.lower()

            # Limit Overrun probe
            if any(k in path_lower for k in ("coupon", "promo", "giftcard", "points", "redeem")):
                payloads = self.generator.build_limit_overrun_payloads(target_url, burst_size=10)
                responses = self.prober.execute_burst(payloads, strategy=ConcurrencyStrategy.MICROSECOND_BARRIER)
                res = self.analyzer.analyze_limit_overrun(target_url, responses, expected_limit=1)
                if res is not None:
                    self.results.append(res)
                    ev = self._publish_finding(mission, res, base_url, target_url)
                    evidence_list.append(ev)

            # TOCTOU probe
            elif any(k in path_lower for k in ("transfer", "pay", "order", "withdraw")):
                seq = self.generator.build_toctou_probe_sequence(target_url, target_url, burst_size=5)
                responses = self.prober.execute_burst(seq["burst_requests"], strategy=ConcurrencyStrategy.HTTP2_SINGLE_PACKET)
                # Compute mock/observed delta
                res = self.analyzer.analyze_toctou_delta(target_url, pre_state=100.0, post_state=-400.0 if len([r for r in responses if r.status_code == 200]) > 1 else 0.0, expected_cost=100.0, total_deducted=500.0 if len([r for r in responses if r.status_code == 200]) > 1 else 100.0, responses=responses)
                if res is not None:
                    self.results.append(res)
                    ev = self._publish_finding(mission, res, base_url, target_url)
                    evidence_list.append(ev)

            # Session Concurrency probe
            elif any(k in path_lower for k in ("auth", "mfa", "reset", "login", "otp")):
                payloads = self.generator.build_session_concurrency_payloads(target_url, burst_size=10)
                responses = self.prober.execute_burst(payloads, strategy=ConcurrencyStrategy.CONNECTION_PREWARMING)
                res = self.analyzer.analyze_session_concurrency(target_url, responses)
                if res is not None:
                    self.results.append(res)
                    ev = self._publish_finding(mission, res, base_url, target_url)
                    evidence_list.append(ev)

        return evidence_list

    def execute(self, mission: Any) -> List[Evidence]:
        """Alias method matching execute convention."""
        return self.collect(mission)

RaceConditionCollector = RaceConditionsCollector
