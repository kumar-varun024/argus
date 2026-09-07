"""websocket: Collector orchestration."""
from __future__ import annotations

import logging
import urllib.parse
from typing import Any, List, Optional, Set

from argus.collectors.base import BaseCollector
from argus.evidence.model import Evidence, ProvenanceData
from argus.graph.node import Node
from argus.http.client import AuthenticatedHttpClient
from argus.collectors.websocket.models import WebSocketSecurityResult, WebSocketSeverity, WebSocketTechnique
from argus.collectors.websocket.payloads import WebSocketPayloadGenerator
from argus.collectors.websocket.analyzer import WebSocketSecurityAnalyzer

logger = logging.getLogger(__name__)


class WebSocketSecurityCollector(BaseCollector):
    """
    Collector for actively testing discovered WebSocket endpoints for CSWSH, broken authentication,
    frame injection, and protocol abuse.
    """

    DEFAULT_WS_CANDIDATE_PATHS: List[str] = [
        "/ws",
        "/wss",
        "/websocket",
        "/api/ws",
        "/api/v1/ws",
        "/v1/ws",
        "/v2/ws",
        "/socket.io/",
        "/socket.io/?EIO=4&transport=websocket",
        "/cable",
        "/sockjs/websocket",
        "/sockjs/",
        "/graphql-ws",
        "/subscriptions",
        "/graphql/subscriptions",
        "/primus/",
        "/engine.io/",
        "/chat",
        "/chat/ws",
        "/notifications",
        "/stream",
        "/live",
        "/signalr",
        "/signalr/connect",
        "/hub",
    ]

    def __init__(
        self,
        http_client: Optional[AuthenticatedHttpClient] = None,
        timeout: float = 10.0,
        max_retries: int = 2,
    ):
        super().__init__()
        self.http_client = http_client
        self.timeout = timeout
        self.max_retries = max_retries
        self.results: List[WebSocketSecurityResult] = []

    def _discover_candidate_endpoints(self, mission: Any) -> List[str]:
        """
        Identifies candidate WebSocket endpoints from mission assets (endpoints, live hosts, target).
        """
        raw_mission = getattr(mission, "_raw_mission", getattr(mission, "_mission", mission))
        candidates: Set[str] = set()

        # 1. Existing endpoints
        endpoints = list(getattr(raw_mission, "endpoints", []) or [])
        for ep in endpoints:
            ep_url = str(ep.get("url", ep) if isinstance(ep, dict) else ep).strip()
            if not ep_url:
                continue
            parsed = urllib.parse.urlparse(ep_url)
            if parsed.scheme in ("ws", "wss"):
                candidates.add(ep_url)
            elif any(ws_path in parsed.path.lower() for ws_path in ("/ws", "/socket.io", "/cable", "/graphql-ws", "/stream", "/chat", "/hub")):
                candidates.add(ep_url)

        # 2. Derive paths from live hosts and target
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
            for candidate_path in self.DEFAULT_WS_CANDIDATE_PATHS:
                candidates.add(urllib.parse.urljoin(root_url, candidate_path))

        return sorted(list(candidates))

    def _publish_finding(
        self,
        mission: Any,
        result: WebSocketSecurityResult,
        base_url: str,
        target_url: str,
    ) -> Evidence:
        """
        Executes quadruple state updates:
        1. mission.evidence.add(ev)
        2. mission.vulnerabilities.append({...})
        3. mission.attack_surface_graph node and edge creation (HAS_ENDPOINT, HAS_VULNERABILITY)
        4. ControlledMission finding publishing
        """
        raw_mission = getattr(mission, "_raw_mission", getattr(mission, "_mission", mission))
        parsed = urllib.parse.urlparse(target_url)
        url_path = parsed.path or "/"

        cwe_id = result.cwe_id
        cvss_score = result.cvss_score

        title_map = {
            WebSocketTechnique.CSWSH.value: f"Cross-Site WebSocket Hijacking (CSWSH) Exposed: {target_url}",
            WebSocketTechnique.BROKEN_AUTHENTICATION.value: f"Unauthenticated WebSocket Handshake Allowed: {target_url}",
            WebSocketTechnique.TOKEN_IN_QUERY_PARAM.value: f"WebSocket Authentication Token Leaked in Query Parameter: {target_url}",
            WebSocketTechnique.INJECTION_SQLI.value: f"WebSocket Frame SQL Injection Vulnerability: {target_url}",
            WebSocketTechnique.INJECTION_CMDI.value: f"WebSocket Frame Command Injection Vulnerability: {target_url}",
            WebSocketTechnique.INJECTION_XSS.value: f"WebSocket Frame Stored/Reflected XSS: {target_url}",
            WebSocketTechnique.PROTOTYPE_POLLUTION.value: f"WebSocket Frame Prototype Pollution: {target_url}",
            WebSocketTechnique.UNMASKED_FRAME_DOS.value: f"WebSocket Server Accepts Unmasked Client Frames: {target_url}",
            WebSocketTechnique.OVERSIZED_FRAME_DOS.value: f"WebSocket Oversized Frame Buffer Exhaustion: {target_url}",
            WebSocketTechnique.RATE_LIMIT_FLOOD.value: f"WebSocket Message Flooding & Missing Rate Limiting: {target_url}",
        }
        title_base = title_map.get(result.technique, f"WebSocket Security Vulnerability ({result.technique}): {target_url}")

        description = (
            f"WebSocket security auditing on '{target_url}' identified a vulnerability using technique '{result.technique}' "
            f"under mutation strategy '{result.mutation_strategy}'.\n"
            f"Evidence: {result.evidence_snippet}\n"
            f"CWE: {cwe_id} (CVSS: {cvss_score})"
        )

        ev = Evidence(
            category="websocket_security",
            value=f"{result.technique}:{target_url}",
            source="websocket_security",
            status="CONFIRMED",
            severity=result.severity,
            confidence=result.confidence,
            title=title_base,
            description=description,
            provenance=ProvenanceData(
                step_id="websocket_security_collector",
            ),
            tags=[
                "websocket",
                "websocket_security",
                result.technique,
                result.mutation_strategy,
                result.template_id,
                cwe_id.lower(),
            ],
            metadata={
                "url": target_url,
                "host": base_url,
                "path": url_path,
                "category": "websocket_security",
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
        client: Any,
        target_url: str,
        base_url: str,
    ) -> List[WebSocketSecurityResult]:
        """
        Executes active handshake and mutation probes against a single candidate endpoint.
        """
        findings: List[WebSocketSecurityResult] = []

        # 1. Baseline Handshake
        headers, ws_key = WebSocketPayloadGenerator.build_handshake_headers(target_url)
        try:
            resp = client.get(target_url, headers=headers)
        except Exception as e:
            logger.debug(f"Baseline handshake failed for {target_url}: {e}")
            return findings

        # Check for unauthenticated access on successful baseline handshake
        unauth_res = WebSocketSecurityAnalyzer.analyze_unauthenticated_handshake(
            target_url, ws_key, resp
        )
        if unauth_res:
            findings.append(unauth_res)

        # Check for token in query parameter
        token_res = WebSocketSecurityAnalyzer.analyze_query_token_leakage(target_url, resp)
        if token_res:
            findings.append(token_res)

        # If baseline handshake wasn't accepted at all (e.g. 404, 405), skip origin mutations unless it's a candidate route
        if resp.status_code not in (101, 200, 400, 401, 403, 426):
            return findings

        # 2. CSWSH & Origin Mutations
        origin_mutations = WebSocketPayloadGenerator.generate_origin_mutations(target_url)
        for strategy, mut_headers, origin_str in origin_mutations:
            mut_key = mut_headers.get("Sec-WebSocket-Key", ws_key)
            try:
                mut_resp = client.get(target_url, headers=mut_headers)
                cswsh_res = WebSocketSecurityAnalyzer.analyze_cswsh(
                    target_url, strategy, origin_str, mut_key, mut_resp
                )
                if cswsh_res:
                    findings.append(cswsh_res)
                    break  # Stop further CSWSH origin mutations once confirmed
            except Exception as e:
                logger.debug(f"CSWSH probe failed for {target_url} with origin {origin_str}: {e}")

        # 3. Subprotocol Tampering
        subproto_mutations = WebSocketPayloadGenerator.generate_subprotocol_mutations(target_url)
        for strategy, proto_headers, proto_str in subproto_mutations:
            proto_key = proto_headers.get("Sec-WebSocket-Key", ws_key)
            try:
                proto_resp = client.get(target_url, headers=proto_headers)
                if proto_resp.status_code == 101:
                    accept_hdr = proto_resp.headers.get("sec-websocket-accept") or proto_resp.headers.get("Sec-WebSocket-Accept")
                    if WebSocketSecurityAnalyzer.verify_sec_websocket_accept(proto_key, accept_hdr):
                        negotiated = proto_resp.headers.get("sec-websocket-protocol", "")
                        if "admin" in proto_str and "admin" in negotiated.lower():
                            findings.append(WebSocketSecurityResult(
                                technique=WebSocketTechnique.BROKEN_AUTHENTICATION.value,
                                mutation_strategy=strategy.value,
                                severity=WebSocketSeverity.HIGH.value,
                                confidence=0.90,
                                payload=f"Sec-WebSocket-Protocol: {proto_str}",
                                matched_signature="admin_subprotocol_negotiated",
                                evidence_snippet=f"WebSocket endpoint negotiated privileged subprotocol '{negotiated}'.",
                                endpoint_url=target_url,
                                parameter="Sec-WebSocket-Protocol",
                                parameter_type="http_header",
                                status_code=proto_resp.status_code,
                                cwe_id="CWE-287",
                                cvss_score=7.5,
                            ))
                            break
            except Exception as e:
                logger.debug(f"Subprotocol probe failed for {target_url}: {e}")

        # 4. Parameter Auth Bypass Mutations
        auth_mutations = WebSocketPayloadGenerator.generate_parameter_auth_bypass_mutations(target_url)
        for strategy, mut_url, auth_headers, desc in auth_mutations:
            try:
                auth_resp = client.get(mut_url, headers=auth_headers)
                query_res = WebSocketSecurityAnalyzer.analyze_query_token_leakage(mut_url, auth_resp)
                if query_res:
                    findings.append(query_res)
                    break
            except Exception as e:
                logger.debug(f"Auth param probe failed for {mut_url}: {e}")

        return findings

    def collect(self, mission: Any) -> List[Evidence]:
        """
        Executes active WebSocket security testing against candidate endpoints.
        """
        candidates = self._discover_candidate_endpoints(mission)
        if not candidates:
            logger.info("WebSocketSecurityCollector: No candidate WebSocket endpoints discovered.")
            return []

        evidences: List[Evidence] = []
        raw_mission = getattr(mission, "_raw_mission", getattr(mission, "_mission", mission))
        mission_target = str(getattr(raw_mission, "target", "") or "")

        def _run_with_client(client: Any) -> List[Evidence]:
            local_evs: List[Evidence] = []
            for target_url in candidates:
                parsed = urllib.parse.urlparse(target_url)
                base_url = f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else mission_target

                results = self._execute_probes(client, target_url, base_url)
                for res in results:
                    ev = self._publish_finding(mission, res, base_url, target_url)
                    local_evs.append(ev)
                    self.results.append(res)
            return local_evs

        if self.http_client is not None:
            evidences = _run_with_client(self.http_client)
        else:
            with AuthenticatedHttpClient(timeout=self.timeout, max_retries=self.max_retries) as client:
                evidences = _run_with_client(client)

        return evidences

    def execute(self, mission: Any) -> List[Evidence]:
        """Alias for collect(mission) conforming to standard collector execution interface."""
        return self.collect(mission)

WebSocketCollector = WebSocketSecurityCollector
