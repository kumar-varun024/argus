"""
Comprehensive Unit and Functional Tests for WebSocketSecurityCollector, WebSocketPayloadGenerator,
WebSocketSecurityAnalyzer, AttackSurfaceGraph integration, TaskGenerator DAG wiring, and ToolRegistry.
"""
import base64
import hashlib
import json
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple
import pytest

from argus.collectors.websocket import (
    WebSocketSecurityCollector,
    WebSocketCollector,
    WebSocketPayloadGenerator,
    WebSocketSecurityAnalyzer,
    WebSocketSecurityResult,
    WebSocketSeverity,
    WebSocketTechnique,
    WebSocketMutationStrategy,
    CSWSH_VULNERABLE_SIGNATURES,
    HARDENED_WS_DEFENSE_SIGNATURES,
    SQL_ERROR_SIGNATURES,
    COMMAND_OUTPUT_SIGNATURES,
    XSS_OUTPUT_SIGNATURES,
    PROTOTYPE_POLLUTION_SIGNATURES,
    DOS_CRASH_SIGNATURES,
)
from argus.evidence.model import Evidence
from argus.evidence.store import EvidenceStore
from argus.graph.graph import KnowledgeGraph
from argus.graph.node import Node
from argus.graph.attack_surface import AttackSurfaceGraphBuilder
from argus.http.client import HttpResponse
from argus.planning.models import CoverageGap, TaskCategory
from argus.planning.task_generator import TaskGenerator, _RECON_TEMPLATES
from argus.plugins.interfaces import ControlledMission
from argus.reporting.cvss import CVSSCalculator
from argus.reporting.models import ReportSeverity
from argus.runtime.mission import Mission
from argus.runtime.plugins import PluginExecutorAdapter
from argus.runtime.registry import registry


class MockWebSocketHttpClient:
    """In-memory Mock HTTP/WebSocket client for deterministic unit and integration tests."""

    def __init__(
        self,
        default_status: int = 101,
        accept_valid_keys: bool = True,
        origin_validator: Optional[Any] = None,
        routes: Optional[Dict[str, Tuple[int, str, Dict[str, str], float]]] = None,
    ):
        self.default_status = default_status
        self.accept_valid_keys = accept_valid_keys
        self.origin_validator = origin_validator
        self.routes: Dict[str, Tuple[int, str, Dict[str, str], float]] = routes or {}
        self.requested_gets: List[Dict[str, Any]] = []

    def set_route(
        self,
        url_pattern: str,
        status_code: int,
        body: str = "",
        headers: Optional[Dict[str, str]] = None,
        elapsed: float = 0.05,
    ):
        self.routes[url_pattern] = (status_code, body, headers or {}, elapsed)

    def get(self, mission_or_url: Any, url: Optional[str] = None, **kwargs) -> HttpResponse:
        target_url = url if url is not None else mission_or_url
        if not isinstance(target_url, str):
            target_url = str(target_url)

        headers = kwargs.get("headers") or {}
        cookies = kwargs.get("cookies") or {}
        self.requested_gets.append({"url": target_url, "headers": headers, "cookies": cookies})

        # Check explicit routes first
        for rk, (sc, b, rh, el) in self.routes.items():
            if rk in target_url:
                resp_hdrs = dict(rh)
                ws_key = headers.get("Sec-WebSocket-Key") or headers.get("sec-websocket-key")
                if sc == 101 and ws_key and "sec-websocket-accept" not in [k.lower() for k in resp_hdrs]:
                    resp_hdrs["sec-websocket-accept"] = WebSocketPayloadGenerator.compute_sec_websocket_accept(ws_key)
                    resp_hdrs["upgrade"] = "websocket"
                    resp_hdrs["connection"] = "Upgrade"
                return HttpResponse(
                    success=(200 <= sc < 300 or sc == 101),
                    status_code=sc,
                    raw_body=b,
                    body=b,
                    headers=resp_hdrs,
                    url=target_url,
                    elapsed=el,
                )

        # Check origin validation
        origin = headers.get("Origin") or headers.get("origin")
        if self.origin_validator is not None and origin is not None:
            try:
                is_valid = self.origin_validator(target_url, origin)
            except TypeError:
                is_valid = self.origin_validator(origin)
            if not is_valid:
                return HttpResponse(
                    success=False,
                    status_code=403,
                    raw_body="Forbidden: Cross-origin WebSocket connection not allowed",
                    body="Forbidden: Cross-origin WebSocket connection not allowed",
                    headers={"content-type": "text/plain"},
                    url=target_url,
                    elapsed=0.05,
                )

        # Default WebSocket handshake handling
        sc = self.default_status
        ws_key = headers.get("Sec-WebSocket-Key") or headers.get("sec-websocket-key")
        resp_headers: Dict[str, str] = {}

        if sc == 101 and ws_key and self.accept_valid_keys:
            resp_headers["sec-websocket-accept"] = WebSocketPayloadGenerator.compute_sec_websocket_accept(ws_key)
            resp_headers["upgrade"] = "websocket"
            resp_headers["connection"] = "Upgrade"
            proto = headers.get("Sec-WebSocket-Protocol")
            if proto:
                resp_headers["sec-websocket-protocol"] = proto.split(",")[0].strip()

        return HttpResponse(
            success=(200 <= sc < 300 or sc == 101),
            status_code=sc,
            raw_body="" if sc == 101 else "OK",
            body="" if sc == 101 else "OK",
            headers=resp_headers,
            url=target_url,
            elapsed=0.05,
        )


# ============================================================================
# Suite 1: Enums & Data Models
# ============================================================================

class TestWebSocketEnumsAndDataModels:
    def test_severity_enum_integrity(self):
        assert WebSocketSeverity.CRITICAL == "critical"
        assert WebSocketSeverity.HIGH == "high"
        assert WebSocketSeverity.MEDIUM == "medium"
        assert WebSocketSeverity.LOW == "low"
        assert WebSocketSeverity.INFO == "info"

    def test_technique_enum_integrity(self):
        assert WebSocketTechnique.CSWSH == "cswsh"
        assert WebSocketTechnique.BROKEN_AUTHENTICATION == "broken_authentication"
        assert WebSocketTechnique.TOKEN_IN_QUERY_PARAM == "token_in_query_param"
        assert WebSocketTechnique.INJECTION_SQLI == "injection_sqli"
        assert WebSocketTechnique.INJECTION_CMDI == "injection_cmdi"
        assert WebSocketTechnique.INJECTION_XSS == "injection_xss"
        assert WebSocketTechnique.PROTOTYPE_POLLUTION == "prototype_pollution"
        assert WebSocketTechnique.UNMASKED_FRAME_DOS == "unmasked_frame_dos"
        assert WebSocketTechnique.OVERSIZED_FRAME_DOS == "oversized_frame_dos"
        assert WebSocketTechnique.RATE_LIMIT_FLOOD == "rate_limit_flood"

    def test_mutation_strategy_enum_integrity(self):
        assert WebSocketMutationStrategy.STANDARD == "standard"
        assert WebSocketMutationStrategy.ORIGIN_MANIPULATION == "origin_manipulation"
        assert WebSocketMutationStrategy.SUBPROTOCOL_TAMPERING == "subprotocol_tampering"
        assert WebSocketMutationStrategy.HOP_BY_HOP_SMUGGLING == "hop_by_hop_smuggling"
        assert WebSocketMutationStrategy.CASING_WHITESPACE_MUTATION == "casing_whitespace_mutation"
        assert WebSocketMutationStrategy.EXTENSION_DEFLATE_FUZZING == "extension_deflate_fuzzing"
        assert WebSocketMutationStrategy.PARAMETER_AUTHENTICATION_BYPASS == "parameter_authentication_bypass"

    def test_security_result_dataclass(self):
        res = WebSocketSecurityResult(
            technique=WebSocketTechnique.CSWSH.value,
            mutation_strategy=WebSocketMutationStrategy.ORIGIN_MANIPULATION.value,
            severity=WebSocketSeverity.HIGH.value,
            confidence=0.95,
            payload="Origin: https://evil.com",
            matched_signature="cswsh_untrusted_origin_accepted",
            evidence_snippet="Server accepted cross-origin handshake",
            endpoint_url="https://api.example.com/ws",
        )
        assert res.technique == "cswsh"
        assert res.vulnerability_type == "cswsh"
        assert res.severity == "high"
        assert res.confidence == 0.95
        assert res.status_code == 101
        assert res.cwe_id == "CWE-1385"
        assert res.cvss_score == 8.1


# ============================================================================
# Suite 2: Payload Generator & Mutation Strategies
# ============================================================================

class TestWebSocketPayloadGenerator:
    def test_sec_websocket_key_generation(self):
        key = WebSocketPayloadGenerator.generate_sec_websocket_key()
        assert isinstance(key, str)
        # Base64 string decoding to 16 bytes
        decoded = base64.b64decode(key)
        assert len(decoded) == 16

    def test_sec_websocket_accept_computation_rfc6455(self):
        # RFC 6455 §4.2.2 standard test vector:
        # Client Key: "dGhlIHNhbXBsZSBub25jZQ==" -> Expected Accept: "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        client_key = "dGhlIHNhbXBsZSBub25jZQ=="
        expected_accept = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        accept = WebSocketPayloadGenerator.compute_sec_websocket_accept(client_key)
        assert accept == expected_accept

    def test_build_handshake_headers(self):
        headers, key = WebSocketPayloadGenerator.build_handshake_headers(
            url="https://example.com/ws",
            origin="https://example.com",
            subprotocols=["chat", "superchat"],
            extensions=["permessage-deflate"],
        )
        assert headers["Upgrade"] == "websocket"
        assert headers["Connection"] == "Upgrade"
        assert headers["Sec-WebSocket-Key"] == key
        assert headers["Sec-WebSocket-Version"] == "13"
        assert headers["Origin"] == "https://example.com"
        assert headers["Sec-WebSocket-Protocol"] == "chat, superchat"
        assert headers["Sec-WebSocket-Extensions"] == "permessage-deflate"

    def test_generate_origin_mutations_count_and_content(self):
        mutations = WebSocketPayloadGenerator.generate_origin_mutations("https://target.com/ws")
        assert len(mutations) >= 5
        origins = [m[2] for m in mutations]
        assert "null" in origins
        assert "https://evil.com" in origins
        assert "https://target.com.attacker.com" in origins
        assert "http://target.com" in origins
        assert any(m[0] == WebSocketMutationStrategy.ORIGIN_MANIPULATION for m in mutations)

    def test_generate_subprotocol_mutations(self):
        mutations = WebSocketPayloadGenerator.generate_subprotocol_mutations("https://target.com/ws")
        assert len(mutations) >= 4
        proto_strings = [m[2] for m in mutations]
        assert any("admin" in p for p in proto_strings)
        assert any("graphql-ws" in p for p in proto_strings)
        assert all(m[0] == WebSocketMutationStrategy.SUBPROTOCOL_TAMPERING for m in mutations)

    def test_generate_hop_by_hop_mutations(self):
        mutations = WebSocketPayloadGenerator.generate_hop_by_hop_mutations("https://target.com/ws")
        assert len(mutations) >= 3
        assert all(m[0] == WebSocketMutationStrategy.HOP_BY_HOP_SMUGGLING for m in mutations)
        conns = [m[1].get("Connection") for m in mutations]
        assert "keep-alive, Upgrade" in conns or "close, Upgrade" in conns

    def test_generate_casing_whitespace_mutations(self):
        mutations = WebSocketPayloadGenerator.generate_casing_whitespace_mutations("https://target.com/ws")
        assert len(mutations) >= 3
        assert all(m[0] == WebSocketMutationStrategy.CASING_WHITESPACE_MUTATION for m in mutations)

    def test_generate_extension_deflate_mutations(self):
        mutations = WebSocketPayloadGenerator.generate_extension_deflate_mutations("https://target.com/ws")
        assert len(mutations) >= 3
        assert all(m[0] == WebSocketMutationStrategy.EXTENSION_DEFLATE_FUZZING for m in mutations)
        exts = [m[2] for m in mutations]
        assert any("permessage-deflate" in e for e in exts)

    def test_generate_parameter_auth_bypass_mutations(self):
        probes = WebSocketPayloadGenerator.generate_parameter_auth_bypass_mutations("https://target.com/ws")
        assert len(probes) >= 4
        assert all(p[0] == WebSocketMutationStrategy.PARAMETER_AUTHENTICATION_BYPASS for p in probes)
        urls = [p[1] for p in probes]
        assert any("token=" in u for u in urls)
        assert any("token=null" in u for u in urls)

    def test_frame_injection_payload_generators(self):
        sqli = WebSocketPayloadGenerator.generate_frame_sqli_payloads()
        assert len(sqli) >= 3
        assert any("1' OR '1'='1" in str(p) for p in sqli)

        cmdi = WebSocketPayloadGenerator.generate_frame_cmdi_payloads()
        assert len(cmdi) >= 3
        assert any("; id" in str(p) or "whoami" in str(p) for p in cmdi)

        xss = WebSocketPayloadGenerator.generate_frame_xss_payloads()
        assert len(xss) >= 3
        assert any("<script>" in str(p) or "onerror=" in str(p) for p in xss)

        proto = WebSocketPayloadGenerator.generate_frame_prototype_pollution_payloads()
        assert len(proto) >= 2
        assert any("__proto__" in str(p) for p in proto)

    def test_protocol_abuse_payload_generators(self):
        unmasked = WebSocketPayloadGenerator.generate_unmasked_frame_payload("TEST")
        assert isinstance(unmasked, bytes)
        assert unmasked[0] == 0x81  # Text frame FIN=1
        assert (unmasked[1] & 0x80) == 0  # Unmasked bit is 0

        oversized = WebSocketPayloadGenerator.generate_oversized_frame_header()
        assert isinstance(oversized, bytes)
        assert len(oversized) >= 2

        pings = WebSocketPayloadGenerator.generate_ping_flood_frames(count=10)
        assert len(pings) == 10
        assert all(p[0] == 0x89 for p in pings)  # Ping opcode 0x9


# ============================================================================
# Suite 3: Security Analyzer Detection Logic
# ============================================================================

class TestWebSocketSecurityAnalyzer:
    def test_verify_sec_websocket_accept(self):
        key = "dGhlIHNhbXBsZSBub25jZQ=="
        valid_accept = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        invalid_accept = "invalid_hash_value=="

        assert WebSocketSecurityAnalyzer.verify_sec_websocket_accept(key, valid_accept) is True
        assert WebSocketSecurityAnalyzer.verify_sec_websocket_accept(key, invalid_accept) is False
        assert WebSocketSecurityAnalyzer.verify_sec_websocket_accept("", valid_accept) is False
        assert WebSocketSecurityAnalyzer.verify_sec_websocket_accept(key, None) is False

    def test_is_hardened_rejection(self):
        assert WebSocketSecurityAnalyzer.is_hardened_rejection(403) is True
        assert WebSocketSecurityAnalyzer.is_hardened_rejection(401) is True
        assert WebSocketSecurityAnalyzer.is_hardened_rejection(426) is True
        assert WebSocketSecurityAnalyzer.is_hardened_rejection(200, "Origin not allowed") is True
        assert WebSocketSecurityAnalyzer.is_hardened_rejection(101, "") is False

    def test_analyze_cswsh_vulnerable_vs_hardened(self):
        key = WebSocketPayloadGenerator.generate_sec_websocket_key()
        accept = WebSocketPayloadGenerator.compute_sec_websocket_accept(key)

        # 1. Vulnerable response: 101 with matching accept
        vuln_resp = HttpResponse(
            success=True,
            status_code=101,
            body="",
            headers={"sec-websocket-accept": accept, "upgrade": "websocket"},
            url="https://target.com/ws",
        )
        res = WebSocketSecurityAnalyzer.analyze_cswsh(
            "https://target.com/ws",
            WebSocketMutationStrategy.ORIGIN_MANIPULATION,
            "https://evil.com",
            key,
            vuln_resp,
        )
        assert res is not None
        assert res.technique == WebSocketTechnique.CSWSH.value
        assert res.severity == "high"
        assert res.cwe_id == "CWE-1385"
        assert res.cvss_score == 8.8

        # 2. Hardened response: 403 Forbidden
        hardened_resp = HttpResponse(
            success=False,
            status_code=403,
            body="Forbidden Origin",
            headers={},
            url="https://target.com/ws",
        )
        res_sec = WebSocketSecurityAnalyzer.analyze_cswsh(
            "https://target.com/ws",
            WebSocketMutationStrategy.ORIGIN_MANIPULATION,
            "https://evil.com",
            key,
            hardened_resp,
        )
        assert res_sec is None

    def test_analyze_unauthenticated_handshake(self):
        key = WebSocketPayloadGenerator.generate_sec_websocket_key()
        accept = WebSocketPayloadGenerator.compute_sec_websocket_accept(key)

        vuln_resp = HttpResponse(
            success=True,
            status_code=101,
            body="",
            headers={"sec-websocket-accept": accept},
            url="https://target.com/api/v1/ws",
        )
        res = WebSocketSecurityAnalyzer.analyze_unauthenticated_handshake(
            "https://target.com/api/v1/ws", key, vuln_resp
        )
        assert res is not None
        assert res.technique == WebSocketTechnique.BROKEN_AUTHENTICATION.value
        assert res.severity == "high"
        assert res.cwe_id == "CWE-287"

        # Secure endpoint returns 401
        secure_resp = HttpResponse(
            success=False,
            status_code=401,
            body="Unauthorized",
            headers={},
            url="https://target.com/api/v1/ws",
        )
        res_sec = WebSocketSecurityAnalyzer.analyze_unauthenticated_handshake(
            "https://target.com/api/v1/ws", key, secure_resp
        )
        assert res_sec is None

    def test_analyze_query_token_leakage(self):
        vuln_url = "https://target.com/ws?token=secret_jwt_token_12345"
        resp = HttpResponse(
            success=True,
            status_code=101,
            body="",
            headers={},
            url=vuln_url,
        )
        res = WebSocketSecurityAnalyzer.analyze_query_token_leakage(vuln_url, resp)
        assert res is not None
        assert res.technique == WebSocketTechnique.TOKEN_IN_QUERY_PARAM.value
        assert res.severity == "medium"
        assert res.parameter == "token"
        assert "REDACTED" in res.payload

        clean_url = "https://target.com/ws"
        assert WebSocketSecurityAnalyzer.analyze_query_token_leakage(clean_url, resp) is None

    def test_analyze_frame_response_injection_techniques(self):
        url = "https://target.com/ws"

        # 1. SQL Injection
        sqli_body = '{"error": "syntax error at or near \\"admin\\": pg_query() failed"}'
        res_sqli = WebSocketSecurityAnalyzer.analyze_frame_response(
            url, WebSocketTechnique.INJECTION_SQLI, "1' OR '1'='1", sqli_body
        )
        assert res_sqli is not None
        assert res_sqli.technique == WebSocketTechnique.INJECTION_SQLI.value
        assert res_sqli.severity == "critical"
        assert res_sqli.cwe_id == "CWE-89"

        # 2. Command Injection
        cmdi_body = '{"output": "uid=0(root) gid=0(root) groups=0(root)"}'
        res_cmdi = WebSocketSecurityAnalyzer.analyze_frame_response(
            url, WebSocketTechnique.INJECTION_CMDI, "; id", cmdi_body
        )
        assert res_cmdi is not None
        assert res_cmdi.technique == WebSocketTechnique.INJECTION_CMDI.value
        assert res_cmdi.severity == "critical"
        assert res_cmdi.cwe_id == "CWE-78"

        # 3. XSS
        xss_body = '{"message": "<script>alert(\'ARGUS_WS_XSS\')</script>"}'
        res_xss = WebSocketSecurityAnalyzer.analyze_frame_response(
            url, WebSocketTechnique.INJECTION_XSS, "<script>alert('ARGUS_WS_XSS')</script>", xss_body
        )
        assert res_xss is not None
        assert res_xss.technique == WebSocketTechnique.INJECTION_XSS.value
        assert res_xss.cwe_id == "CWE-79"

        # 4. Prototype Pollution
        proto_body = '{"polluted": true, "user": "test"}'
        res_proto = WebSocketSecurityAnalyzer.analyze_frame_response(
            url, WebSocketTechnique.PROTOTYPE_POLLUTION, '{"__proto__": {"polluted": true}}', proto_body
        )
        assert res_proto is not None
        assert res_proto.technique == WebSocketTechnique.PROTOTYPE_POLLUTION.value
        assert res_proto.cwe_id == "CWE-1321"

    def test_analyze_protocol_abuse(self):
        url = "https://target.com/ws"

        # 1. Unmasked frame accepted without 1002
        res_unmasked = WebSocketSecurityAnalyzer.analyze_protocol_abuse(
            url, WebSocketTechnique.UNMASKED_FRAME_DOS, accepted_unmasked=True
        )
        assert res_unmasked is not None
        assert res_unmasked.technique == WebSocketTechnique.UNMASKED_FRAME_DOS.value
        assert res_unmasked.severity == "medium"

        # Clean rejection with close code 1002 suppresses finding
        res_unmasked_clean = WebSocketSecurityAnalyzer.analyze_protocol_abuse(
            url, WebSocketTechnique.UNMASKED_FRAME_DOS, close_code=1002, accepted_unmasked=True
        )
        assert res_unmasked_clean is None

        # 2. Oversized frame server crash
        res_oversized = WebSocketSecurityAnalyzer.analyze_protocol_abuse(
            url, WebSocketTechnique.OVERSIZED_FRAME_DOS, server_crashed=True, status_code=500
        )
        assert res_oversized is not None
        assert res_oversized.technique == WebSocketTechnique.OVERSIZED_FRAME_DOS.value

        # Clean 1009 suppresses
        res_oversized_clean = WebSocketSecurityAnalyzer.analyze_protocol_abuse(
            url, WebSocketTechnique.OVERSIZED_FRAME_DOS, close_code=1009
        )
        assert res_oversized_clean is None

        # 3. Rate limit flood
        res_flood = WebSocketSecurityAnalyzer.analyze_protocol_abuse(
            url, WebSocketTechnique.RATE_LIMIT_FLOOD, flood_processed=60, flood_limit=50
        )
        assert res_flood is not None
        assert res_flood.technique == WebSocketTechnique.RATE_LIMIT_FLOOD.value


# ============================================================================
# Suite 4: False Positive Suppression
# ============================================================================

class TestWebSocketFalsePositiveSuppression:
    def test_hardened_origin_rejection_produces_no_evidence(self):
        def strict_validator(target_url: str, origin: str) -> bool:
            parsed = urllib.parse.urlparse(target_url)
            return origin == f"{parsed.scheme}://{parsed.netloc}"

        client = MockWebSocketHttpClient(origin_validator=strict_validator)
        collector = WebSocketSecurityCollector(http_client=client)

        mission = Mission(target="target.com")
        mission.endpoints = ["https://target.com/ws"]

        evidences = collector.collect(mission)
        # Should not produce CSWSH findings for rejected origin
        cswsh_evs = [e for e in evidences if e.metadata.get("technique") == "cswsh"]
        assert len(cswsh_evs) == 0

    def test_invalid_accept_header_suppresses_cswsh(self):
        key = WebSocketPayloadGenerator.generate_sec_websocket_key()
        fake_accept = "bogus_accept_hash_12345"

        resp = HttpResponse(
            success=True,
            status_code=101,
            body="",
            headers={"sec-websocket-accept": fake_accept},
            url="https://target.com/ws",
        )
        res = WebSocketSecurityAnalyzer.analyze_cswsh(
            "https://target.com/ws",
            WebSocketMutationStrategy.ORIGIN_MANIPULATION,
            "https://evil.com",
            key,
            resp,
        )
        assert res is None

    def test_clean_close_codes_suppress_injection(self):
        url = "https://target.com/ws"
        # Server closes connection with 1008 Policy Violation
        res = WebSocketSecurityAnalyzer.analyze_frame_response(
            url, WebSocketTechnique.INJECTION_SQLI, "' OR '1'='1", "", close_code=1008
        )
        assert res is None

    def test_benign_json_errors_do_not_trigger_sqli(self):
        url = "https://target.com/ws"
        benign_error = '{"error": "SyntaxError: Unexpected token in JSON at position 12"}'
        res = WebSocketSecurityAnalyzer.analyze_frame_response(
            url, WebSocketTechnique.INJECTION_SQLI, "{bad_json", benign_error
        )
        assert res is None


# ============================================================================
# Suite 5: Collector Execution & Quadruple State Updates
# ============================================================================

class TestWebSocketCollectorExecution:
    def test_candidate_discovery(self):
        collector = WebSocketSecurityCollector()
        mission = Mission(target="example.com")
        mission.endpoints = ["https://example.com/api/v1/ws", "wss://stream.example.com/live"]
        mission.live_hosts = ["https://example.com"]

        candidates = collector._discover_candidate_endpoints(mission)
        assert len(candidates) >= 20
        assert "https://example.com/api/v1/ws" in candidates
        assert "wss://stream.example.com/live" in candidates
        assert "https://example.com/socket.io/" in candidates
        assert "https://example.com/cable" in candidates

    def test_collector_execution_quadruple_state_updates(self):
        # Setup vulnerable mock client that accepts all handshakes and origins
        client = MockWebSocketHttpClient(default_status=101, accept_valid_keys=True)
        collector = WebSocketSecurityCollector(http_client=client)

        mission = Mission(target="vuln-ws.example.com")
        mission.endpoints = ["https://vuln-ws.example.com/ws"]
        mission.evidence = EvidenceStore()
        mission.vulnerabilities = []
        mission.attack_surface_graph = KnowledgeGraph()

        evidences = collector.collect(mission)
        assert len(evidences) >= 1

        # 1. Verify mission.evidence.add()
        ev_items = mission.evidence.all()
        assert len(ev_items) >= 1
        assert ev_items[0].category == "websocket_security"

        # 2. Verify mission.vulnerabilities.append()
        assert len(mission.vulnerabilities) >= 1
        assert "websocket" in mission.vulnerabilities[0]["template_id"].lower()

        # 3. Verify attack_surface_graph Node and Edge expansion
        graph = mission.attack_surface_graph
        ep_nodes = graph.nodes_by_type("endpoint")
        assert len(ep_nodes) >= 1

        vuln_nodes = graph.nodes_by_type("vulnerability")
        assert len(vuln_nodes) >= 1

        # Verify HAS_ENDPOINT and HAS_VULNERABILITY edges
        has_ep_edges = [e for e in graph.edges if e.type == "HAS_ENDPOINT"]
        has_vuln_edges = [e for e in graph.edges if e.type == "HAS_VULNERABILITY"]
        assert len(has_ep_edges) >= 1
        assert len(has_vuln_edges) >= 2

    def test_controlled_mission_publish_finding(self):
        client = MockWebSocketHttpClient(default_status=101)
        collector = WebSocketSecurityCollector(http_client=client)

        base_mission = Mission(target="test.com")
        base_mission.endpoints = ["https://test.com/ws"]
        base_mission.evidence = EvidenceStore()
        base_mission.vulnerabilities = []
        base_mission.attack_surface_graph = KnowledgeGraph()

        published_findings = {}

        class DummyControlledMission(ControlledMission):
            def publish_finding(self, fid: str, finding: Any):
                published_findings[fid] = finding

        controlled = DummyControlledMission(base_mission)
        evidences = collector.collect(controlled)
        assert len(evidences) >= 1
        assert len(published_findings) >= 1

    def test_execute_method_alias(self):
        client = MockWebSocketHttpClient(default_status=101)
        collector = WebSocketSecurityCollector(http_client=client)
        mission = Mission(target="alias.com")
        mission.endpoints = ["https://alias.com/ws"]

        res = collector.execute(mission)
        assert isinstance(res, list)
        assert len(res) >= 1


# ============================================================================
# Suite 6: Pipeline, Registry, DAG & Reporting Integration
# ============================================================================

class TestWebSocketPipelineAndIntegration:
    def test_registry_lookup_by_id_and_aliases(self):
        tool = registry.get("websocket_security")
        assert tool is not None
        assert tool.id == "websocket_security"
        assert tool.capability == "websocket_security_detector"

        # Check key aliases
        aliases = [
            "websocket",
            "cswsh",
            "websocket_collector",
            "ws_security",
            "ws_collector",
            "cswsh_collector",
            "cswsh_detector",
            "websocket_detector",
            "websocket_injection",
            "websocket_dos",
            "websocket_auth",
            "ws",
            "wss",
        ]
        for alias in aliases:
            resolved = registry.get(alias)
            assert resolved is not None, f"Failed to resolve alias '{alias}'"
            assert resolved.id == "websocket_security"

    def test_plugin_executor_adapter_fallback(self):
        adapter = PluginExecutorAdapter()
        inst = adapter._instantiate_specialist_fallback("websocket_security")
        assert inst is not None
        assert isinstance(inst, WebSocketSecurityCollector)

        inst_cswsh = adapter._instantiate_specialist_fallback("cswsh_collector")
        assert inst_cswsh is not None
        assert isinstance(inst_cswsh, WebSocketSecurityCollector)

    def test_task_generator_dag_template(self):
        assert "websocket_security" in _RECON_TEMPLATES
        tmpl = _RECON_TEMPLATES["websocket_security"]
        assert tmpl["title"] == "Validate WebSocket Security"
        assert "Discover API Endpoints" in tmpl["dependencies"]
        assert tmpl["metadata"]["tool_id"] == "websocket_security"
        assert tmpl["category"] == TaskCategory.EVIDENCE_CORRELATION

    def test_task_generator_gap_resolution(self):
        mission = Mission(target="example.com")
        mission.endpoints = ["https://example.com/ws"]
        tg = TaskGenerator(mission)

        # 1. Explicit area resolution
        gap = CoverageGap(
            area="websocket security",
            description="WebSocket endpoints require security validation",
            severity=0.8,
            category=TaskCategory.EVIDENCE_CORRELATION,
        )
        tasks = tg.from_gaps([gap])
        assert len(tasks) == 1
        assert tasks[0].title == "Validate WebSocket Security"
        assert tasks[0].metadata["tool_id"] == "websocket_security"
        assert "https://example.com/ws" in tasks[0].required_inputs

        # 2. Category keyword resolution
        gap2 = CoverageGap(
            area="custom",
            description="Check CSWSH and socket.io upgrade bypasses",
            severity=0.8,
            category=TaskCategory.EVIDENCE_CORRELATION,
        )
        tasks2 = tg.from_gaps([gap2])
        assert len(tasks2) == 1
        assert tasks2[0].title == "Validate WebSocket Security"

    def test_attack_surface_graph_builder_ingestion(self):
        ev = Evidence(
            category="websocket_security",
            value="cswsh:https://target.com/ws",
            source="websocket_security",
            severity="high",
            title="Cross-Site WebSocket Hijacking (CSWSH) Exposed: https://target.com/ws",
            description="Vulnerable to CSWSH",
            metadata={
                "url": "https://target.com/ws",
                "host": "https://target.com",
                "technique": "cswsh",
                "template_id": "websocket-security",
                "status_code": 101,
            },
        )

        builder = AttackSurfaceGraphBuilder()
        graph = builder.build_from_evidence([ev], target="target.com")

        ep_nodes = graph.nodes_by_type("endpoint")
        assert any(n.value == "https://target.com/ws" for n in ep_nodes)

        vuln_nodes = graph.nodes_by_type("vulnerability")
        assert len(vuln_nodes) >= 1

        has_vuln_edges = [e for e in graph.edges if e.type == "HAS_VULNERABILITY"]
        assert len(has_vuln_edges) >= 1

    def test_cvss_calculator_cwe_and_vector_presets(self):
        calc = CVSSCalculator()

        # CWE lookup
        cwe_ws = calc.get_cwe_for_category("websocket_security")
        assert cwe_ws.id == "CWE-1385"

        cwe_cswsh = calc.get_cwe_for_category("cswsh")
        assert cwe_cswsh.id == "CWE-1385"

        cwe_auth = calc.get_cwe_for_category("websocket_auth")
        assert cwe_auth.id == "CWE-306"

        cwe_dos = calc.get_cwe_for_category("websocket_dos")
        assert cwe_dos.id == "CWE-400"

        cwe_rate = calc.get_cwe_for_category("websocket_rate_limit")
        assert cwe_rate.id == "CWE-799"

        # Preset vectors
        vec_high = calc._get_preset_vector("websocket_security", ReportSeverity.HIGH)
        assert "AV:N" in vec_high
        score_high = calc.calculate_base_score(vec_high)
        assert 7.0 <= score_high <= 8.9
