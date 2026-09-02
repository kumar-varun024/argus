"""
Comprehensive Unit and Functional Tests for HTTP Request Smuggling Detection Module in ARGUS:
- RequestSmugglingPayloadGenerator
- RawHttpStreamProber & RawHttpResponse
- RequestSmugglingSecurityAnalyzer
- HTTPRequestSmugglingCollector (and RequestSmugglingCollector alias)
- ToolRegistry registration and aliases
- PluginExecutorAdapter specialist fallback
- TaskGenerator DAG recon templates and gap resolution
- AttackSurfaceGraph node and edge expansion
- CVSS & CWE-444 classification and scoring
"""
from __future__ import annotations

import urllib.parse
from typing import Any, Dict, List, Optional, Tuple
import pytest

from argus.collectors.request_smuggling import (
    HTTPRequestSmugglingCollector,
    RequestSmugglingCollector,
    RequestSmugglingPayloadGenerator,
    RequestSmugglingSecurityAnalyzer,
    RawHttpStreamProber,
    RawHttpResponse,
    RequestSmugglingResult,
    RequestSmugglingSeverity,
    RequestSmugglingTechnique,
    RequestSmugglingMutationStrategy,
    HARDENED_DEFENSE_SIGNATURES,
    CANARY_DESYNC_SIGNATURES,
)
from argus.evidence.model import Evidence
from argus.evidence.store import EvidenceStore
from argus.graph.graph import KnowledgeGraph
from argus.graph.node import Node
from argus.graph.attack_surface import AttackSurfaceGraphBuilder
from argus.planning.models import CoverageGap, TaskCategory
from argus.planning.task_generator import TaskGenerator, _RECON_TEMPLATES
from argus.plugins.interfaces import ControlledMission
from argus.reporting.cvss import CVSSCalculator
from argus.reporting.models import ReportSeverity
from argus.runtime.mission import Mission
from argus.runtime.plugins import PluginExecutorAdapter
from argus.runtime.registry import registry


class MockRawTransport:
    """Mock transport adapter for simulating raw HTTP/1.1 and HTTP/2 backend behaviors."""

    def __init__(
        self,
        default_status: int = 200,
        routes: Optional[Dict[str, Tuple[int, str, Dict[str, str], float]]] = None,
        behavior_mode: str = "normal",  # normal, cl_te_desync, te_cl_desync, te_te_desync, hardened
    ):
        self.default_status = default_status
        self.routes = routes or {}
        self.behavior_mode = behavior_mode
        self.received_probes: List[Tuple[str, str]] = []
        self.socket_buffer: str = ""

    def adapter(self, target_url: str, raw_payload: Any, timeout: float = 5.0) -> RawHttpResponse:
        payload_str = raw_payload if isinstance(raw_payload, str) else raw_payload.decode("latin-1", errors="replace")
        self.received_probes.append((target_url, payload_str))

        # Check explicit routes
        for path_key, (st, body, hdrs, el) in self.routes.items():
            if path_key in payload_str or path_key in target_url:
                return RawHttpResponse(
                    status_code=st,
                    body=body,
                    headers=dict(hdrs),
                    elapsed=el,
                    url=target_url,
                )

        if self.behavior_mode == "hardened":
            return RawHttpResponse(
                status_code=400,
                body="400 Bad Request: Malformed HTTP request or illegal Transfer-Encoding header",
                headers={"content-type": "text/plain"},
                elapsed=0.05,
                url=target_url,
            )

        elif self.behavior_mode == "cl_te_timing":
            # If CL.TE timing probe with Content-Length: 4 and Transfer-Encoding: chunked
            if "Transfer-Encoding: chunked" in payload_str and "Content-Length: 4" in payload_str:
                return RawHttpResponse(
                    status_code=200,
                    body="Backend hung waiting for next chunk",
                    elapsed=5.1,
                    timed_out=True,
                    error="socket_timeout",
                    url=target_url,
                )
            return RawHttpResponse(status_code=200, body="OK", elapsed=0.05, url=target_url)

        elif self.behavior_mode == "te_cl_timing":
            if "Transfer-Encoding: chunked" in payload_str and "Content-Length: 6" in payload_str:
                return RawHttpResponse(
                    status_code=200,
                    body="Backend hung waiting for remaining content bytes",
                    elapsed=4.8,
                    url=target_url,
                )
            return RawHttpResponse(status_code=200, body="OK", elapsed=0.05, url=target_url)

        elif self.behavior_mode == "cl_te_pipeline":
            # If attack probe leaves canary in socket buffer
            if "Transfer-Encoding: chunked" in payload_str and "ARGUS_SMUGGLE_CANARY" in payload_str:
                self.socket_buffer = "canary_smuggled"
                return RawHttpResponse(status_code=200, body="Attack accepted", elapsed=0.05, url=target_url)
            elif self.socket_buffer == "canary_smuggled":
                self.socket_buffer = ""
                # Follow-up receives 404 with canary path reflection
                return RawHttpResponse(
                    status_code=404,
                    body="404 Not Found: Resource /argus_smuggled_canary does not exist",
                    headers={"x-canary-response": "ARGUS_SMUGGLE_CANARY"},
                    elapsed=0.05,
                    url=target_url,
                )
            return RawHttpResponse(status_code=200, body="OK", elapsed=0.05, url=target_url)

        elif self.behavior_mode == "te_te_pipeline":
            if any(h in payload_str for h in ("Transfer-encoding:\tchunked", "Transfer-Encoding : chunked", "Connection: Transfer-Encoding", "0;foo=bar")):
                self.socket_buffer = "canary_smuggled"
                return RawHttpResponse(status_code=200, body="Attack accepted", elapsed=0.05, url=target_url)
            elif self.socket_buffer == "canary_smuggled":
                self.socket_buffer = ""
                return RawHttpResponse(
                    status_code=404,
                    body="404 Not Found: /argus_smuggled_canary",
                    headers={"x-canary-reflected": "ARGUS_SMUGGLE_CANARY"},
                    elapsed=0.05,
                    url=target_url,
                )
            return RawHttpResponse(status_code=200, body="OK", elapsed=0.05, url=target_url)

        return RawHttpResponse(
            status_code=self.default_status,
            body="Default Response",
            headers={"content-type": "text/html"},
            elapsed=0.05,
            url=target_url,
        )


# ============================================================================
# Unit Tests: Payload Generator
# ============================================================================

def test_build_baseline_probe():
    probe = RequestSmugglingPayloadGenerator.build_baseline_probe("example.com", "/test")
    assert "GET /test HTTP/1.1\r\n" in probe
    assert "Host: example.com\r\n" in probe
    assert probe.endswith("\r\n\r\n")


def test_build_cl_te_timing_probe():
    probe = RequestSmugglingPayloadGenerator.build_cl_te_timing_probe("target.local", "/api")
    assert "POST /api HTTP/1.1\r\n" in probe
    assert "Host: target.local\r\n" in probe
    assert "Content-Length: 4\r\n" in probe
    assert "Transfer-Encoding: chunked\r\n" in probe
    assert "1\r\nZ\r\nQ\r\n" in probe


def test_build_te_cl_timing_probe():
    probe = RequestSmugglingPayloadGenerator.build_te_cl_timing_probe("target.local", "/login")
    assert "POST /login HTTP/1.1\r\n" in probe
    assert "Content-Length: 6\r\n" in probe
    assert "Transfer-Encoding: chunked\r\n" in probe
    assert "0\r\n\r\nX" in probe


def test_build_cl_te_pipeline_probe():
    attack, follow_up = RequestSmugglingPayloadGenerator.build_cl_te_pipeline_probe(
        "target.local", "/submit", canary_path="/custom_canary", canary_header="CUSTOM_CANARY_MARKER"
    )
    assert "POST /submit HTTP/1.1\r\n" in attack
    assert "Transfer-Encoding: chunked\r\n" in attack
    assert "GET /custom_canary HTTP/1.1\r\n" in attack
    assert "X-Canary: CUSTOM_CANARY_MARKER\r\n" in attack
    assert "POST /submit HTTP/1.1\r\n" in follow_up
    assert "x=123" in follow_up


def test_build_te_cl_pipeline_probe():
    attack, follow_up = RequestSmugglingPayloadGenerator.build_te_cl_pipeline_probe(
        "target.local", "/search", canary_path="/canary_te_cl", canary_header="TE_CL_CANARY"
    )
    assert "POST /search HTTP/1.1\r\n" in attack
    assert "Content-Length: 4\r\n" in attack
    assert "Transfer-Encoding: chunked\r\n" in attack
    assert "GET /canary_te_cl HTTP/1.1\r\n" in attack
    assert "GET /search HTTP/1.1\r\n" in follow_up


def test_generate_te_te_mutations_coverage():
    mutations = RequestSmugglingPayloadGenerator.generate_te_te_mutations("example.org", "/")
    assert len(mutations) >= 6
    strategies = {m[0] for m in mutations}
    assert RequestSmugglingMutationStrategy.HEADER_CASING_WHITESPACE in strategies
    assert RequestSmugglingMutationStrategy.DUAL_HEADER in strategies
    assert RequestSmugglingMutationStrategy.HOP_BY_HOP in strategies
    assert RequestSmugglingMutationStrategy.CHUNK_EXTENSION in strategies
    assert RequestSmugglingMutationStrategy.HEX_MUTATION in strategies
    assert RequestSmugglingMutationStrategy.COMMA_DELIMITED in strategies


def test_generate_h2_downgrade_probes():
    h2_probes = RequestSmugglingPayloadGenerator.generate_h2_downgrade_probes("h2.target.org", "/h2")
    assert len(h2_probes) >= 4
    techs = {p[0] for p in h2_probes}
    assert RequestSmugglingTechnique.H2_CL in techs
    assert RequestSmugglingTechnique.H2_TE in techs
    assert RequestSmugglingTechnique.H2_CRLF in techs


# ============================================================================
# Unit Tests: Raw HTTP Stream Prober & Response Parser
# ============================================================================

def test_raw_http_response_parser_standard():
    raw_bytes = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/html\r\n"
        b"Server: nginx/1.18.0\r\n"
        b"\r\n"
        b"<h1>Hello World</h1>"
    )
    resp = RawHttpStreamProber._parse_raw_http_response(raw_bytes, 0.04, "http://localhost/")
    assert resp.status_code == 200
    assert resp.protocol == "HTTP/1.1"
    assert resp.headers.get("server") == "nginx/1.18.0"
    assert resp.headers.get("content-type") == "text/html"
    assert resp.body == "<h1>Hello World</h1>"
    assert resp.elapsed == 0.04


def test_raw_http_response_parser_empty():
    resp = RawHttpStreamProber._parse_raw_http_response(b"", 0.01, "http://localhost/")
    assert resp.status_code == 0
    assert resp.error == "empty_response"


def test_raw_http_stream_prober_with_custom_adapter():
    mock = MockRawTransport(default_status=200)
    prober = RawHttpStreamProber(transport_adapter=mock.adapter)
    resp = prober.send_raw_probe("http://example.com/test", "GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n")
    assert resp.status_code == 200
    assert len(mock.received_probes) == 1


def test_send_pipeline_sequence():
    mock = MockRawTransport(behavior_mode="cl_te_pipeline")
    prober = RawHttpStreamProber(transport_adapter=mock.adapter)
    atk_p, fol_p = RequestSmugglingPayloadGenerator.build_cl_te_pipeline_probe("example.com", "/")
    r1, r2 = prober.send_pipeline_sequence("http://example.com/", atk_p, fol_p, inter_request_delay=0)
    assert r1.status_code == 200
    assert r2.status_code == 404
    assert "ARGUS_SMUGGLE_CANARY" in r2.headers.get("x-canary-response", "")


# ============================================================================
# Unit Tests: Security Analyzer
# ============================================================================

def test_is_hardened_rejection():
    assert RequestSmugglingSecurityAnalyzer.is_hardened_rejection(400, "Bad Request") is True
    assert RequestSmugglingSecurityAnalyzer.is_hardened_rejection(501, "Not Implemented") is True
    assert RequestSmugglingSecurityAnalyzer.is_hardened_rejection(200, "Transfer-Encoding not supported") is True
    assert RequestSmugglingSecurityAnalyzer.is_hardened_rejection(200, "Normal response body") is False


def test_analyze_timing_response_positive():
    res = RequestSmugglingSecurityAnalyzer.analyze_timing_response(
        endpoint_url="http://target.com/api",
        technique=RequestSmugglingTechnique.CL_TE.value,
        strategy=RequestSmugglingMutationStrategy.STANDARD.value,
        baseline_elapsed=0.10,
        injected_elapsed=4.50,
        threshold=3.0,
        status_code=200,
    )
    assert res is not None
    assert res.technique == RequestSmugglingTechnique.CL_TE.value
    assert res.delay_delta >= 4.0
    assert res.cvss_score >= 9.0
    assert res.cwe_id == "CWE-444"


def test_analyze_timing_response_suppression_on_hardened_or_fast():
    # Below threshold
    res_fast = RequestSmugglingSecurityAnalyzer.analyze_timing_response(
        endpoint_url="http://target.com/api",
        technique=RequestSmugglingTechnique.CL_TE.value,
        strategy=RequestSmugglingMutationStrategy.STANDARD.value,
        baseline_elapsed=0.10,
        injected_elapsed=0.20,
        threshold=3.0,
    )
    assert res_fast is None

    # Hardened 400 rejection
    res_hardened = RequestSmugglingSecurityAnalyzer.analyze_timing_response(
        endpoint_url="http://target.com/api",
        technique=RequestSmugglingTechnique.CL_TE.value,
        strategy=RequestSmugglingMutationStrategy.STANDARD.value,
        baseline_elapsed=0.10,
        injected_elapsed=5.0,
        status_code=400,
    )
    assert res_hardened is None


def test_analyze_pipeline_response_canary_reflection():
    attack_resp = RawHttpResponse(status_code=200, body="Accepted", elapsed=0.05)
    follow_up_resp = RawHttpResponse(
        status_code=200,
        body="Welcome user ARGUS_SMUGGLE_CANARY reflected!",
        headers={"content-type": "text/html"},
        elapsed=0.05,
    )
    res = RequestSmugglingSecurityAnalyzer.analyze_pipeline_response(
        endpoint_url="http://target.com/submit",
        technique=RequestSmugglingTechnique.CL_TE.value,
        strategy=RequestSmugglingMutationStrategy.STANDARD.value,
        attack_resp=attack_resp,
        follow_up_resp=follow_up_resp,
        canary_marker="ARGUS_SMUGGLE_CANARY",
    )
    assert res is not None
    assert res.matched_signature == "canary_reflection"
    assert res.cvss_score == 9.8


def test_analyze_pipeline_response_status_inversion():
    attack_resp = RawHttpResponse(status_code=200, body="Accepted", elapsed=0.05)
    follow_up_resp = RawHttpResponse(status_code=404, body="Resource not found", elapsed=0.05)
    res = RequestSmugglingSecurityAnalyzer.analyze_pipeline_response(
        endpoint_url="http://target.com/submit",
        technique=RequestSmugglingTechnique.TE_CL.value,
        strategy=RequestSmugglingMutationStrategy.STANDARD.value,
        attack_resp=attack_resp,
        follow_up_resp=follow_up_resp,
        baseline_status=200,
    )
    assert res is not None
    assert res.matched_signature == "pipeline_status_inversion"
    assert res.follow_up_status == 404


def test_analyze_h2_downgrade_response():
    resp = RawHttpResponse(
        status_code=200,
        body="HTTP/2 Downgrade reflected ARGUS_SMUGGLE_CANARY in stream",
        elapsed=0.05,
    )
    res = RequestSmugglingSecurityAnalyzer.analyze_h2_downgrade_response(
        endpoint_url="https://target.com/h2",
        technique=RequestSmugglingTechnique.H2_CRLF.value,
        strategy=RequestSmugglingMutationStrategy.H2_PSEUDO_HEADER.value,
        response=resp,
        canary_marker="ARGUS_SMUGGLE_CANARY",
    )
    assert res is not None
    assert res.technique == RequestSmugglingTechnique.H2_CRLF.value
    assert res.cvss_score == 9.8


# ============================================================================
# Integration Tests: HTTPRequestSmugglingCollector
# ============================================================================

def test_collector_endpoint_discovery():
    mission = Mission(
        id="smuggle_mission_1",
        target="http://smuggle-target.local",
        endpoints=["http://smuggle-target.local/api/v1/users", "http://smuggle-target.local/search"],
        live_hosts=["http://smuggle-target.local"],
    )
    collector = HTTPRequestSmugglingCollector()
    candidates = collector._discover_candidate_endpoints(mission)
    assert "http://smuggle-target.local/api/v1/users" in candidates
    assert "http://smuggle-target.local/search" in candidates
    assert "http://smuggle-target.local/" in candidates


def test_collector_cl_te_pipeline_detection_and_quadruple_publishing():
    mission = Mission(
        id="smuggle_mission_cl_te",
        target="http://vuln-cl-te.local",
        endpoints=["http://vuln-cl-te.local/submit"],
        live_hosts=["http://vuln-cl-te.local"],
    )
    mock_transport = MockRawTransport(behavior_mode="cl_te_pipeline")
    prober = RawHttpStreamProber(transport_adapter=mock_transport.adapter)
    collector = HTTPRequestSmugglingCollector(prober=prober)

    evidences = collector.collect(mission)
    assert len(evidences) >= 1
    ev = evidences[0]
    assert ev.category == "request_smuggling"
    assert ev.status == "CONFIRMED"
    assert "HTTP Request Smuggling" in ev.title
    assert "CWE-444" in ev.description

    # Verify mission.vulnerabilities updated
    assert len(mission.vulnerabilities) >= 1
    vuln = mission.vulnerabilities[0]
    assert vuln["cwe_id"] == "CWE-444"
    assert vuln["cvss_score"] >= 9.0

    # Verify attack_surface_graph updated
    graph = mission.attack_surface_graph
    assert graph is not None
    vuln_nodes = graph.nodes_by_type("vulnerability")
    assert len(vuln_nodes) >= 1
    has_vuln_edges = [e for e in graph.edges if e.type == "HAS_VULNERABILITY"]
    assert len(has_vuln_edges) >= 1


def test_collector_te_te_obfuscation_detection():
    mission = Mission(
        id="smuggle_mission_te_te",
        target="http://vuln-te-te.local",
        endpoints=["http://vuln-te-te.local/api"],
        live_hosts=["http://vuln-te-te.local"],
    )
    mock_transport = MockRawTransport(behavior_mode="te_te_pipeline")
    prober = RawHttpStreamProber(transport_adapter=mock_transport.adapter)
    collector = RequestSmugglingCollector(prober=prober)  # Using alias

    evidences = collector.collect(mission)
    assert len(evidences) >= 1
    assert any("TE.TE" in ev.title or "te_te" in ev.tags for ev in evidences)


def test_collector_hardened_false_positive_rejection():
    mission = Mission(
        id="smuggle_mission_hardened",
        target="http://hardened.local",
        endpoints=["http://hardened.local/"],
        live_hosts=["http://hardened.local"],
    )
    mock_transport = MockRawTransport(behavior_mode="hardened")
    prober = RawHttpStreamProber(transport_adapter=mock_transport.adapter)
    collector = HTTPRequestSmugglingCollector(prober=prober)

    evidences = collector.collect(mission)
    assert len(evidences) == 0
    assert len(mission.vulnerabilities) == 0


def test_collector_execute_alias():
    mission = Mission(
        id="smuggle_mission_exec",
        target="http://target.local",
        endpoints=["http://target.local/"],
    )
    mock_transport = MockRawTransport(behavior_mode="cl_te_pipeline")
    prober = RawHttpStreamProber(transport_adapter=mock_transport.adapter)
    collector = HTTPRequestSmugglingCollector(prober=prober)

    evidences = collector.execute(mission)
    assert len(evidences) >= 1


# ============================================================================
# Pipeline Connectivity Tests
# ============================================================================

def test_tool_registry_registration_and_aliases():
    # Direct ID lookup
    tool = registry.get("request_smuggling")
    assert tool is not None
    assert tool.id == "request_smuggling"
    assert tool.capability == "request_smuggling_detector"
    assert tool.priority == 95

    # Alias lookups
    for alias in [
        "http_request_smuggling",
        "request_smuggling_collector",
        "request_smuggling_detector",
        "cl_te",
        "te_cl",
        "te_te",
        "h2_smuggling",
        "http2_smuggling",
        "h2_cl",
        "h2_te",
        "h2_crlf",
        "smuggling",
        "http_smuggling",
        "http_desync",
        "desync",
    ]:
        resolved = registry.get(alias)
        assert resolved is not None, f"Failed resolving alias {alias}"
        assert resolved.id == "request_smuggling"


def test_plugin_executor_adapter_fallback():
    adapter = PluginExecutorAdapter()
    for pid in [
        "request_smuggling",
        "http_request_smuggling",
        "cl_te",
        "te_cl",
        "te_te",
        "h2_cl",
        "h2_te",
        "http_desync",
        "smuggling",
    ]:
        instance = adapter._instantiate_specialist_fallback(pid)
        assert instance is not None, f"Failed instantiating fallback for {pid}"
        assert isinstance(instance, HTTPRequestSmugglingCollector)


def test_task_generator_dag_scheduling_and_gap_resolution():
    mission = Mission(
        id="dag_mission",
        target="http://example.com",
        endpoints=["http://example.com/api"],
    )
    gen = TaskGenerator(mission)

    # Check template existence
    assert "request_smuggling" in _RECON_TEMPLATES
    tmpl = _RECON_TEMPLATES["request_smuggling"]
    assert tmpl["dependencies"] == ["Discover API Endpoints"]

    # Check gap resolution for smuggling keywords
    for kw in ["request smuggling", "HTTP Request Smuggling", "CL.TE", "TE.CL", "TE.TE", "h2 smuggling", "http desync"]:
        gap = CoverageGap(area=kw, category=TaskCategory.EVIDENCE_CORRELATION, description=f"Audit {kw}")
        resolved = gen._resolve_template_for_gap(gap)
        assert resolved["metadata"]["tool_id"] == "request_smuggling"

    # Check from_gaps produces ResearchTask with correct inputs
    tasks = gen.from_gaps([
        CoverageGap(area="request smuggling", category=TaskCategory.EVIDENCE_CORRELATION, description="Audit CL.TE")
    ])
    assert len(tasks) == 1
    assert tasks[0].metadata["tool_id"] == "request_smuggling"
    assert "http://example.com/api" in tasks[0].required_inputs


def test_attack_surface_graph_builder_integration():
    builder = AttackSurfaceGraphBuilder()
    store = EvidenceStore()
    ev = Evidence(
        category="request_smuggling",
        value="cl_te:http://example.com/api/users",
        source="request_smuggling",
        status="CONFIRMED",
        severity="critical",
        title="HTTP Request Smuggling (CL.TE): http://example.com/api/users",
        metadata={
            "url": "http://example.com/api/users",
            "host": "http://example.com",
            "technique": "cl_te",
            "template_id": "request-smuggling",
            "status_code": 404,
        },
    )
    store.add(ev)

    graph = builder.build_from_evidence(store, target="example.com")
    assert graph is not None

    # Check nodes
    lh_node = graph.get("live_host:http://example.com")
    ep_node = graph.get("endpoint:http://example.com/api/users")
    assert lh_node is not None
    assert ep_node is not None

    vuln_nodes = graph.nodes_by_type("vulnerability")
    assert len(vuln_nodes) >= 1

    # Check edges
    edges = graph.edges
    assert any(e.source == lh_node.id and e.target == ep_node.id and e.type == "HAS_ENDPOINT" for e in edges)
    assert any(e.source == lh_node.id and e.type == "HAS_VULNERABILITY" for e in edges)
    assert any(e.source == ep_node.id and e.type == "HAS_VULNERABILITY" for e in edges)


def test_cvss_and_cwe_mapping():
    # CWE lookup
    for cat in ["request_smuggling", "http_request_smuggling", "cl_te", "te_cl", "te_te", "h2_smuggling", "http_desync"]:
        cwe_info = CVSSCalculator.get_cwe_for_category(cat)
        assert cwe_info is not None
        assert cwe_info.id == "CWE-444"

    # CVSS preset scoring for Critical and High
    cvss_crit = CVSSCalculator.get_approximate_cvss("request_smuggling", severity="critical")
    assert cvss_crit.score == 9.8
    assert cvss_crit.severity_rating == "Critical"

    cvss_high = CVSSCalculator.get_approximate_cvss("request_smuggling", severity="high")
    assert cvss_high.score == 8.2
    assert cvss_high.severity_rating == "High"
