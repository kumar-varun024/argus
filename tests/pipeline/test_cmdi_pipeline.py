"""
Pipeline Integration tests for Command Injection (CMDi) Engine:
ToolRegistry, PluginExecutorAdapter, TaskGenerator DAG, AttackSurfaceGraphBuilder, and Mission Loop.
"""
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple
import pytest

from argus.collectors.command_injection import (
    CommandInjectionCollector,
    CommandInjectionAnalyzer,
    CommandInjectionPayloadGenerator,
)
from argus.evidence.model import Evidence, ProvenanceData
from argus.evidence.store import EvidenceStore
from argus.graph.attack_surface import AttackSurfaceGraphBuilder
from argus.graph.graph import KnowledgeGraph
from argus.graph.node import Node
from argus.http.client import HttpResponse
from argus.planning.models import CoverageGap, TaskCategory
from argus.planning.task_generator import TaskGenerator, _RECON_TEMPLATES
from argus.plugins.interfaces import ControlledMission
from argus.runtime.mission import Mission
from argus.runtime.plugins import PluginExecutorAdapter
from argus.runtime.registry import registry


def _has_edge(graph: KnowledgeGraph, source: str, target: str, edge_type: str) -> bool:
    """Helper to check if a specific typed edge exists in the knowledge graph."""
    return any(e.source == source and e.target == target and e.type == edge_type for e in graph.edges)


class MockPipelineHttpClient:
    """Mock HTTP client for pipeline integration tests."""

    def __init__(self, routes: Optional[Dict[str, Tuple[int, str, float]]] = None):
        self.routes = dict(routes or {})

    def set_route(self, key: str, status_code: int, body: str, elapsed: float = 0.05):
        self.routes[key] = (status_code, body, elapsed)

    def get(self, mission_or_url: Any, url: Optional[str] = None, **kwargs) -> HttpResponse:
        target_url = url if url is not None else mission_or_url
        if not isinstance(target_url, str):
            target_url = str(target_url)

        unquoted_url = urllib.parse.unquote_plus(target_url)
        for reg_key, (status_code, body, elapsed) in self.routes.items():
            if reg_key in target_url or reg_key in unquoted_url:
                return HttpResponse(
                    success=(200 <= status_code < 300),
                    status_code=status_code,
                    raw_body=body,
                    body=body,
                    url=target_url,
                    elapsed=elapsed,
                )

        return HttpResponse(
            success=True,
            status_code=200,
            raw_body="OK Clean Response",
            body="OK Clean Response",
            url=target_url,
            elapsed=0.05,
        )

    def post(self, mission_or_url: Any, url: Optional[str] = None, **kwargs) -> HttpResponse:
        return self.get(mission_or_url, url=url, **kwargs)


def test_cmdi_tool_registry_registration_and_aliases():
    """Verifies that the command_injection tool is registered in ToolRegistry and alias lookups succeed."""
    tool = registry.get("command_injection")
    assert tool is not None
    assert tool.id == "command_injection"
    assert tool.name == "Command Injection Collector"
    assert "command_injection_detector" in tool.capabilities
    assert "command_injection_collector" in tool.capabilities
    assert "Command Injection Detection" in tool.supported_tasks
    assert "endpoints" in tool.required_inputs
    assert "vulnerabilities" in tool.produced_outputs
    assert tool.priority >= 90

    # Alias lookups
    for alias in ["cmdi", "cmd_injection", "command_injection_collector", "os_command_injection", "rce"]:
        aliased_tool = registry.get(alias)
        assert aliased_tool is not None
        assert aliased_tool.id == "command_injection"


def test_cmdi_plugin_executor_adapter_fallback():
    """Verifies PluginExecutorAdapter._instantiate_specialist_fallback instantiates CommandInjectionCollector."""
    adapter = PluginExecutorAdapter()

    plugin_cmdi = adapter._instantiate_specialist_fallback("command_injection")
    assert isinstance(plugin_cmdi, CommandInjectionCollector)

    plugin_short = adapter._instantiate_specialist_fallback("cmdi")
    assert isinstance(plugin_short, CommandInjectionCollector)

    plugin_alt = adapter._instantiate_specialist_fallback("cmd_injection_collector")
    assert isinstance(plugin_alt, CommandInjectionCollector)


def test_cmdi_task_generator_recon_template():
    """Verifies TaskGenerator._RECON_TEMPLATES contains command_injection with correct DAG metadata."""
    assert "command_injection" in _RECON_TEMPLATES
    tmpl = _RECON_TEMPLATES["command_injection"]
    assert tmpl["title"] == "Fuzz OS Command Injection"
    assert tmpl["category"] == TaskCategory.EVIDENCE_CORRELATION
    assert "endpoints" in tmpl["required_inputs"]
    assert "vulnerabilities" in tmpl["expected_outputs"]
    assert "Discover API Endpoints" in tmpl["dependencies"]
    assert tmpl["metadata"]["tool_id"] == "command_injection"


def test_cmdi_task_generator_gap_resolution():
    """Verifies TaskGenerator._resolve_template_for_gap resolves command injection gaps to the template."""
    mission = Mission(target="http://example.com")
    generator = TaskGenerator(mission)

    # Area-based gap resolution
    for area in ["command injection", "cmdi", "command_injection", "cmd_injection", "os command injection", "remote code execution", "rce", "shell injection"]:
        gap = CoverageGap(area=area, description=f"Test coverage gap for {area}", severity=0.85)
        tmpl = generator._resolve_template_for_gap(gap)
        assert tmpl["metadata"]["tool_id"] == "command_injection"

    # Category-based gap description resolution
    corr_gap = CoverageGap(
        area="evidence",
        category=TaskCategory.EVIDENCE_CORRELATION,
        description="Fuzz endpoints for potential OS command injection and shell flaws",
        severity=0.85,
    )
    tmpl_corr = generator._resolve_template_for_gap(corr_gap)
    assert tmpl_corr["metadata"]["tool_id"] == "command_injection"


def test_cmdi_task_generator_from_gaps_input_resolution():
    """Verifies TaskGenerator.from_gaps binds endpoint inputs when scheduling command_injection tasks."""
    mission = Mission(target="http://example.com")
    mission.endpoints = ["http://example.com/api/ping", "http://example.com/api/run"]
    generator = TaskGenerator(mission)

    gap = CoverageGap(area="command_injection", description="Fuzz command injection on discovered endpoints", severity=0.90)
    tasks = generator.from_gaps([gap])

    assert len(tasks) == 1
    task = tasks[0]
    assert task.title == "Fuzz OS Command Injection"
    assert "http://example.com/api/ping" in task.required_inputs
    assert "http://example.com/api/run" in task.required_inputs


def test_cmdi_attack_surface_graph_builder_from_evidence():
    """Verifies AttackSurfaceGraphBuilder.build_from_evidence creates nodes and HAS_ENDPOINT/HAS_VULNERABILITY edges."""
    builder = AttackSurfaceGraphBuilder()
    graph = KnowledgeGraph()
    evidence_store = EvidenceStore()

    target_url = "http://target.local:8080/api/tools/ping"
    base_url = "http://target.local:8080"

    ev = Evidence(
        category="command_injection",
        title="Command Injection: ip on http://target.local:8080/api/tools/ping",
        description="OS Command Injection confirmed via query parameter 'ip'",
        severity="critical",
        confidence=0.95,
        value=target_url,
        provenance=ProvenanceData(step_id="command_injection_collector"),
        tags=["command_injection", "cmdi", "result_based"],
        metadata={
            "url": target_url,
            "host": base_url,
            "parameter": "ip",
            "parameter_type": "query",
            "payload": "; id",
            "technique": "result_based",
            "template_id": "cmdi",
            "severity": "critical",
            "status_code": 200,
        },
    )
    evidence_store.add(ev)

    builder.build_from_evidence(evidence_store, target=base_url, graph=graph)

    # Check Nodes
    lh_id = f"live_host:{base_url}"
    ep_id = f"endpoint:{target_url}"
    vuln_id = f"vulnerability:cmdi:{target_url}:ip"

    assert lh_id in graph.nodes
    assert ep_id in graph.nodes
    assert vuln_id in graph.nodes

    # Check Edges
    assert _has_edge(graph, lh_id, ep_id, "HAS_ENDPOINT")
    assert _has_edge(graph, lh_id, vuln_id, "HAS_VULNERABILITY")
    assert _has_edge(graph, ep_id, vuln_id, "HAS_VULNERABILITY")


def test_cmdi_mission_loop_e2e_integration():
    """Tests end-to-end mission loop execution: Mission -> PluginAdapter -> Collector -> Graph Reconstruction."""
    mock_http = MockPipelineHttpClient()
    mock_http.set_route("; id", 200, "PING 127.0.0.1 (127.0.0.1)\nuid=0(root) gid=0(root) groups=0(root)")

    mission = Mission(target="http://example-cmdi.org")
    mission.endpoints = ["http://example-cmdi.org/api/system/ping?host=127.0.0.1"]
    mission.live_hosts = ["http://example-cmdi.org"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    mission.attack_surface_graph = KnowledgeGraph()

    # Execute via PluginExecutorAdapter
    adapter = PluginExecutorAdapter()
    collector = adapter._instantiate_specialist_fallback("command_injection")
    assert collector is not None
    collector.http_client = mock_http

    controlled_mission = ControlledMission(mission)
    findings = collector.execute(controlled_mission)

    assert len(findings) >= 1
    assert len(mission.evidence.all()) >= 1
    assert len(mission.vulnerabilities) >= 1

    # Graph Builder rebuild
    builder = AttackSurfaceGraphBuilder()
    rebuilt_graph = builder.build(mission)
    assert len(rebuilt_graph.nodes_by_type("vulnerability")) >= 1
    assert len(rebuilt_graph.edges) >= 2


def test_cmdi_multi_technique_mission_graph_edges():
    """Tests simultaneous Result-Based, Time-Based, and Error-Based command injection evidence graph expansion."""
    builder = AttackSurfaceGraphBuilder()
    graph = KnowledgeGraph()
    evidence_store = EvidenceStore()

    base_url = "http://multi-cmdi.corp"
    ep_res = f"{base_url}/diag"
    ep_time = f"{base_url}/sleep"
    ep_err = f"{base_url}/exec"

    ev1 = Evidence(
        category="command_injection",
        title="Result CMDi",
        severity="critical",
        value=ep_res,
        metadata={"url": ep_res, "host": base_url, "parameter": "target", "technique": "result_based", "template_id": "cmdi_res"},
    )
    ev2 = Evidence(
        category="command_injection",
        title="Time Blind CMDi",
        severity="critical",
        value=ep_time,
        metadata={"url": ep_time, "host": base_url, "parameter": "delay", "technique": "time_blind", "template_id": "cmdi_time"},
    )
    ev3 = Evidence(
        category="command_injection",
        title="Error CMDi",
        severity="high",
        value=ep_err,
        metadata={"url": ep_err, "host": base_url, "parameter": "cmd", "technique": "error_based", "template_id": "cmdi_err"},
    )

    evidence_store.add(ev1)
    evidence_store.add(ev2)
    evidence_store.add(ev3)

    builder.build_from_evidence(evidence_store, target=base_url, graph=graph)

    vuln_nodes = graph.nodes_by_type("vulnerability")
    assert len(vuln_nodes) == 3

    # All 3 should be connected from live_host and their respective endpoints
    lh_id = f"live_host:{base_url}"
    for ev in [ev1, ev2, ev3]:
        ep_id = f"endpoint:{ev.metadata['url']}"
        vuln_id = f"vulnerability:{ev.metadata['template_id']}:{ev.metadata['url']}:{ev.metadata['parameter']}"
        assert _has_edge(graph, lh_id, ep_id, "HAS_ENDPOINT")
        assert _has_edge(graph, lh_id, vuln_id, "HAS_VULNERABILITY")
        assert _has_edge(graph, ep_id, vuln_id, "HAS_VULNERABILITY")
