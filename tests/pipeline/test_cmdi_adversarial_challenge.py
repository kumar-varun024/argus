"""
Adversarial Challenge Test Suite for Sprint 11: OS Command Injection (CMDi) Engine.
Focus: Pipeline & Graph Integration under edge cases, malformed inputs, boundary conditions,
and concurrent/high-volume evidence graphs.
"""
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple
import pytest

from argus.collectors.command_injection import (
    CommandInjectionCollector,
    CommandInjectionAnalyzer,
    CommandInjectionPayloadGenerator,
    CommandInjectionResult,
    Severity,
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
from argus.runtime.registry import ToolRegistry, registry


def _has_edge(graph: KnowledgeGraph, source: str, target: str, edge_type: str) -> bool:
    """Helper to check if a specific typed edge exists in the knowledge graph."""
    return any(e.source == source and e.target == target and e.type == edge_type for e in graph.edges)


class MockAdversarialHttpClient:
    """Configurable Mock HTTP Client for adversarial test scenarios."""

    def __init__(self, routes: Optional[Dict[str, Tuple[int, str, float]]] = None):
        self.routes = dict(routes or {})
        self.request_log: List[Dict[str, Any]] = []

    def set_route(self, key: str, status_code: int, body: str, elapsed: float = 0.05):
        self.routes[key] = (status_code, body, elapsed)

    def get(self, mission_or_url: Any, url: Optional[str] = None, **kwargs) -> HttpResponse:
        target_url = url if url is not None else mission_or_url
        if not isinstance(target_url, str):
            target_url = str(target_url)

        headers = kwargs.get("headers") or {}
        self.request_log.append({"method": "GET", "url": target_url, "headers": headers})

        # Header routing
        for hk, hv in headers.items():
            h_key = f"header:{hk}:{hv}"
            if h_key in self.routes:
                st, bd, el = self.routes[h_key]
                return HttpResponse(success=(200 <= st < 300), status_code=st, raw_body=bd, body=bd, url=target_url, elapsed=el)

        unquoted = urllib.parse.unquote_plus(target_url)
        for key, (st, bd, el) in self.routes.items():
            if key in target_url or key in unquoted:
                return HttpResponse(success=(200 <= st < 300), status_code=st, raw_body=bd, body=bd, url=target_url, elapsed=el)

        return HttpResponse(success=True, status_code=200, raw_body="Clean Response", body="Clean Response", url=target_url, elapsed=0.05)

    def post(self, mission_or_url: Any, url: Optional[str] = None, **kwargs) -> HttpResponse:
        target_url = url if url is not None else mission_or_url
        if not isinstance(target_url, str):
            target_url = str(target_url)

        data = kwargs.get("data")
        json_data = kwargs.get("json")
        headers = kwargs.get("headers") or {}
        self.request_log.append({"method": "POST", "url": target_url, "data": data, "json": json_data, "headers": headers})

        for key, (st, bd, el) in self.routes.items():
            if data and isinstance(data, dict):
                for v in data.values():
                    if key in str(v):
                        return HttpResponse(success=(200 <= st < 300), status_code=st, raw_body=bd, body=bd, url=target_url, elapsed=el)
            if json_data and isinstance(json_data, dict):
                for v in json_data.values():
                    if key in str(v):
                        return HttpResponse(success=(200 <= st < 300), status_code=st, raw_body=bd, body=bd, url=target_url, elapsed=el)
            if key in target_url:
                return HttpResponse(success=(200 <= st < 300), status_code=st, raw_body=bd, body=bd, url=target_url, elapsed=el)

        return HttpResponse(success=True, status_code=200, raw_body="Clean Response", body="Clean Response", url=target_url, elapsed=0.05)


# =============================================================================
# 1. ToolRegistry Adversarial Challenges
# =============================================================================

def test_tool_registry_exhaustive_aliases_and_properties():
    """Adversarially tests all aliases, capability lookup fallbacks, and security properties."""
    tool = registry.get("command_injection")
    assert tool is not None
    assert tool.id == "command_injection"
    assert tool.name == "Command Injection Collector"
    assert tool.priority == 95
    assert tool.timeout == 300.0
    assert tool.safety_requirements == {"type": "internal", "permissions": ["network", "db_read", "db_write"]}
    assert "endpoints" in tool.required_inputs
    assert set(["vulnerabilities", "observations", "evidence"]).issubset(set(tool.produced_outputs))

    # All required aliases
    aliases = ["cmdi", "cmd_injection", "command_injection_collector", "os_command_injection", "rce"]
    for alias in aliases:
        resolved = registry.get(alias)
        assert resolved is not None, f"Alias {alias} failed to resolve in ToolRegistry"
        assert resolved.id == "command_injection", f"Alias {alias} resolved to wrong tool {resolved.id}"

    # Capability-based fallbacks
    capabilities = ["command_injection_detector", "command_injection_collector", "cmdi_detector", "cmdi_collector"]
    for cap in capabilities:
        resolved = registry.get(cap)
        assert resolved is not None, f"Capability {cap} failed to resolve in ToolRegistry"
        assert resolved.id == "command_injection"

    # Non-existent tool returns None safely
    assert registry.get("nonexistent_tool_xyz_123") is None
    assert registry.get("") is None


def test_tool_registry_find_compatible_tools_deterministic_sorting():
    """Verifies deterministic sorting in find_compatible_tools across categories."""
    # Category where command_injection participates
    cmdi_tools = registry.find_compatible_tools("Command Injection Detection")
    assert len(cmdi_tools) >= 1
    assert cmdi_tools[0].id == "command_injection"

    # Multi-tool category: Vulnerability Scanning
    vuln_tools = registry.find_compatible_tools("Vulnerability Scanning")
    assert any(t.id == "command_injection" for t in vuln_tools)
    # Check deterministic ordering: priority descending, then tool id alphabetically
    for i in range(len(vuln_tools) - 1):
        t1, t2 = vuln_tools[i], vuln_tools[i + 1]
        assert (t1.priority > t2.priority) or (t1.priority == t2.priority and t1.id <= t2.id)

    # Multi-tool category: API Discovery
    api_tools = registry.find_compatible_tools("API Discovery")
    assert any(t.id == "command_injection" for t in api_tools)


# =============================================================================
# 2. PluginExecutorAdapter Adversarial Challenges
# =============================================================================

def test_plugin_executor_adapter_fallbacks_and_errors():
    """Adversarially tests PluginExecutorAdapter specialist fallback resolution."""
    adapter = PluginExecutorAdapter()

    # Supported key variations
    for key in ["command_injection", "cmdi", "cmd_injection", "command", "os_command_injection", "custom_cmdi_runner"]:
        inst = adapter._instantiate_specialist_fallback(key)
        assert isinstance(inst, CommandInjectionCollector), f"Failed fallback for key '{key}'"

    # Unrecognized key returns None safely
    assert adapter._instantiate_specialist_fallback("completely_unrelated_tool") is None
    assert adapter._instantiate_specialist_fallback("") is None


def test_plugin_executor_adapter_controlled_mission_lifecycle():
    """Verifies execute_plugin wraps mission in ControlledMission, executes hooks, and records findings."""
    mock_http = MockAdversarialHttpClient()
    mock_http.set_route("; id", 200, "uid=0(root) gid=0(root)")

    mission = Mission(target="http://adv-target.local")
    mission.endpoints = ["http://adv-target.local/api/diag?ip=127.0.0.1"]
    mission.live_hosts = ["http://adv-target.local"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    mission.attack_surface_graph = KnowledgeGraph()

    adapter = PluginExecutorAdapter()

    # Pre-inject mock http client into fallback
    collector = adapter._instantiate_specialist_fallback("command_injection")
    assert collector is not None
    collector.http_client = mock_http

    # Monkeypatch manager to return this collector
    class MockPluginManager:
        class MockRegistry:
            def get_plugin(self, pid):
                return collector
        registry = MockRegistry()

    adapter._manager = MockPluginManager()

    result = adapter.execute_plugin("command_injection", mission)
    assert result["status"] == "success"
    assert result["plugin_instance"] is collector

    # Verify findings propagated to mission
    assert len(mission.evidence.all()) >= 1
    assert len(mission.vulnerabilities) >= 1
    assert len(mission.attack_surface_graph.nodes) >= 3


# =============================================================================
# 3. TaskGenerator DAG Resolution Adversarial Challenges
# =============================================================================

def test_task_generator_dag_gap_resolution_adversarial_keywords():
    """Tests gap resolution with case variations, punctuation, and multi-word synonyms."""
    mission = Mission(target="http://adv-dag.com")
    generator = TaskGenerator(mission)

    # Diverse gap areas
    test_areas = [
        "command injection",
        "Command Injection",
        "COMMAND INJECTION",
        "cmdi",
        "CMDI",
        "command_injection",
        "cmd_injection",
        "os command injection",
        "OS Command Injection",
        "remote code execution",
        "RCE",
        "rce",
        "os injection",
        "shell injection",
    ]

    for area in test_areas:
        gap = CoverageGap(area=area, description=f"Gap for {area}", severity=0.88)
        tmpl = generator._resolve_template_for_gap(gap)
        assert tmpl["metadata"]["tool_id"] == "command_injection", f"Area '{area}' failed to resolve to command_injection"
        assert tmpl["title"] == "Fuzz OS Command Injection"
        assert "Discover API Endpoints" in tmpl["dependencies"]

    # Category EVIDENCE_CORRELATION with varying description keywords
    desc_keywords = [
        "Unchecked OS command execution possible",
        "Evaluate endpoints for cmdi flaws",
        "Suspected RCE in backup utility",
        "Fuzz shell injection vectors",
        "Test for os injection via ping service",
    ]
    for desc in desc_keywords:
        gap = CoverageGap(area="unknown_custom_area", category=TaskCategory.EVIDENCE_CORRELATION, description=desc, severity=0.88)
        tmpl = generator._resolve_template_for_gap(gap)
        assert tmpl["metadata"]["tool_id"] == "command_injection", f"Description '{desc}' failed to resolve"


def test_task_generator_from_gaps_input_hierarchy():
    """Verifies input precedence hierarchy: related_assets > endpoints > live_hosts > target."""
    # 1. Related assets precedence
    mission1 = Mission(target="http://target.com")
    mission1.endpoints = ["http://target.com/ep1", "http://target.com/ep2"]
    generator1 = TaskGenerator(mission1)
    gap1 = CoverageGap(
        area="cmdi",
        description="Gap with related assets",
        related_assets=["http://target.com/custom_asset_1", "http://target.com/custom_asset_2"],
        severity=0.9,
    )
    tasks1 = generator1.from_gaps([gap1])
    assert len(tasks1) == 1
    assert tasks1[0].required_inputs == ["http://target.com/custom_asset_1", "http://target.com/custom_asset_2"]

    # 2. Endpoints precedence (when related_assets empty)
    mission2 = Mission(target="http://target.com")
    mission2.endpoints = [{"url": "http://target.com/api/run"}, {"url": "http://target.com/api/test"}]
    generator2 = TaskGenerator(mission2)
    gap2 = CoverageGap(area="cmdi", description="Gap on endpoints", severity=0.9)
    tasks2 = generator2.from_gaps([gap2])
    assert len(tasks2) == 1
    assert "http://target.com/api/run" in tasks2[0].required_inputs
    assert "http://target.com/api/test" in tasks2[0].required_inputs

    # 3. Live hosts fallback (when endpoints empty)
    mission3 = Mission(target="http://target.com")
    mission3.endpoints = []
    mission3.live_hosts = ["http://host1.target.com", "http://host2.target.com"]
    generator3 = TaskGenerator(mission3)
    gap3 = CoverageGap(area="cmdi", description="Gap on live hosts", severity=0.9)
    tasks3 = generator3.from_gaps([gap3])
    assert len(tasks3) == 1
    assert "http://host1.target.com" in tasks3[0].required_inputs
    assert "http://host2.target.com" in tasks3[0].required_inputs

    # 4. Target fallback (when live_hosts and endpoints empty)
    mission4 = Mission(target="http://root.target.com")
    mission4.endpoints = []
    mission4.live_hosts = []
    generator4 = TaskGenerator(mission4)
    gap4 = CoverageGap(area="cmdi", description="Gap on root target", severity=0.9)
    tasks4 = generator4.from_gaps([gap4])
    assert len(tasks4) == 1
    assert tasks4[0].required_inputs == ["http://root.target.com"]


def test_task_generator_duplicate_gap_deduplication():
    """Verifies multiple gaps mapping to command_injection are deduplicated by title."""
    mission = Mission(target="http://target.com")
    mission.endpoints = ["http://target.com/api/run"]
    generator = TaskGenerator(mission)

    gaps = [
        CoverageGap(area="command_injection", description="Gap 1", severity=0.9),
        CoverageGap(area="cmdi", description="Gap 2", severity=0.85),
        CoverageGap(area="rce", description="Gap 3", severity=0.8),
        CoverageGap(area="shell injection", description="Gap 4", severity=0.75),
    ]
    tasks = generator.from_gaps(gaps)
    assert len(tasks) == 1
    assert tasks[0].title == "Fuzz OS Command Injection"


# =============================================================================
# 4. AttackSurfaceGraphBuilder Adversarial Challenges
# =============================================================================

def test_attack_surface_graph_builder_category_aliases_and_degraded_metadata():
    """Tests AttackSurfaceGraphBuilder handling of all category aliases, missing fields, and unicode."""
    builder = AttackSurfaceGraphBuilder()
    graph = KnowledgeGraph()
    evidence_store = EvidenceStore()

    base_url = "http://adv-graph.org:8443"

    # Category alias 1: cmdi
    ev_cmdi = Evidence(
        category="cmdi",
        title="CMDi on Ping",
        severity="critical",
        value=f"{base_url}/tools/ping",
        metadata={"url": f"{base_url}/tools/ping", "host": base_url, "parameter": "host", "template_id": "cmdi_1"},
    )
    # Category alias 2: os_command_injection
    ev_os = Evidence(
        category="os_command_injection",
        title="OS CMDi on Exec",
        severity="critical",
        value=f"{base_url}/admin/exec",
        metadata={"url": f"{base_url}/admin/exec", "host": base_url, "parameter": "cmd", "template_id": "cmdi_2"},
    )
    # Category alias 3: cmd_injection
    ev_cmd = Evidence(
        category="cmd_injection",
        title="CMD Injection on Shell",
        severity="high",
        value=f"{base_url}/api/shell",
        metadata={"url": f"{base_url}/api/shell", "host": base_url, "parameter": "q", "template_id": "cmdi_3"},
    )
    # Degraded evidence: no parameter, no template_id, missing host (relies on URL parse)
    ev_degraded = Evidence(
        category="command_injection",
        title="Degraded CMDi",
        severity="critical",
        value=f"{base_url}/degraded_ep",
        metadata={"url": f"{base_url}/degraded_ep"},
    )
    # Unicode / special char parameter
    ev_unicode = Evidence(
        category="command_injection",
        title="Unicode Parameter CMDi",
        severity="critical",
        value=f"{base_url}/search",
        metadata={"url": f"{base_url}/search", "host": base_url, "parameter": "päram;test$", "template_id": "cmdi_uni"},
    )

    evidence_store.add(ev_cmdi)
    evidence_store.add(ev_os)
    evidence_store.add(ev_cmd)
    evidence_store.add(ev_degraded)
    evidence_store.add(ev_unicode)

    builder.build_from_evidence(evidence_store, target=base_url, graph=graph)

    # Verify all 5 vulnerabilities were mapped
    vuln_nodes = graph.nodes_by_type("vulnerability")
    assert len(vuln_nodes) == 5

    # Verify edge topology
    lh_id = f"live_host:{base_url}"
    assert lh_id in graph.nodes

    # Check that live_host has edges to all 5 endpoints and all 5 vulnerabilities
    for ev in [ev_cmdi, ev_os, ev_cmd, ev_unicode]:
        target_url = ev.metadata["url"]
        param = ev.metadata["parameter"]
        tmpl = ev.metadata["template_id"]
        ep_id = f"endpoint:{target_url}"
        vuln_id = f"vulnerability:{tmpl}:{target_url}:{param}"

        assert ep_id in graph.nodes
        assert vuln_id in graph.nodes
        assert _has_edge(graph, lh_id, ep_id, "HAS_ENDPOINT")
        assert _has_edge(graph, lh_id, vuln_id, "HAS_VULNERABILITY")
        assert _has_edge(graph, ep_id, vuln_id, "HAS_VULNERABILITY")

    # Degraded evidence node
    ep_deg = f"endpoint:{base_url}/degraded_ep"
    vuln_deg = f"vulnerability:cmdi:{base_url}/degraded_ep"
    assert ep_deg in graph.nodes
    assert vuln_deg in graph.nodes
    assert _has_edge(graph, lh_id, ep_deg, "HAS_ENDPOINT")
    assert _has_edge(graph, lh_id, vuln_deg, "HAS_VULNERABILITY")
    assert _has_edge(graph, ep_deg, vuln_deg, "HAS_VULNERABILITY")


def test_attack_surface_graph_builder_high_volume_stress():
    """Stress tests AttackSurfaceGraphBuilder with 100 CMDi findings across 25 endpoints."""
    builder = AttackSurfaceGraphBuilder()
    graph = KnowledgeGraph()
    evidence_store = EvidenceStore()

    base_url = "http://high-volume-test.internal"

    for ep_idx in range(25):
        ep_url = f"{base_url}/service_{ep_idx}/action"
        for param_idx in range(4):
            param_name = f"field_{param_idx}"
            ev = Evidence(
                category="command_injection",
                title=f"CMDi {ep_idx}:{param_idx}",
                severity="critical",
                value=ep_url,
                metadata={
                    "url": ep_url,
                    "host": base_url,
                    "parameter": param_name,
                    "template_id": "cmdi",
                    "status_code": 200,
                },
            )
            evidence_store.add(ev)

    builder.build_from_evidence(evidence_store, target=base_url, graph=graph)

    # Invariants:
    # 1 live_host node
    # 25 endpoint nodes
    # 100 vulnerability nodes
    assert len(graph.nodes_by_type("live_host")) == 1
    assert len(graph.nodes_by_type("endpoint")) == 25
    assert len(graph.nodes_by_type("vulnerability")) == 100

    # Total HAS_ENDPOINT edges = 25
    # Total live_host -> HAS_VULNERABILITY edges = 100
    # Total endpoint -> HAS_VULNERABILITY edges = 100
    # Total edges = 225
    assert len(graph.edges) == 225


def test_attack_surface_graph_builder_direct_mission_vulnerabilities():
    """Verifies AttackSurfaceGraphBuilder.build populates graph directly from mission.vulnerabilities."""
    mission = Mission(target="http://direct-vuln.org")
    mission.live_hosts = ["http://direct-vuln.org"]
    mission.endpoints = ["http://direct-vuln.org/api/exec"]
    mission.vulnerabilities = [{
        "name": "Command Injection (Result-Based)",
        "template_id": "cmdi",
        "severity": "critical",
        "host": "http://direct-vuln.org",
        "url": "http://direct-vuln.org/api/exec",
        "parameter": "cmd",
        "technique": "result_based",
    }]
    mission.evidence = None

    builder = AttackSurfaceGraphBuilder()
    graph = builder.build(mission)

    assert len(graph.nodes_by_type("live_host")) >= 1
    assert len(graph.nodes_by_type("endpoint")) >= 1
    assert len(graph.nodes_by_type("vulnerability")) >= 1

    lh_id = "live_host:http://direct-vuln.org"
    ep_id = "endpoint:http://direct-vuln.org/api/exec"
    vuln_id = "vulnerability:cmdi:http://direct-vuln.org/api/exec"

    assert _has_edge(graph, lh_id, ep_id, "HAS_ENDPOINT")
    assert _has_edge(graph, lh_id, vuln_id, "HAS_VULNERABILITY")
    assert _has_edge(graph, ep_id, vuln_id, "HAS_VULNERABILITY")


def test_attack_surface_graph_builder_mixed_vulnerability_categories():
    """Tests co-existence of CMDi, SQLi, XSS, Path Traversal, and Info Disclosure on shared endpoints."""
    builder = AttackSurfaceGraphBuilder()
    graph = KnowledgeGraph()
    evidence_store = EvidenceStore()

    base_url = "http://shared-target.corp"
    ep_url = f"{base_url}/api/v1/resource"

    # CMDi
    ev_cmdi = Evidence(
        category="command_injection",
        title="CMDi on Resource",
        severity="critical",
        value=ep_url,
        metadata={"url": ep_url, "host": base_url, "parameter": "cmd", "template_id": "cmdi"},
    )
    # SQLi
    ev_sqli = Evidence(
        category="sql_injection",
        title="SQLi on Resource",
        severity="critical",
        value=ep_url,
        metadata={"url": ep_url, "host": base_url, "parameter": "id", "template_id": "sqli"},
    )
    # XSS
    ev_xss = Evidence(
        category="xss",
        title="XSS on Resource",
        severity="high",
        value=ep_url,
        metadata={"url": ep_url, "host": base_url, "parameter": "q", "template_id": "xss", "xss_type": "reflected"},
    )
    # Path Traversal
    ev_pt = Evidence(
        category="path_traversal",
        title="Path Traversal on Resource",
        severity="critical",
        value=ep_url,
        metadata={"url": ep_url, "host": base_url, "template_id": "path-traversal"},
    )

    evidence_store.add(ev_cmdi)
    evidence_store.add(ev_sqli)
    evidence_store.add(ev_xss)
    evidence_store.add(ev_pt)

    builder.build_from_evidence(evidence_store, target=base_url, graph=graph)

    # Invariants: 1 live_host, 1 endpoint, 4 distinct vulnerability nodes
    assert len(graph.nodes_by_type("live_host")) == 1
    assert len(graph.nodes_by_type("endpoint")) == 1
    assert len(graph.nodes_by_type("vulnerability")) == 4

    lh_id = f"live_host:{base_url}"
    ep_id = f"endpoint:{ep_url}"
    assert _has_edge(graph, lh_id, ep_id, "HAS_ENDPOINT")

    for v_node in graph.nodes_by_type("vulnerability"):
        assert _has_edge(graph, lh_id, v_node.id, "HAS_VULNERABILITY")
        assert _has_edge(graph, ep_id, v_node.id, "HAS_VULNERABILITY")


def test_attack_surface_graph_builder_ipv6_and_custom_ports():
    """Tests host and endpoint URL parsing with IPv6 addresses and non-standard ports."""
    builder = AttackSurfaceGraphBuilder()
    graph = KnowledgeGraph()
    evidence_store = EvidenceStore()

    target_url = "http://[::1]:8080/api/tools/ping"
    base_url = "http://[::1]:8080"

    ev = Evidence(
        category="cmdi",
        title="CMDi on IPv6",
        severity="critical",
        value=target_url,
        metadata={"url": target_url, "host": base_url, "parameter": "target"},
    )
    evidence_store.add(ev)

    builder.build_from_evidence(evidence_store, target=base_url, graph=graph)

    lh_id = f"live_host:{base_url}"
    ep_id = f"endpoint:{target_url}"
    vuln_id = f"vulnerability:cmdi:{target_url}:target"

    assert lh_id in graph.nodes
    assert ep_id in graph.nodes
    assert vuln_id in graph.nodes
    assert _has_edge(graph, lh_id, ep_id, "HAS_ENDPOINT")
    assert _has_edge(graph, lh_id, vuln_id, "HAS_VULNERABILITY")


def test_cmdi_collector_resilience_to_exceptions_and_malformed_responses():
    """Tests collector resilience when HTTP client throws unexpected network exceptions or returns corrupted data."""
    class FailingHttpClient:
        def get(self, *args, **kwargs):
            raise ConnectionResetError("Adversarial connection drop")
        def post(self, *args, **kwargs):
            raise TimeoutError("Adversarial timeout")

    collector = CommandInjectionCollector(http_client=FailingHttpClient())
    mission = Mission(target="http://unstable.target.com")
    mission.endpoints = ["http://unstable.target.com/api/ping?ip=127.0.0.1"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    mission.attack_surface_graph = KnowledgeGraph()

    # Must complete safely without unhandled exception, emitting 0 false findings
    findings = collector.collect(mission)
    assert findings == []
    assert len(mission.vulnerabilities) == 0


def test_task_generator_edge_case_empty_and_unknown_gaps():
    """Tests TaskGenerator behavior with unmapped, empty, and edge case gaps."""
    mission = Mission(target="http://edge-cases.com")
    generator = TaskGenerator(mission)

    # Empty area with description
    gap_empty_area = CoverageGap(area="", description="Perform unknown testing", severity=0.5)
    tmpl1 = generator._resolve_template_for_gap(gap_empty_area)
    assert tmpl1 is not None

    # Unknown category fallback
    gap_unknown = CoverageGap(area="alien_vector", description="Unknown alien vector", category=TaskCategory.COVERAGE_IMPROVEMENT, severity=0.5)
    tmpl2 = generator._resolve_template_for_gap(gap_unknown)
    assert tmpl2["title"] == "Improve Coverage"

