"""
Unit and integration tests for PathTraversalCollector, PathTraversalPayloadGenerator,
PathTraversalAnalyzer, DAG TaskGenerator, ToolRegistry, and AttackSurfaceGraph wiring.
"""
from typing import Any, Dict, List, Optional
import pytest
import urllib.parse

from argus.collectors.path_traversal import (
    PathTraversalCollector,
    PathTraversalPayloadGenerator,
    PathTraversalAnalyzer,
    DEFAULT_TRAVERSAL_PAYLOADS,
)
from argus.evidence.model import Evidence
from argus.evidence.store import EvidenceStore
from argus.graph.graph import KnowledgeGraph
from argus.graph.attack_surface import AttackSurfaceGraphBuilder
from argus.http.client import HttpResponse
from argus.planning.models import CoverageGap, TaskCategory
from argus.planning.task_generator import TaskGenerator, _RECON_TEMPLATES
from argus.plugins.interfaces import ControlledMission
from argus.runtime.mission import Mission
from argus.runtime.plugins import PluginExecutorAdapter
from argus.runtime.registry import registry


class MockTraversalHttpClient:
    """Mock HTTP client that returns responses based on URL matching."""

    def __init__(self, routes: Optional[Dict[str, tuple]] = None):
        self.routes = routes or {}
        self.requested_urls: List[str] = []

    def set_route(self, url: str, status_code: int, body: str):
        self.routes[url] = (status_code, body)

    def get(self, mission_or_url: Any, url: Optional[str] = None, **kwargs) -> HttpResponse:
        target_url = url if url is not None else mission_or_url
        if not isinstance(target_url, str):
            target_url = str(target_url)
        self.requested_urls.append(target_url)

        if target_url in self.routes:
            status_code, body = self.routes[target_url]
            return HttpResponse(
                success=(200 <= status_code < 300),
                status_code=status_code,
                raw_body=body,
                body=body,
                url=target_url,
            )

        # Check partial query match
        for registered_url, (status_code, body) in self.routes.items():
            if target_url == registered_url:
                return HttpResponse(
                    success=(200 <= status_code < 300),
                    status_code=status_code,
                    raw_body=body,
                    body=body,
                    url=target_url,
                )

        return HttpResponse(success=False, status_code=404, error="Not Found", url=target_url)


def test_path_traversal_mock_verification_linux_passwd():
    """
    R1/R5 Acceptance Requirement:
    Programmatic mock test verifying Evidence(category="path_traversal", severity="critical")
    when an endpoint returns 'root:x:0:0:root:/root:/bin/bash'.
    """
    mission = Mission(target="example.com")
    mission.endpoints = [{"url": "https://example.com/view?file=report.pdf"}]
    mission.live_hosts = ["https://example.com"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    graph = KnowledgeGraph()
    mission.attack_surface_graph = graph

    mock_client = MockTraversalHttpClient()
    vuln_url = "https://example.com/view?file=..%2F..%2F..%2F..%2Fetc%2Fpasswd"
    mock_client.set_route(
        vuln_url,
        200,
        "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin",
    )

    collector = PathTraversalCollector(http_client=mock_client)
    evidence_list = collector.collect(mission)

    assert len(evidence_list) >= 1
    ev = evidence_list[0]
    assert ev.category == "path_traversal"
    assert ev.severity == "critical"
    assert ev.status == "CONFIRMED"
    assert ev.confidence == 0.95
    assert ev.metadata["target_file"] == "/etc/passwd"
    assert ev.metadata["os"] == "linux"
    assert ev.metadata["parameter"] == "file"
    assert "root:x:0:0" in ev.metadata["evidence_snippet"]

    # Verify mission state
    assert len(mission.vulnerabilities) >= 1
    assert mission.vulnerabilities[0]["severity"] == "critical"
    assert mission.vulnerabilities[0]["parameter"] == "file"


def test_path_traversal_payload_generator_mutations():
    """
    R2: Tests that payload generator creates standard, encoded, double-encoded,
    overlong UTF-8, absolute, null-byte, and path parameter mutations.
    """
    generator = PathTraversalPayloadGenerator()
    payloads = generator.get_payloads()

    assert any("../" in p for p in payloads)
    assert any("....//" in p for p in payloads)
    assert any("%2e%2e%2f" in p.lower() or "..%2f" in p.lower() for p in payloads)
    assert any("%252e%252e%252f" in p.lower() or "..%252f" in p.lower() for p in payloads)
    assert any("%c0%ae" in p.lower() for p in payloads)
    assert "/etc/passwd" in payloads
    assert "c:\\windows\\win.ini" in payloads or "c:/windows/win.ini" in payloads
    assert "/etc/shadow" in payloads
    assert any("%00" in p for p in payloads)
    assert any("..;/" in p for p in payloads)


def test_path_traversal_analyzer_linux_signatures():
    """
    R3: Tests Linux signature matches (/etc/passwd, /etc/shadow, /proc/self/environ, /etc/hosts).
    """
    analyzer = PathTraversalAnalyzer()

    # 1. /etc/passwd root bash
    res1 = analyzer.analyze(200, "root:x:0:0:root:/root:/bin/bash\nbin:x:1:1:bin:/bin:/bin/sh", "../../../../etc/passwd")
    assert res1 is not None
    assert res1["target_file"] == "/etc/passwd"
    assert res1["os"] == "linux"

    # 2. /etc/passwd fallback
    res2 = analyzer.analyze(200, "root:*:0:0:SuperUser:/var/root:/bin/sh", "/etc/passwd")
    assert res2 is not None
    assert res2["target_file"] == "/etc/passwd"

    # 3. /etc/shadow
    shadow_content = "root:$6$rounds=40960$salt$encryptedhash:18000:0:99999:7:::\ndaemon:*:18000:0:99999:7:::"
    res3 = analyzer.analyze(200, shadow_content, "/etc/shadow")
    assert res3 is not None
    assert res3["target_file"] == "/etc/shadow"

    # 4. /proc/self/environ
    environ_content = "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin\x00USER=www-data\x00HOME=/var/www\x00"
    res4 = analyzer.analyze(200, environ_content, "/proc/self/environ")
    assert res4 is not None
    assert res4["target_file"] == "/proc/self/environ"

    # 5. /etc/hosts
    hosts_content = "127.0.0.1 localhost\n::1 localhost ip6-localhost"
    res5 = analyzer.analyze(200, hosts_content, "/etc/hosts")
    assert res5 is not None
    assert res5["target_file"] == "/etc/hosts"


def test_path_traversal_analyzer_windows_signatures():
    """
    R3: Tests Windows signature matches (win.ini, boot.ini, hosts).
    """
    analyzer = PathTraversalAnalyzer()

    # 1. win.ini with extensions and 16-bit app comment
    win_ini_body = "; for 16-bit app support\r\n[fonts]\r\nArial=arial.ttf\r\n[extensions]\r\n"
    res1 = analyzer.analyze(200, win_ini_body, "c:\\windows\\win.ini")
    assert res1 is not None
    assert res1["target_file"] == "c:\\windows\\win.ini"
    assert res1["os"] == "windows"

    # 2. boot.ini
    boot_ini_body = "[boot loader]\r\ntimeout=30\r\ndefault=multi(0)disk(0)rdisk(0)partition(1)\\WINDOWS\r\n[operating systems]"
    res2 = analyzer.analyze(200, boot_ini_body, "c:\\boot.ini")
    assert res2 is not None
    assert res2["target_file"] == "c:\\boot.ini"
    assert res2["os"] == "windows"


def test_false_positive_rejection_echo_reflection():
    """
    R3: False positive prevention:
    Reflection of payload without genuine OS file contents should be discarded.
    """
    analyzer = PathTraversalAnalyzer()

    # Error page echoing the payload parameter
    reflected_body = "<html><body><h1>Error: File not found</h1><p>The requested file ../../../../etc/passwd does not exist.</p></body></html>"
    res = analyzer.analyze(200, reflected_body, "../../../../etc/passwd")
    assert res is None

    # Form reflection
    form_reflection = '<form><input type="text" name="file" value="../../../../windows/win.ini" /></form>'
    res2 = analyzer.analyze(200, form_reflection, "../../../../windows/win.ini")
    assert res2 is None


def test_false_positive_rejection_http_error_codes():
    """
    R3: Reject 404, 500, 403, 400 even if body contains matching patterns.
    """
    analyzer = PathTraversalAnalyzer()
    body = "root:x:0:0:root:/root:/bin/bash"

    assert analyzer.analyze(404, body, "/etc/passwd") is None
    assert analyzer.analyze(500, body, "/etc/passwd") is None
    assert analyzer.analyze(403, body, "/etc/passwd") is None
    assert analyzer.analyze(400, body, "/etc/passwd") is None
    assert analyzer.analyze(None, body, "/etc/passwd") is None


def test_false_positive_rejection_baseline_differential():
    """
    R3: Baseline differential check: if baseline already contains signature, reject.
    """
    analyzer = PathTraversalAnalyzer()
    static_page = "Welcome to Linux admin docs! Example entry: root:x:0:0:root:/root:/bin/bash for root user."

    res = analyzer.analyze(
        status_code=200,
        body=static_page,
        payload="../../../../etc/passwd",
        baseline_body=static_page,
    )
    assert res is None


def test_path_traversal_query_parameter_fuzzing():
    """
    R1: Tests fuzzing multiple query parameters on discovered endpoints.
    """
    mission = Mission(target="api.target.com")
    mission.endpoints = [{"url": "https://api.target.com/documents/view?doc_id=123&format=pdf&source=default"}]
    mission.live_hosts = ["https://api.target.com"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []

    mock_client = MockTraversalHttpClient()
    # Mock vulnerable response when source parameter has traversal payload
    for payload in DEFAULT_TRAVERSAL_PAYLOADS:
        mutated_url = f"https://api.target.com/documents/view?doc_id=123&format=pdf&source={urllib.parse.quote_plus(payload)}"
        if "passwd" in payload:
            mock_client.set_route(mutated_url, 200, "root:x:0:0:root:/root:/bin/bash\nbin:x:1:1:bin:/bin:/sh")

    collector = PathTraversalCollector(http_client=mock_client)
    evidence_list = collector.collect(mission)

    assert len(evidence_list) >= 1
    assert any(ev.metadata.get("parameter") == "source" for ev in evidence_list)


def test_path_traversal_path_segment_fuzzing():
    """
    R1: Tests fuzzing endpoints with path segments (e.g. /download/{payload}).
    """
    mission = Mission(target="static.target.com")
    mission.endpoints = ["https://static.target.com/download/sample.txt"]
    mission.live_hosts = ["https://static.target.com"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []

    mock_client = MockTraversalHttpClient()
    for payload in DEFAULT_TRAVERSAL_PAYLOADS:
        mutated_url = f"https://static.target.com/download/{payload.lstrip('/')}"
        if "win.ini" in payload:
            mock_client.set_route(mutated_url, 200, "[fonts]\r\nArial=arial.ttf\r\n[extensions]\r\n")

    collector = PathTraversalCollector(http_client=mock_client)
    evidence_list = collector.collect(mission)

    assert len(evidence_list) >= 1
    assert any(ev.metadata.get("os") == "windows" for ev in evidence_list)


def test_path_traversal_fallback_probe_routes():
    """
    R1: When no parameterized endpoints exist, standard probe routes are automatically tested.
    """
    mission = Mission(target="probe-target.com")
    mission.endpoints = []
    mission.live_hosts = ["https://probe-target.com"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []

    mock_client = MockTraversalHttpClient()
    # Route /download?file=... is vulnerable
    for payload in DEFAULT_TRAVERSAL_PAYLOADS:
        mutated_url = f"https://probe-target.com/download?file={urllib.parse.quote_plus(payload)}"
        if "passwd" in payload:
            mock_client.set_route(mutated_url, 200, "root:x:0:0:root:/root:/bin/bash\n")

    collector = PathTraversalCollector(http_client=mock_client)
    evidence_list = collector.collect(mission)

    assert len(evidence_list) >= 1
    assert any("download" in ev.metadata.get("url", "") for ev in evidence_list)


def test_path_traversal_attack_surface_graph_wiring():
    """
    R1/R4: Verifies live_host, endpoint, and vulnerability nodes and HAS_ENDPOINT/HAS_VULNERABILITY edges.
    """
    mission = Mission(target="graph-target.com")
    mission.endpoints = [{"url": "https://graph-target.com/read?file=test"}]
    mission.live_hosts = ["https://graph-target.com"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    graph = KnowledgeGraph()
    mission.attack_surface_graph = graph

    mock_client = MockTraversalHttpClient()
    for payload in DEFAULT_TRAVERSAL_PAYLOADS:
        mutated_url = f"https://graph-target.com/read?file={urllib.parse.quote_plus(payload)}"
        if "passwd" in payload:
            mock_client.set_route(mutated_url, 200, "root:x:0:0:root:/root:/bin/bash\n")

    collector = PathTraversalCollector(http_client=mock_client)
    collector.collect(mission)

    # Check graph nodes
    nodes = list(graph.nodes.values())
    node_types = {n.type for n in nodes}
    assert "live_host" in node_types
    assert "endpoint" in node_types
    assert "vulnerability" in node_types

    # Check edges
    edges = graph.edges
    edge_types = {e.type for e in edges}
    assert "HAS_ENDPOINT" in edge_types
    assert "HAS_VULNERABILITY" in edge_types


def test_attack_surface_graph_builder_path_traversal_reconstruction():
    """
    R4: Tests AttackSurfaceGraphBuilder reconstruction of path_traversal evidence into KnowledgeGraph.
    """
    builder = AttackSurfaceGraphBuilder()
    ev = Evidence(
        title="Path Traversal: file on https://app.example.com/get?file=../../../../etc/passwd",
        category="path_traversal",
        severity="critical",
        status="CONFIRMED",
        value="https://app.example.com/get?file=../../../../etc/passwd",
        metadata={
            "url": "https://app.example.com/get?file=../../../../etc/passwd",
            "host": "https://app.example.com",
            "path": "/get",
            "parameter": "file",
            "template_id": "path-traversal-etc-passwd",
            "target_file": "/etc/passwd",
            "status_code": 200,
        },
    )

    graph = builder.build_from_evidence([ev], target="example.com")
    assert graph is not None

    vuln_nodes = graph.nodes_by_type("vulnerability")
    assert len(vuln_nodes) == 1
    assert "Path Traversal" in vuln_nodes[0].value

    ep_nodes = graph.nodes_by_type("endpoint")
    assert len(ep_nodes) == 1

    edges = graph.edges
    assert any(e.type == "HAS_VULNERABILITY" for e in edges)
    assert any(e.type == "HAS_ENDPOINT" for e in edges)


def test_task_generator_dag_scheduling_path_traversal():
    """
    R4: Tests DAG generation includes path_traversal template and gap scheduling with proper priority and dependencies.
    """
    assert "path_traversal" in _RECON_TEMPLATES
    tpl = _RECON_TEMPLATES["path_traversal"]
    assert tpl["title"] == "Fuzz Path & Directory Traversal"
    assert tpl["category"] == TaskCategory.EVIDENCE_CORRELATION
    assert "Discover API Endpoints" in tpl["dependencies"]
    assert tpl["priority"] == 0.81
    assert tpl["metadata"]["tool_id"] == "path_traversal"

    mission = Mission(target="task-target.com")
    mission.subdomains = ["app.task-target.com"]
    mission.live_hosts = ["https://app.task-target.com"]
    mission.endpoints = ["https://app.task-target.com/api/v1/download"]

    generator = TaskGenerator(mission)
    tasks = generator.from_gaps([CoverageGap(area="path traversal", description="Unfuzzed endpoint paths", severity=0.81)])

    assert len(tasks) == 1
    task = tasks[0]
    assert task.title == "Fuzz Path & Directory Traversal"
    assert task.category == TaskCategory.EVIDENCE_CORRELATION
    assert "Discover API Endpoints" in task.dependencies
    assert task.metadata.get("tool_id") == "path_traversal"
    assert "https://app.task-target.com/api/v1/download" in task.required_inputs


def test_task_generator_gap_resolver_path_traversal():
    """
    R4: Tests gap resolution routes path traversal keywords to path_traversal template.
    """
    mission = Mission(target="gap-target.com")
    generator = TaskGenerator(mission)

    gaps = [
        CoverageGap(area="path traversal", description="Uncovered path traversal vectors", severity=0.9),
        CoverageGap(area="arbitrary file read", description="Need LFI verification", severity=0.85),
    ]

    tasks = generator.from_gaps(gaps)
    assert len(tasks) == 1  # Deduplicated by title
    assert tasks[0].metadata.get("tool_id") == "path_traversal"


def test_tool_registry_path_traversal_registration():
    """
    R4: Tests that path_traversal is registered in global tool registry.
    """
    tool = registry.get("path_traversal")
    assert tool is not None
    assert tool.id == "path_traversal"
    assert tool.capability == "path_traversal_detector"
    assert "Path Traversal Detection" in tool.supported_tasks
    assert tool.safety_requirements["type"] == "internal"


def test_plugin_executor_adapter_path_traversal_fallback():
    """
    R4: Tests PluginExecutorAdapter fallback instantiates PathTraversalCollector.
    """
    adapter = PluginExecutorAdapter()
    instance = adapter._instantiate_specialist_fallback("path_traversal")
    assert instance is not None
    assert isinstance(instance, PathTraversalCollector)


def test_controlled_mission_execution():
    """
    R4: Tests executing PathTraversalCollector through ControlledMission.
    """
    mission = Mission(target="controlled.com")
    mission.endpoints = [{"url": "https://controlled.com/view?file=report.pdf"}]
    mission.live_hosts = ["https://controlled.com"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []

    mock_client = MockTraversalHttpClient()
    for payload in DEFAULT_TRAVERSAL_PAYLOADS:
        mutated_url = f"https://controlled.com/view?file={urllib.parse.quote_plus(payload)}"
        if "passwd" in payload:
            mock_client.set_route(mutated_url, 200, "root:x:0:0:root:/root:/bin/bash\n")

    collector = PathTraversalCollector(http_client=mock_client)
    controlled_mission = ControlledMission(mission)
    evidence_list = collector.execute(controlled_mission)

    assert len(evidence_list) >= 1
    assert evidence_list[0].category == "path_traversal"


def test_custom_payloads_injection():
    """
    R1: Tests that custom payloads injected via constructor are utilized.
    """
    custom_list = ["../../custom_file.txt", "....//custom_file.txt"]
    collector = PathTraversalCollector(payloads=custom_list)
    assert collector.generator.get_payloads() == custom_list


def test_empty_or_malformed_target_graceful_handling():
    """
    R1: Tests that empty mission or unreachable targets do not crash collector.
    """
    mission = Mission(target="")
    mission.endpoints = []
    mission.live_hosts = []

    collector = PathTraversalCollector()
    results = collector.collect(mission)
    assert results == []

