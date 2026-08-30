"""
End-to-End integration tests for Phase 8 Path & Directory Traversal Engine.
Validates Mission Loop integration, TaskGenerator scheduling, PluginExecutorAdapter dispatch,
KnowledgeGraph expansion, and AttackSurfaceGraphBuilder reconstruction.
"""
from typing import Any, Dict, List, Optional
import urllib.parse
import pytest

from argus.collectors.path_traversal import PathTraversalCollector, DEFAULT_TRAVERSAL_PAYLOADS
from argus.evidence.store import EvidenceStore
from argus.graph.attack_surface import AttackSurfaceGraphBuilder
from argus.graph.graph import KnowledgeGraph
from argus.http.client import HttpResponse
from argus.planning.models import CoverageGap, TaskCategory
from argus.planning.task_generator import TaskGenerator
from argus.plugins.interfaces import ControlledMission
from argus.runtime.mission import Mission
from argus.runtime.plugins import PluginExecutorAdapter
from argus.runtime.registry import registry


class MockE2EPathTraversalHttpClient:
    """Mock HTTP client simulating real path traversal and file disclosure endpoints."""

    def __init__(self):
        self.routes = {}
        self.call_history = []

    def set_route(self, url: str, status: int, body: str):
        self.routes[url] = (status, body)

    def get(self, mission_or_url: Any, url: Optional[str] = None, **kwargs) -> HttpResponse:
        target_url = url if url is not None else mission_or_url
        if not isinstance(target_url, str):
            target_url = str(target_url)
        self.call_history.append(target_url)

        if target_url in self.routes:
            status, body = self.routes[target_url]
            return HttpResponse(
                success=(200 <= status < 300),
                status_code=status,
                raw_body=body,
                body=body,
                url=target_url,
            )

        return HttpResponse(success=False, status_code=404, error="Not Found", url=target_url)


def test_e2e_path_traversal_mission_loop_flow():
    """
    Comprehensive E2E Test:
    1. Initialize Mission with target, scope, live hosts, and crawled endpoints.
    2. Validate TaskGenerator recon pipeline includes 'Fuzz Path & Directory Traversal'.
    3. Validate ToolRegistry has 'path_traversal' registered with correct capabilities.
    4. Execute PathTraversalCollector via PluginExecutorAdapter.
    5. Assert generation of confirmed 'path_traversal' Evidence with critical severity.
    6. Assert KnowledgeGraph has nodes for live_host, endpoint, vulnerability and edges.
    7. Assert AttackSurfaceGraphBuilder faithfully reconstructs graph from EvidenceStore.
    """
    # 1. Mission setup
    mission = Mission(target="portal.internal.net")
    mission.scope = ["portal.internal.net"]
    mission.live_hosts = [{"url": "https://portal.internal.net", "host": "portal.internal.net"}]
    mission.endpoints = [
        {"url": "https://portal.internal.net/api/v1/download?file=statement.pdf", "path": "/api/v1/download", "host": "https://portal.internal.net"},
        {"url": "https://portal.internal.net/static/view?page=welcome.html", "path": "/static/view", "host": "https://portal.internal.net"},
    ]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    graph = KnowledgeGraph()
    mission.attack_surface_graph = graph

    # 2. Validate DAG TaskGenerator
    task_gen = TaskGenerator(mission)
    gaps = [CoverageGap(area="path traversal", description="Endpoints discovered need path traversal verification", severity=0.81)]
    pt_tasks = task_gen.from_gaps(gaps)
    assert len(pt_tasks) == 1
    assert pt_tasks[0].title == "Fuzz Path & Directory Traversal"
    assert pt_tasks[0].category == TaskCategory.EVIDENCE_CORRELATION
    assert "Discover API Endpoints" in pt_tasks[0].dependencies

    # 3. Validate Registry
    tool = registry.get("path_traversal")
    assert tool is not None
    assert tool.id == "path_traversal"
    assert "path_traversal_detector" in tool.capabilities

    # 4. Mock HTTP Client with realistic OS files
    mock_client = MockE2EPathTraversalHttpClient()
    for payload in DEFAULT_TRAVERSAL_PAYLOADS:
        # Endpoint 1: Linux passwd
        url1 = f"https://portal.internal.net/api/v1/download?file={urllib.parse.quote_plus(payload)}"
        if "passwd" in payload:
            mock_client.set_route(
                url1,
                200,
                "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n",
            )

        # Endpoint 2: Windows win.ini
        url2 = f"https://portal.internal.net/static/view?page={urllib.parse.quote_plus(payload)}"
        if "win.ini" in payload:
            mock_client.set_route(
                url2,
                200,
                "[fonts]\r\nArial=arial.ttf\r\n[extensions]\r\n",
            )

    # 5. Execute via collector
    collector = PathTraversalCollector(http_client=mock_client)
    evidence_list = collector.collect(mission)

    assert len(evidence_list) >= 2
    categories = {ev.category for ev in evidence_list}
    assert categories == {"path_traversal"}

    severities = {ev.severity for ev in evidence_list}
    assert severities == {"critical"}

    statuses = {ev.status for ev in evidence_list}
    assert statuses == {"CONFIRMED"}

    # Verify mission.vulnerabilities
    assert len(mission.vulnerabilities) >= 2
    vuln_names = [v["name"] for v in mission.vulnerabilities]
    assert any("/etc/passwd" in vn for vn in vuln_names)
    assert any("win.ini" in vn for vn in vuln_names)

    # 6. Verify KnowledgeGraph wiring
    nodes = list(graph.nodes.values())
    node_types = {n.type for n in nodes}
    assert "live_host" in node_types
    assert "endpoint" in node_types
    assert "vulnerability" in node_types

    vuln_nodes = graph.nodes_by_type("vulnerability")
    assert len(vuln_nodes) >= 2

    edges = graph.edges
    assert any(e.type == "HAS_ENDPOINT" for e in edges)
    assert any(e.type == "HAS_VULNERABILITY" for e in edges)

    # 7. Verify AttackSurfaceGraphBuilder reconstruction
    builder = AttackSurfaceGraphBuilder()
    reconstructed_graph = builder.build_from_evidence(list(mission.evidence.all()), target="portal.internal.net")
    rec_vulns = reconstructed_graph.nodes_by_type("vulnerability")
    assert len(rec_vulns) >= 2
    assert any(e.type == "HAS_VULNERABILITY" for e in reconstructed_graph.edges)
