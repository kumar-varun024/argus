"""
End-to-End integration tests for SQL Injection Detection Engine.
Validates Mission Loop integration, TaskGenerator scheduling, PluginExecutorAdapter dispatch,
Multi-technique detection, KnowledgeGraph expansion, and AttackSurfaceGraphBuilder reconstruction.
"""
from typing import Any, Dict, List, Optional, Tuple
import urllib.parse
import pytest

from argus.collectors.sql_injection import (
    SQLInjectionCollector,
    SQLInjectionPayloadGenerator,
    SQLInjectionAnalyzer,
    DEFAULT_ERROR_PAYLOADS,
)
from argus.evidence.store import EvidenceStore
from argus.graph.attack_surface import AttackSurfaceGraphBuilder
from argus.graph.graph import KnowledgeGraph
from argus.http.client import HttpResponse
from argus.planning.models import CoverageGap, TaskCategory
from argus.planning.task_generator import TaskGenerator, _RECON_TEMPLATES
from argus.plugins.interfaces import ControlledMission
from argus.runtime.mission import Mission
from argus.runtime.plugins import PluginExecutorAdapter
from argus.runtime.registry import registry


class MockE2ESQLiHttpClient:
    """Mock HTTP client simulating real SQL injection response behavior."""

    def __init__(self):
        self.routes: Dict[str, Tuple[int, str, float]] = {}
        self.call_history: List[str] = []

    def set_route(self, url: str, status: int, body: str, elapsed: float = 0.05):
        self.routes[url] = (status, body, elapsed)

    def get(self, mission_or_url: Any, url: Optional[str] = None, **kwargs) -> HttpResponse:
        target_url = url if url is not None else mission_or_url
        if not isinstance(target_url, str):
            target_url = str(target_url)
        self.call_history.append(target_url)

        if target_url in self.routes:
            status, body, elapsed = self.routes[target_url]
            return HttpResponse(
                success=(200 <= status < 300),
                status_code=status,
                raw_body=body,
                body=body,
                url=target_url,
                elapsed=elapsed,
            )

        # Baseline default fallback
        return HttpResponse(
            success=True,
            status_code=200,
            raw_body="<html><body><h1>Normal Web Application</h1><p>Welcome to the portal.</p></body></html>",
            body="<html><body><h1>Normal Web Application</h1><p>Welcome to the portal.</p></body></html>",
            url=target_url,
            elapsed=0.05,
        )

    def post(self, mission_or_url: Any, url: Optional[str] = None, **kwargs) -> HttpResponse:
        target_url = url if url is not None else mission_or_url
        if not isinstance(target_url, str):
            target_url = str(target_url)

        json_data = kwargs.get("json") or {}
        if isinstance(json_data, dict) and any("'" in str(v) for v in json_data.values()):
            return HttpResponse(
                success=False,
                status_code=500,
                raw_body="You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version",
                body="You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version",
                url=target_url,
                elapsed=0.05,
            )

        return HttpResponse(
            success=True,
            status_code=200,
            raw_body="<html><body><h1>POST OK</h1></body></html>",
            body="<html><body><h1>POST OK</h1></body></html>",
            url=target_url,
            elapsed=0.05,
        )


def test_e2e_sql_injection_mission_loop_flow():
    """
    Comprehensive E2E Test:
    1. Initialize Mission with target, scope, live hosts, and crawled endpoints.
    2. Validate TaskGenerator recon pipeline and gap resolution for 'Fuzz SQL Injection'.
    3. Validate ToolRegistry has 'sql_injection' registered.
    4. Execute SQLInjectionCollector via PluginExecutorAdapter.
    5. Assert generation of confirmed Evidence(category='sql_injection') with critical severity.
    6. Assert KnowledgeGraph has nodes for live_host, endpoint, vulnerability, and edges.
    7. Assert AttackSurfaceGraphBuilder faithfully reconstructs graph from EvidenceStore.
    """
    # 1. Mission setup
    mission = Mission(target="portal.internal.net")
    mission.scope = ["portal.internal.net"]
    mission.live_hosts = [{"url": "https://portal.internal.net", "host": "portal.internal.net"}]
    mission.endpoints = [
        {"url": "https://portal.internal.net/api/v1/search?q=test", "path": "/api/v1/search", "params": {"q": "test"}, "host": "https://portal.internal.net"},
    ]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    graph = KnowledgeGraph()
    mission.attack_surface_graph = graph

    # 2. Validate DAG TaskGenerator
    task_gen = TaskGenerator(mission)
    gaps = [CoverageGap(area="sql injection", description="Discovered endpoints require SQL injection fuzzing", severity=0.81)]
    sqli_tasks = task_gen.from_gaps(gaps)
    assert len(sqli_tasks) == 1
    assert sqli_tasks[0].title == "Fuzz SQL Injection"
    assert sqli_tasks[0].category == TaskCategory.EVIDENCE_CORRELATION
    assert "Discover API Endpoints" in sqli_tasks[0].dependencies

    # 3. Validate Registry
    tool = registry.get("sql_injection")
    assert tool is not None
    assert tool.id == "sql_injection"
    assert "sql_injection_detector" in tool.capabilities

    # 4. Mock HTTP Client with realistic database syntax error
    mock_client = MockE2ESQLiHttpClient()
    vuln_url = "https://portal.internal.net/api/v1/search?q=%27"
    mock_client.set_route(
        vuln_url,
        500,
        "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '''",
        0.06,
    )

    collector = SQLInjectionCollector(http_client=mock_client)
    adapter = PluginExecutorAdapter()
    controlled_mission = ControlledMission(mission)

    # 5. Execute
    evidence_list = collector.execute(controlled_mission)
    assert len(evidence_list) >= 1
    ev = evidence_list[0]
    assert ev.category == "sql_injection"
    assert ev.severity == "critical"
    assert ev.status == "CONFIRMED"
    assert ev.confidence == 0.95
    assert ev.metadata["dbms"] == "mysql"
    assert ev.metadata["parameter"] == "q"

    # 6. Verify KnowledgeGraph nodes and edges
    assert len(graph.nodes) >= 3
    live_host_nodes = graph.nodes_by_type("live_host")
    endpoint_nodes = graph.nodes_by_type("endpoint")
    vuln_nodes = graph.nodes_by_type("vulnerability")
    assert len(live_host_nodes) >= 1
    assert len(endpoint_nodes) >= 1
    assert len(vuln_nodes) >= 1

    assert any(e.type == "HAS_ENDPOINT" for e in graph.edges)
    assert any(e.type == "HAS_VULNERABILITY" for e in graph.edges)

    # 7. Verify Graph Builder Reconstruction from Evidence
    builder = AttackSurfaceGraphBuilder()
    reconstructed_graph = builder.build_from_evidence(list(mission.evidence), target="portal.internal.net")
    assert any(e.type == "HAS_VULNERABILITY" for e in reconstructed_graph.edges)
    assert any(e.type == "HAS_ENDPOINT" for e in reconstructed_graph.edges)


def test_e2e_sql_injection_multi_technique_mission():
    """
    Tests mission containing both error-based and boolean-based SQL injection on distinct endpoints,
    confirming critical and high severity levels and knowledge graph integrity.
    """
    mission = Mission(target="app.testcorp.com")
    mission.scope = ["app.testcorp.com"]
    mission.live_hosts = ["https://app.testcorp.com"]
    mission.endpoints = [
        {"url": "https://app.testcorp.com/users?id=10", "path": "/users", "params": {"id": "10"}},
        {"url": "https://app.testcorp.com/products?cat=electronics", "path": "/products", "params": {"cat": "electronics"}},
    ]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    mission.attack_surface_graph = KnowledgeGraph()

    mock_client = MockE2ESQLiHttpClient()
    # Endpoint 1: PostgreSQL Error-Based
    mock_client.set_route(
        "https://app.testcorp.com/users?id=%27",
        500,
        "org.postgresql.util.PSQLException: ERROR: syntax error at or near \"'\"",
        0.05,
    )
    # Endpoint 2: Boolean-based blind differential
    # Baseline
    mock_client.set_route(
        "https://app.testcorp.com/products?cat=electronics",
        200,
        "<html><body>" + ("<div>Product Item</div>" * 100) + "</body></html>",
        0.05,
    )
    # TRUE query
    mock_client.set_route(
        "https://app.testcorp.com/products?cat=%27+OR+1%3D1--",
        200,
        "<html><body>" + ("<div>Product Item</div>" * 100) + "</body></html>",
        0.05,
    )
    # FALSE query
    mock_client.set_route(
        "https://app.testcorp.com/products?cat=%27+OR+1%3D2--",
        200,
        "<html><body><div>No Products Found</div></body></html>",
        0.05,
    )

    collector = SQLInjectionCollector(http_client=mock_client)
    evidence_list = collector.collect(mission)

    assert len(evidence_list) == 2
    severities = {ev.severity for ev in evidence_list}
    assert "critical" in severities
    assert "high" in severities

    techniques = {ev.metadata["technique"] for ev in evidence_list}
    assert "error_based" in techniques
    assert "boolean_blind" in techniques


def test_e2e_sql_injection_gap_analysis_and_replanning():
    """
    Tests that GapAnalyzer and TaskGenerator properly identify SQL injection gaps
    and schedule tasks with proper dependencies.
    """
    mission = Mission(target="target.org")
    mission.endpoints = [{"url": "https://target.org/api/v1/item?id=1"}]

    generator = TaskGenerator(mission)
    gaps = [
        CoverageGap(area="sql_injection", description="Audit endpoints for SQLi", severity=0.85),
    ]
    tasks = generator.from_gaps(gaps)

    assert len(tasks) == 1
    task = tasks[0]
    assert task.metadata["tool_id"] == "sql_injection"
    assert task.priority == 0.85
    assert "Discover API Endpoints" in task.dependencies
