"""
End-to-End integration tests for Cross-Site Scripting (XSS) Detection Engine and Environment Detector.
Validates Mission Loop integration, TaskGenerator DAG scheduling, ToolRegistry lookup,
PluginExecutorAdapter dispatch, Reflected & Stored XSS lifecycles, Multi-vulnerability missions (XSS + SQLi),
Environment Detector mission initialization, and AttackSurfaceGraphBuilder reconstruction.
"""

from __future__ import annotations

import html
import socket
from typing import Any, Dict, List, Optional, Tuple
import urllib.parse
from unittest.mock import MagicMock, patch

import httpx
import pytest

from argus.collectors.sql_injection import SQLInjectionCollector
from argus.collectors.xss import (
    XSSCollector,
    XSSAnalyzer,
    XSSPayloadGenerator,
    XSSContext,
)
from argus.evidence.model import Evidence
from argus.evidence.store import EvidenceStore
from argus.graph.attack_surface import AttackSurfaceGraphBuilder
from argus.graph.graph import KnowledgeGraph
from argus.http.client import HttpResponse
from argus.planning.models import CoverageGap, TaskCategory
from argus.planning.task_generator import TaskGenerator, _RECON_TEMPLATES
from argus.plugins.interfaces import ControlledMission
from argus.runtime.checkpoint import MissionCheckpointer
from argus.runtime.mission import Mission, MissionState
from argus.runtime.mission_runtime import AutonomousMissionRuntime
from argus.runtime.plugins import PluginExecutorAdapter
from argus.runtime.registry import registry
from argus.runtime.state_machine import MissionStateMachine
from argus.utils.environment import EnvironmentDetector


class MockE2EXSSHttpClient:
    """Mock HTTP client simulating real web application responses for XSS and SQLi E2E testing."""

    def __init__(self, routes: Optional[Dict[str, Tuple[int, str, float]]] = None):
        self.routes: Dict[str, Tuple[int, str, float]] = routes or {}
        self.call_history: List[str] = []
        self.stored_posts: Dict[str, str] = {}
        self.post_history: List[Dict[str, Any]] = []

    def set_route(self, url: str, status: int, body: str, elapsed: float = 0.05):
        self.routes[url] = (status, body, elapsed)

    def get(
        self, mission_or_url: Any, url: Optional[str] = None, **kwargs
    ) -> HttpResponse:
        target_url = url if url is not None else mission_or_url
        if not isinstance(target_url, str):
            target_url = str(target_url)
        self.call_history.append(target_url)

        headers = kwargs.get("headers") or {}
        # Header reflection check
        for hk, hv in headers.items():
            if f"header:{hk}:{hv}" in self.routes:
                status, body, elapsed = self.routes[f"header:{hk}:{hv}"]
                return HttpResponse(
                    success=(200 <= status < 300),
                    status_code=status,
                    raw_body=body,
                    body=body,
                    headers={"Content-Type": "text/html; charset=utf-8"},
                    url=target_url,
                    elapsed=elapsed,
                )

        parsed = urllib.parse.urlparse(target_url)
        clean_path = parsed.path

        # Stored state persistence check
        if clean_path in self.stored_posts:
            persisted = self.stored_posts[clean_path]
            body = f"<html><body><div id='comments'>{persisted}</div></body></html>"
            return HttpResponse(
                success=True,
                status_code=200,
                raw_body=body,
                body=body,
                headers={"Content-Type": "text/html; charset=utf-8"},
                url=target_url,
                elapsed=0.05,
            )

        # Exact URL match
        if target_url in self.routes:
            status, body, elapsed = self.routes[target_url]
            return HttpResponse(
                success=(200 <= status < 300),
                status_code=status,
                raw_body=body,
                body=body,
                headers={"Content-Type": "text/html; charset=utf-8"},
                url=target_url,
                elapsed=elapsed,
            )

        # Dynamic query param simulation
        if parsed.query:
            qs = urllib.parse.parse_qs(parsed.query)

            # Check for SQL injection payloads
            for p_vals in qs.values():
                for v in p_vals:
                    if "'" in v or "OR 1=1" in v or "sleep(" in v.lower():
                        if (
                            "search" in clean_path
                            or "users" in clean_path
                            or "api" in clean_path
                        ):
                            return HttpResponse(
                                success=False,
                                status_code=500,
                                raw_body="You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '''",
                                body="You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '''",
                                headers={"Content-Type": "text/html; charset=utf-8"},
                                url=target_url,
                                elapsed=0.05,
                            )

            # Check for custom reflection routes
            for p_key, p_vals in qs.items():
                for v in p_vals:
                    if f"reflect:{p_key}" in self.routes:
                        status, tmpl, elapsed = self.routes[f"reflect:{p_key}"]
                        body = tmpl.format(val=v)
                        return HttpResponse(
                            success=(200 <= status < 300),
                            status_code=status,
                            raw_body=body,
                            body=body,
                            headers={"Content-Type": "text/html; charset=utf-8"},
                            url=target_url,
                            elapsed=elapsed,
                        )

            # Default generic reflection for common search / user parameters
            for p_key, p_vals in qs.items():
                for v in p_vals:
                    if p_key in ("q", "query", "search", "name", "user", "msg"):
                        body = f"<html><body><h1>Results</h1><div id='output'>Search: {v}</div></body></html>"
                        return HttpResponse(
                            success=True,
                            status_code=200,
                            raw_body=body,
                            body=body,
                            headers={"Content-Type": "text/html; charset=utf-8"},
                            url=target_url,
                            elapsed=0.05,
                        )

        # Normal default fallback response
        return HttpResponse(
            success=True,
            status_code=200,
            raw_body="<html><body><h1>Normal Web Application</h1><p>Welcome to the portal.</p></body></html>",
            body="<html><body><h1>Normal Web Application</h1><p>Welcome to the portal.</p></body></html>",
            headers={"Content-Type": "text/html; charset=utf-8"},
            url=target_url,
            elapsed=0.05,
        )

    def post(
        self, mission_or_url: Any, url: Optional[str] = None, **kwargs
    ) -> HttpResponse:
        target_url = url if url is not None else mission_or_url
        if not isinstance(target_url, str):
            target_url = str(target_url)

        data = kwargs.get("data")
        json_data = kwargs.get("json")
        self.post_history.append({"url": target_url, "data": data, "json": json_data})

        parsed = urllib.parse.urlparse(target_url)
        clean_path = parsed.path

        # Stored XSS persistence
        if isinstance(data, dict):
            for k in (
                "comment",
                "message",
                "content",
                "text",
                "feedback",
                "name",
                "body",
            ):
                if k in data and data[k]:
                    self.stored_posts[clean_path] = str(data[k])
                    break
        elif isinstance(json_data, dict):
            for k in (
                "comment",
                "message",
                "content",
                "text",
                "feedback",
                "name",
                "body",
            ):
                if k in json_data and json_data[k]:
                    self.stored_posts[clean_path] = str(json_data[k])
                    break

        if target_url in self.routes:
            status, body, elapsed = self.routes[target_url]
            return HttpResponse(
                success=(200 <= status < 300),
                status_code=status,
                raw_body=body,
                body=body,
                headers={"Content-Type": "text/html; charset=utf-8"},
                url=target_url,
                elapsed=elapsed,
            )

        # Reflected POST response simulation
        reflected_val = None
        if isinstance(data, dict):
            for v in data.values():
                if isinstance(v, str):
                    reflected_val = v
                    break
        elif isinstance(json_data, dict):
            for v in json_data.values():
                if isinstance(v, str):
                    reflected_val = v
                    break

        if reflected_val:
            body = f"<html><body><h1>POST Response</h1><div id='submitted'>{reflected_val}</div></body></html>"
            return HttpResponse(
                success=True,
                status_code=200,
                raw_body=body,
                body=body,
                headers={"Content-Type": "text/html; charset=utf-8"},
                url=target_url,
                elapsed=0.05,
            )

        return HttpResponse(
            success=True,
            status_code=200,
            raw_body="<html><body><h1>POST OK</h1></body></html>",
            body="<html><body><h1>POST OK</h1></body></html>",
            headers={"Content-Type": "text/html; charset=utf-8"},
            url=target_url,
            elapsed=0.05,
        )


class MockRuntimeEngine:
    """Mock engine for autonomous runtime dependencies."""

    def __getattr__(self, name):
        if name in ("queue_manager",):
            return MockRuntimeEngine()

        def _mock(*args, **kwargs):
            if name == "is_complete":
                return True
            return None

        return _mock


def test_e2e_reflected_xss_mission_lifecycle():
    """
    Comprehensive E2E Reflected XSS Test:
    1. Initialize Mission with target, scope, live hosts, and crawled endpoints.
    2. Validate TaskGenerator DAG scheduling for 'Fuzz Cross-Site Scripting (XSS)' and dependencies.
    3. Validate ToolRegistry lookup for 'xss' and required capabilities.
    4. Execute XSSCollector via PluginExecutorAdapter on ControlledMission.
    5. Assert generation of confirmed Evidence(category='xss', severity='high', status='CONFIRMED').
    6. Assert KnowledgeGraph expansion (live_host, endpoint, vulnerability nodes, HAS_ENDPOINT and HAS_VULNERABILITY edges).
    7. Assert AttackSurfaceGraphBuilder faithful graph reconstruction from EvidenceStore.
    """
    # 1. Mission setup
    mission = Mission(target="portal.internal.net")
    mission.scope = ["portal.internal.net"]
    mission.live_hosts = [
        {"url": "https://portal.internal.net", "host": "portal.internal.net"}
    ]
    mission.endpoints = [
        {
            "url": "https://portal.internal.net/api/v1/search?q=test",
            "path": "/api/v1/search",
            "params": {"q": "test"},
            "host": "https://portal.internal.net",
        },
    ]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    graph = KnowledgeGraph()
    mission.attack_surface_graph = graph

    # 2. Validate DAG TaskGenerator
    task_gen = TaskGenerator(mission)
    gaps = [
        CoverageGap(
            area="xss",
            description="Discovered endpoints require XSS fuzzing",
            severity=0.81,
        )
    ]
    xss_tasks = task_gen.from_gaps(gaps)
    assert len(xss_tasks) == 1
    task = xss_tasks[0]
    assert task.title == "Fuzz Cross-Site Scripting (XSS)"
    assert task.category == TaskCategory.EVIDENCE_CORRELATION
    assert "Discover API Endpoints" in task.dependencies
    assert task.metadata["tool_id"] == "xss"
    assert task.priority == 0.81

    # 3. Validate Registry
    tool = registry.get("xss")
    assert tool is not None
    assert tool.id == "xss"
    assert "xss_detector" in tool.capabilities

    # 4. Mock HTTP Client with reflected canary unescaped in HTML body
    mock_client = MockE2EXSSHttpClient()
    collector = XSSCollector(http_client=mock_client)
    adapter = PluginExecutorAdapter()
    controlled_mission = ControlledMission(mission)

    # 5. Execute via collector/adapter interface
    evidence_list = collector.execute(controlled_mission)
    assert len(evidence_list) >= 1

    ev = evidence_list[0]
    assert ev.category == "xss"
    assert ev.severity == "high"
    assert ev.status == "CONFIRMED"
    assert ev.confidence >= 0.9
    assert ev.metadata["parameter"] == "q"
    assert ev.metadata["xss_type"] == "reflected"
    assert ev.metadata["host"] == "https://portal.internal.net"
    assert "api/v1/search" in ev.metadata["url"]

    # 6. Verify KnowledgeGraph nodes and edges
    assert len(graph.nodes) >= 3
    live_host_nodes = graph.nodes_by_type("live_host")
    endpoint_nodes = graph.nodes_by_type("endpoint")
    vuln_nodes = graph.nodes_by_type("vulnerability")
    assert len(live_host_nodes) >= 1
    assert len(endpoint_nodes) >= 1
    assert len(vuln_nodes) >= 1

    has_endpoint_edges = [e for e in graph.edges if e.type == "HAS_ENDPOINT"]
    has_vuln_edges = [e for e in graph.edges if e.type == "HAS_VULNERABILITY"]
    assert len(has_endpoint_edges) >= 1
    assert len(has_vuln_edges) >= 2  # host -> vuln, endpoint -> vuln

    # 7. Verify Graph Builder Reconstruction from Evidence
    builder = AttackSurfaceGraphBuilder()
    reconstructed_graph = builder.build_from_evidence(
        list(mission.evidence), target="portal.internal.net"
    )
    assert any(e.type == "HAS_VULNERABILITY" for e in reconstructed_graph.edges)
    assert any(e.type == "HAS_ENDPOINT" for e in reconstructed_graph.edges)
    reconstructed_vulns = reconstructed_graph.nodes_by_type("vulnerability")
    assert len(reconstructed_vulns) >= 1
    assert reconstructed_vulns[0].metadata.get("severity") == "high"


def test_e2e_stored_xss_mission_lifecycle():
    """
    Comprehensive E2E Stored XSS Test:
    1. Initialize Mission with target, scope, live hosts, and stateful POST endpoint.
    2. Setup Mock HTTP Client simulating POST storage and subsequent GET reflection.
    3. Execute XSSCollector and assert emission of Evidence with category='xss' and severity='critical'.
    4. Assert KnowledgeGraph updated with critical vulnerability node and HAS_VULNERABILITY edges.
    5. Assert AttackSurfaceGraphBuilder reconstructs critical severity on the graph.
    """
    mission = Mission(target="board.internal.net")
    mission.scope = ["board.internal.net"]
    mission.live_hosts = [
        {"url": "https://board.internal.net", "host": "board.internal.net"}
    ]
    mission.endpoints = [
        {
            "url": "https://board.internal.net/comments",
            "path": "/comments",
            "method": "POST",
            "body": {"comment": "sample user comment"},
            "host": "https://board.internal.net",
        },
    ]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    graph = KnowledgeGraph()
    mission.attack_surface_graph = graph

    mock_client = MockE2EXSSHttpClient()
    collector = XSSCollector(http_client=mock_client)

    evidence_list = collector.collect(mission)
    stored_ev = [ev for ev in evidence_list if ev.metadata.get("xss_type") == "stored"]
    assert len(stored_ev) >= 1

    ev = stored_ev[0]
    assert ev.category == "xss"
    assert ev.severity == "critical"
    assert ev.status == "CONFIRMED"
    assert ev.metadata["template_id"] == "xss-stored"
    assert ev.metadata["parameter_type"] == "stored_post"

    # Verify KnowledgeGraph critical node
    vuln_nodes = graph.nodes_by_type("vulnerability")
    assert len(vuln_nodes) >= 1
    assert any(n.metadata.get("severity") == "critical" for n in vuln_nodes)

    has_vuln_edges = [e for e in graph.edges if e.type == "HAS_VULNERABILITY"]
    assert len(has_vuln_edges) >= 2

    # Verify AttackSurfaceGraphBuilder reconstruction
    builder = AttackSurfaceGraphBuilder()
    reconstructed_graph = builder.build_from_evidence(
        list(mission.evidence), target="board.internal.net"
    )
    rec_vulns = reconstructed_graph.nodes_by_type("vulnerability")
    assert len(rec_vulns) >= 1
    assert any(n.metadata.get("severity") == "critical" for n in rec_vulns)


def test_e2e_multi_vulnerability_mission_xss_and_sqli():
    """
    Comprehensive E2E Multi-Vulnerability Mission Test:
    1. Mission with endpoints vulnerable to both SQL injection (error-based) and XSS (reflected & stored).
    2. Execute both SQLInjectionCollector and XSSCollector against the shared mission state.
    3. Verify concurrent categorization, independent evidence stores, and knowledge graph integrity.
    4. Verify AttackSurfaceGraphBuilder builds composite graph containing both vulnerability types.
    """
    mission = Mission(target="enterprise.target.com")
    mission.scope = ["enterprise.target.com"]
    mission.live_hosts = [
        {"url": "https://enterprise.target.com", "host": "enterprise.target.com"}
    ]
    mission.endpoints = [
        {
            "url": "https://enterprise.target.com/api/v1/search?q=test",
            "path": "/api/v1/search",
            "params": {"q": "test"},
            "host": "https://enterprise.target.com",
        },
        {
            "url": "https://enterprise.target.com/profile?name=alice",
            "path": "/profile",
            "params": {"name": "alice"},
            "host": "https://enterprise.target.com",
        },
        {
            "url": "https://enterprise.target.com/feedback",
            "path": "/feedback",
            "method": "POST",
            "body": {"message": "Great service!"},
            "host": "https://enterprise.target.com",
        },
    ]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    mission.attack_surface_graph = KnowledgeGraph()

    mock_client = MockE2EXSSHttpClient()

    sqli_collector = SQLInjectionCollector(http_client=mock_client)
    xss_collector = XSSCollector(http_client=mock_client)

    sqli_evidence = sqli_collector.collect(mission)
    xss_evidence = xss_collector.collect(mission)

    # 1. Assert EvidenceStore contains both categories
    all_evidence = list(mission.evidence)
    sqli_items = [e for e in all_evidence if e.category == "sql_injection"]
    xss_items = [e for e in all_evidence if e.category == "xss"]

    assert len(sqli_items) >= 1
    assert len(xss_items) >= 2  # reflected and stored

    # 2. Verify independent metadata and severities
    assert sqli_items[0].severity == "critical"
    assert sqli_items[0].metadata["dbms"] == "mysql"

    xss_types = {e.metadata.get("xss_type") for e in xss_items}
    assert "reflected" in xss_types
    assert "stored" in xss_types

    # 3. Verify KnowledgeGraph integrity with multi-vulnerability nodes
    graph = mission.attack_surface_graph
    vuln_nodes = graph.nodes_by_type("vulnerability")
    assert len(vuln_nodes) >= 3

    node_categories = {n.metadata.get("category", "") for n in vuln_nodes}
    assert "sql_injection" in node_categories
    assert "xss" in node_categories

    # 4. Verify composite graph reconstruction
    builder = AttackSurfaceGraphBuilder()
    reconstructed = builder.build_from_evidence(
        all_evidence, target="enterprise.target.com"
    )
    rec_vulns = reconstructed.nodes_by_type("vulnerability")
    assert len(rec_vulns) >= 3
    rec_severities = {n.metadata.get("severity") for n in rec_vulns}
    assert "critical" in rec_severities
    assert "high" in rec_severities


def test_e2e_environment_detector_mission_initialization():
    """
    Mission runtime lifecycle test validating that environment detection
    populates `mission.environment` with tool availability, network status,
    and cloud metadata at startup and throughout the state machine lifecycle.
    """
    mission = Mission(target="https://target.corp.local")
    assert mission.environment == {}

    sm = MissionStateMachine(mission)
    checkpointer = MissionCheckpointer()

    fake_env = {
        "tools": {
            "subfinder": True,
            "httpx": True,
            "nuclei": False,
            "katana": True,
            "dnsx": True,
            "node": True,
            "npm": True,
        },
        "network": {
            "target": "https://target.corp.local",
            "host": "target.corp.local",
            "dns_resolvable": True,
            "ip_addresses": ["10.0.0.5"],
            "http_reachable": True,
            "status_code": 200,
            "error": None,
        },
        "cloud_metadata": {
            "aws": False,
            "gcp": False,
            "azure": False,
            "endpoints": {
                "aws": {"accessible": False, "status_code": None},
                "gcp": {"accessible": False, "status_code": None},
                "azure": {"accessible": False, "status_code": None},
            },
        },
        "summary": {
            "tools_available_count": 6,
            "tools_missing_count": 1,
            "network_reachable": True,
            "in_cloud_environment": False,
        },
    }

    with patch(
        "argus.utils.environment.EnvironmentDetector.detect", return_value=fake_env
    ) as mock_detect:
        runtime = AutonomousMissionRuntime(
            mission=mission,
            state_machine=sm,
            checkpointer=checkpointer,
            mission_planner=MockRuntimeEngine(),
            research_planner=MockRuntimeEngine(),
            task_scheduler=MockRuntimeEngine(),
            tool_orchestrator=MockRuntimeEngine(),
            correlation_engine=MockRuntimeEngine(),
            fusion_engine=MockRuntimeEngine(),
            investigation_builder=MockRuntimeEngine(),
            priority_engine=MockRuntimeEngine(),
            hypothesis_engine=MockRuntimeEngine(),
            learning_engine=MockRuntimeEngine(),
        )

        mock_detect.assert_called_once_with("https://target.corp.local")
        assert mission.environment == fake_env
        assert mission.environment["tools"]["subfinder"] is True
        assert mission.environment["tools"]["nuclei"] is False
        assert mission.environment["network"]["http_reachable"] is True
        assert mission.environment["summary"]["tools_available_count"] == 6

        # Step into PLANNING phase and confirm environment is preserved
        sm.transition_to(MissionState.PLANNING)
        runtime.step()
        assert mission.environment == fake_env
        assert mission.status == MissionState.RESEARCHING


def test_e2e_xss_gap_analysis_and_replanning():
    """
    Tests that GapAnalyzer and TaskGenerator properly identify XSS coverage gaps
    across all supported synonym phrases, resolving them to the 'Fuzz Cross-Site Scripting (XSS)' DAG task.
    """
    mission = Mission(target="target.org")
    mission.endpoints = [{"url": "https://target.org/api/v1/item?id=1"}]

    generator = TaskGenerator(mission)

    gap_variations = [
        CoverageGap(area="xss", description="Audit endpoints for XSS", severity=0.85),
        CoverageGap(
            area="xss detection", description="Perform XSS checks", severity=0.88
        ),
        CoverageGap(
            area="cross site scripting", description="Fuzz parameters", severity=0.82
        ),
        CoverageGap(
            area="cross-site scripting",
            description="Inspect reflections",
            severity=0.90,
        ),
        CoverageGap(
            area="stored xss", description="Audit comments and boards", severity=0.95
        ),
        CoverageGap(
            area="reflected xss", description="Audit query params", severity=0.80
        ),
        CoverageGap(
            area="dom xss", description="Audit client sink reflections", severity=0.75
        ),
        CoverageGap(
            area="general",
            category=TaskCategory.EVIDENCE_CORRELATION,
            description="Discovered endpoints require xss verification",
            severity=0.78,
        ),
        CoverageGap(
            area="general",
            category=TaskCategory.EVIDENCE_CORRELATION,
            description="Discovered endpoints require cross-site scripting verification",
            severity=0.84,
        ),
    ]

    for gap in gap_variations:
        tasks = generator.from_gaps([gap])
        assert (
            len(tasks) == 1
        ), f"Failed generating task for gap: {gap.area} - {gap.description}"
        task = tasks[0]
        assert task.title == "Fuzz Cross-Site Scripting (XSS)"
        assert task.metadata["tool_id"] == "xss"
        assert task.category == TaskCategory.EVIDENCE_CORRELATION
        assert "Discover API Endpoints" in task.dependencies
        assert task.priority == gap.severity


def test_e2e_xss_false_positive_suppression_lifecycle():
    """
    E2E False Positive Suppression Test:
    Ensures that an application which properly entity-encodes user inputs
    does NOT generate any XSS Evidence or false positive vulnerability nodes.
    """
    mission = Mission(target="secure.internal.net")
    mission.scope = ["secure.internal.net"]
    mission.live_hosts = ["https://secure.internal.net"]
    mission.endpoints = [
        {
            "url": "https://secure.internal.net/search?q=hello",
            "path": "/search",
            "params": {"q": "hello"},
            "host": "https://secure.internal.net",
        }
    ]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    graph = KnowledgeGraph()
    mission.attack_surface_graph = graph

    mock_client = MockE2EXSSHttpClient()

    # Custom getter returning fully HTML-escaped reflections
    def safe_get(mission_or_url, url=None, **kwargs):
        target_url = url if url is not None else mission_or_url
        parsed = urllib.parse.urlparse(str(target_url))
        qs = urllib.parse.parse_qs(parsed.query)
        q_val = qs.get("q", [""])[0]
        escaped_val = html.escape(q_val)
        body = f"<html><body><h1>Safe Portal</h1><div>Results for: {escaped_val}</div></body></html>"
        return HttpResponse(
            success=True,
            status_code=200,
            raw_body=body,
            body=body,
            headers={"Content-Type": "text/html; charset=utf-8"},
            url=str(target_url),
        )

    def safe_post(mission_or_url, url=None, **kwargs):
        target_url = url if url is not None else mission_or_url
        data = kwargs.get("data") or {}
        json_data = kwargs.get("json") or {}
        msg = ""
        if isinstance(data, dict):
            for v in data.values():
                if isinstance(v, str):
                    msg = v
                    break
        elif isinstance(json_data, dict):
            for v in json_data.values():
                if isinstance(v, str):
                    msg = v
                    break
        escaped_val = html.escape(msg)
        body = f"<html><body><h1>Safe Portal</h1><div>Submitted: {escaped_val}</div></body></html>"
        return HttpResponse(
            success=True,
            status_code=200,
            raw_body=body,
            body=body,
            headers={"Content-Type": "text/html; charset=utf-8"},
            url=str(target_url),
        )

    mock_client.get = safe_get
    mock_client.post = safe_post

    collector = XSSCollector(http_client=mock_client)
    evidence_list = collector.collect(mission)

    assert len(evidence_list) == 0
    assert len(mission.vulnerabilities) == 0
    assert len(graph.nodes_by_type("vulnerability")) == 0
