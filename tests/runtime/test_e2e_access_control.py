"""
End-to-End integration tests for Sprint 6 Access Control / IDOR Engine.
Validates Mission Loop integration, TaskGenerator scheduling, PluginExecutorAdapter dispatch,
KnowledgeGraph expansion, and AttackSurfaceGraphBuilder reconstruction.
"""
import json
from typing import Optional, Any, Dict, List, Set
import pytest


from argus.collectors.access_control import AccessControlCollector
from argus.evidence.store import EvidenceStore
from argus.graph.attack_surface import AttackSurfaceGraphBuilder
from argus.graph.graph import KnowledgeGraph
from argus.models.test_identity import TestIdentity, AuthType
from argus.planning.gap_analysis import GapAnalyzer
from argus.planning.models import CoverageGap, TaskCategory
from argus.planning.task_generator import TaskGenerator
from argus.runtime.mission import Mission
from argus.runtime.plugins import PluginExecutorAdapter
from argus.runtime.registry import registry
from argus.http.client import HttpResponse


class MockE2EAccessControlHttpClient:
    """Mock HTTP client simulating real IDOR, vertical escalation, and header bypass behaviors."""

    def __init__(self):
        self.routes = {
            # Horizontal IDOR on /api/v1/users/user_101/account: both user_101 and user_102 receive user_101's account data
            "https://api.target.corp/api/v1/users/user_101/account": {
                "status": 200,
                "body": json.dumps({
                    "id": "user_101",
                    "name": "Alice Target",
                    "email": "alice@target.corp",
                    "balance": 150000,
                    "account_number": "ACC-9988-7766",
                    "role": "customer",
                }),
            },
            # Vertical Privilege Escalation on /api/admin/system: accessible by standard unprivileged user
            "https://api.target.corp/api/admin/system": {
                "status": 200,
                "body": json.dumps({
                    "system_status": "ONLINE",
                    "active_connections": 420,
                    "database_pool": "postgres://master:sec@internal:5432/main",
                    "maintenance_mode": False,
                    "cluster_nodes": ["node1.internal", "node2.internal"],
                }),
            },
            # Protected route: returns 403 on direct access, but 200 on X-Original-URL header
            "https://api.target.corp/management/users": {
                "status": 403,
                "body": json.dumps({"error": "Forbidden: Access restricted to internal network"}),
            },
        }

    def execute_as(self, identity, mission, method, url, headers=None, **kwargs):
        req_headers = dict(headers or {})

        # Check header bypass
        if "X-Original-URL" in req_headers and req_headers["X-Original-URL"] == "/management/users":
            return HttpResponse(
                success=True,
                status_code=200,
                raw_body=json.dumps({"users": ["admin@target.corp", "devops@target.corp"], "count": 2}),
                body=json.dumps({"users": ["admin@target.corp", "devops@target.corp"], "count": 2}),
                url=url,
            )

        if url in self.routes:
            r = self.routes[url]
            return HttpResponse(
                success=True,
                status_code=r["status"],
                raw_body=r["body"],
                body=r["body"],
                url=url,
            )

        return HttpResponse(success=False, status_code=404, error="Not Found", url=url)


def test_e2e_access_control_mission_loop_flow():
    """
    Comprehensive E2E test:
    1. Initialize Mission with target, scope, multiple TestIdentities (Alice, Bob, Admin), live hosts, and endpoints.
    2. Validate TaskGenerator recon pipeline includes 'Analyze Access Control & IDOR'.
    3. Validate ToolRegistry has 'access_control' registered with correct capability.
    4. Execute AccessControlCollector with MockE2EAccessControlHttpClient.
    5. Assert generation of confirmed 'broken_access_control' Evidence with critical severity.
    6. Assert KnowledgeGraph has nodes for live_host, endpoint, vulnerability and edges (HAS_ENDPOINT, HAS_VULNERABILITY).
    7. Assert AttackSurfaceGraphBuilder faithfully reconstructs graph from EvidenceStore.
    """
    # 1. Mission setup
    mission = Mission(target="target.corp")
    mission.scope = ["target.corp", "api.target.corp"]
    mission.live_hosts = [{"url": "https://api.target.corp", "host": "api.target.corp"}]
    mission.endpoints = [
        {"url": "https://api.target.corp/api/v1/users/user_101/account"},
        {"url": "https://api.target.corp/api/admin/system"},
        {"url": "https://api.target.corp/management/users"},
    ]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    graph = KnowledgeGraph()
    mission.attack_surface_graph = graph

    # Test Identities
    alice = TestIdentity(
        id="user_101",
        name="Alice Target",
        role="customer",
        auth_type=AuthType.BEARER,
        token="jwt_alice_101",
        credentials={"email": "alice@target.corp", "user_id": "user_101"},
    )
    bob = TestIdentity(
        id="user_102",
        name="Bob Attacker",
        role="customer",
        auth_type=AuthType.BEARER,
        token="jwt_bob_102",
        credentials={"email": "bob@target.corp", "user_id": "user_102"},
    )
    admin = TestIdentity(
        id="admin_001",
        name="Admin Operator",
        role="admin",
        auth_type=AuthType.BEARER,
        token="jwt_admin_001",
        credentials={"email": "admin@target.corp", "user_id": "admin_001"},
    )
    mission.test_identities = [alice, bob, admin]

    # 2. Task Generator Recon Template & Gap Resolution Verification
    from argus.planning.task_generator import _RECON_TEMPLATES
    assert "access_control" in _RECON_TEMPLATES
    ac_template = _RECON_TEMPLATES["access_control"]
    assert ac_template["category"] == TaskCategory.AUTHORIZATION_ANALYSIS
    assert ac_template["dependencies"] == ["Discover API Endpoints"]
    assert ac_template["priority"] == 0.81
    assert ac_template["metadata"]["tool_id"] == "access_control"

    task_gen = TaskGenerator(mission)
    ac_gap = CoverageGap(area="Access Control", description="Probe broken access control & IDOR", category=TaskCategory.AUTHORIZATION_ANALYSIS)
    gap_tasks = task_gen.from_gaps([ac_gap])
    assert len(gap_tasks) == 1
    ac_task = gap_tasks[0]
    assert ac_task.title == "Analyze Access Control & IDOR"
    assert ac_task.category == TaskCategory.AUTHORIZATION_ANALYSIS
    assert "Discover API Endpoints" in ac_task.dependencies
    assert ac_task.metadata.get("tool_id") == "access_control"


    # 3. Tool Registry Verification
    registered_tool = registry.get("access_control")
    assert registered_tool is not None
    assert registered_tool.capability == "access_control_collector"
    assert "Authorization Analysis" in registered_tool.supported_tasks

    # 4. Collector Execution
    mock_client = MockE2EAccessControlHttpClient()
    collector = AccessControlCollector(http_client=mock_client)
    evidence_list = collector.collect(mission)

    # 5. Assert Evidence Generation
    assert len(evidence_list) >= 3, f"Expected at least 3 BAC evidence items, got {len(evidence_list)}"

    categories = {e.category for e in evidence_list}
    assert "broken_access_control" in categories

    severities = {e.severity for e in evidence_list}
    assert "critical" in severities

    discrepancy_types = {e.metadata.get("discrepancy_type") for e in evidence_list}
    assert "horizontal_idor" in discrepancy_types
    assert "vertical_privilege_escalation" in discrepancy_types
    assert "header_bypass" in discrepancy_types

    # Validate mission vulnerabilities list
    assert len(mission.vulnerabilities) >= 3
    vuln_names = [v["name"] for v in mission.vulnerabilities]
    assert any("IDOR" in n for n in vuln_names)
    assert any("Vertical Privilege" in n for n in vuln_names)

    # 6. Validate Direct KnowledgeGraph Mutation
    assert graph.get("live_host:https://api.target.corp") is not None
    assert graph.get("endpoint:https://api.target.corp/api/v1/users/user_101/account") is not None
    assert graph.get("endpoint:https://api.target.corp/api/admin/system") is not None

    # Check edges
    assert graph.are_connected(
        "live_host:https://api.target.corp",
        "endpoint:https://api.target.corp/api/v1/users/user_101/account",
    )
    assert graph.are_connected(
        "endpoint:https://api.target.corp/api/v1/users/user_101/account",
        "vulnerability:idor-horizontal-privilege-escalation:https://api.target.corp/api/v1/users/user_101/account",
    )
    assert graph.are_connected(
        "live_host:https://api.target.corp",
        "vulnerability:idor-horizontal-privilege-escalation:https://api.target.corp/api/v1/users/user_101/account",
    )

    # 7. Validate AttackSurfaceGraphBuilder reconstruction
    builder = AttackSurfaceGraphBuilder()
    rebuilt_graph = builder.build_from_evidence(mission.evidence, target="target.corp")

    assert rebuilt_graph.get("endpoint:https://api.target.corp/api/v1/users/user_101/account") is not None
    assert rebuilt_graph.get("vulnerability:idor-horizontal-privilege-escalation:https://api.target.corp/api/v1/users/user_101/account") is not None
    assert rebuilt_graph.are_connected(
        "endpoint:https://api.target.corp/api/v1/users/user_101/account",
        "vulnerability:idor-horizontal-privilege-escalation:https://api.target.corp/api/v1/users/user_101/account",
    )


def test_plugin_executor_adapter_executes_access_control():
    """Verifies that PluginExecutorAdapter dynamically resolves and executes AccessControlCollector."""
    adapter = PluginExecutorAdapter()
    mission = Mission(target="example.com")
    mission.live_hosts = ["https://example.com"]
    mission.endpoints = ["https://example.com/api/users/123/profile"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []

    res = adapter.execute_plugin("access_control", mission)
    assert res["status"] == "success"
    assert isinstance(res["plugin_instance"], AccessControlCollector)
