"""
End-to-End integration tests for OAuth/OIDC Token Testing & Stateful Auth Validation Engine.
Validates TaskGenerator DAG scheduling, ToolRegistry lookup & aliases, PluginExecutorAdapter dispatch,
KnowledgeGraph expansion, and AttackSurfaceGraphBuilder reconstruction.
"""
from typing import Any, Dict, List, Optional
import pytest

from argus.collectors.oauth import OAuthCollector, OAuthPayloadGenerator
from argus.evidence.store import EvidenceStore
from argus.graph.attack_surface import AttackSurfaceGraphBuilder
from argus.graph.graph import KnowledgeGraph
from argus.planning.models import CoverageGap, TaskCategory
from argus.planning.task_generator import TaskGenerator, _RECON_TEMPLATES
from argus.plugins.interfaces import ControlledMission
from argus.runtime.mission import Mission
from argus.runtime.plugins import PluginExecutorAdapter
from argus.runtime.registry import registry
from tests.collectors.test_oauth import MockOAuthHttpClient


def test_e2e_oauth_task_generator_dag_generation():
    """
    R4: Validates that TaskGenerator creates 'Analyze OAuth & OIDC Authentication'
    task from coverage gaps and orders dependencies after 'Discover API Endpoints'.
    """
    mission = Mission(target="oauth.target.com")
    mission.live_hosts = ["https://oauth.target.com"]
    mission.endpoints = [{"url": "https://oauth.target.com/oauth/authorize"}]

    generator = TaskGenerator(mission)
    gap = CoverageGap(
        area="oauth",
        description="Unassessed OAuth and OIDC authentication endpoints",
        category=TaskCategory.AUTHORIZATION_ANALYSIS,
        severity=0.85,
    )

    tasks = generator.from_gaps([gap])
    assert len(tasks) == 1
    task = tasks[0]
    assert task.title == "Analyze OAuth & OIDC Authentication"
    assert "Discover API Endpoints" in task.dependencies
    assert task.metadata.get("tool_id") == "oauth"


def test_e2e_oauth_task_generator_recon_pipeline_integration():
    """R4: Validates template lookup in _RECON_TEMPLATES for OAuth/OIDC."""
    assert "oauth" in _RECON_TEMPLATES
    tmpl = _RECON_TEMPLATES["oauth"]
    assert tmpl["title"] == "Analyze OAuth & OIDC Authentication"
    assert "Discover API Endpoints" in tmpl["dependencies"]
    assert tmpl["metadata"]["tool_id"] == "oauth"
    assert tmpl["priority"] >= 0.80


def test_e2e_oauth_tool_registry_and_aliases():
    """R4: Validates ToolRegistry registration and aliases for oauth."""
    tool = registry.get("oauth")
    assert tool is not None
    assert tool.id == "oauth"
    assert tool.priority == 95

    # Check aliases
    assert registry.get("oauth_oidc") is not None
    assert registry.get("oidc") is not None
    assert registry.get("oauth_collector") is not None
    assert registry.get("oidc_collector") is not None


def test_e2e_oauth_plugin_executor_adapter_dispatch():
    """R4: Validates PluginExecutorAdapter instantiates and dispatches OAuthCollector."""
    adapter = PluginExecutorAdapter()
    mission = Mission(target="oauth.target.com")
    mission.endpoints = [{"url": "https://oauth.target.com/oauth/authorize"}]
    mission.live_hosts = ["https://oauth.target.com"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    mission.attack_surface_graph = KnowledgeGraph()

    # Fallback instantiation
    collector = adapter._instantiate_specialist_fallback("oauth")
    assert collector is not None
    assert isinstance(collector, OAuthCollector)

    collector_oidc = adapter._instantiate_specialist_fallback("oidc")
    assert collector_oidc is not None
    assert isinstance(collector_oidc, OAuthCollector)


def test_e2e_oauth_attack_surface_graph_reconstruction():
    """R4: Validates AttackSurfaceGraphBuilder reconstruction for OAuth and Session findings."""
    mission = Mission(target="oauth.target.com")
    mission.endpoints = [{"url": "https://oauth.target.com/oauth/authorize"}]
    mission.live_hosts = ["https://oauth.target.com"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    mission.attack_surface_graph = KnowledgeGraph()

    client = MockOAuthHttpClient()
    client.set_route(
        "redirect_uri=https%3A%2F%2Fattacker.com%2Fcallback",
        302,
        "",
        headers={"Location": "https://attacker.com/callback?code=CODE123"},
    )

    collector = OAuthCollector(http_client=client)
    collector.collect(mission)

    # Reconstruct graph from mission evidence
    builder = AttackSurfaceGraphBuilder()
    reconstructed = builder.build_from_evidence(list(mission.evidence), target="oauth.target.com")

    # Verify tripartite connectivity: live_host, endpoint, vulnerability
    assert len(reconstructed.nodes_by_type("live_host")) >= 1
    assert len(reconstructed.nodes_by_type("endpoint")) >= 1
    assert len(reconstructed.nodes_by_type("vulnerability")) >= 1

    has_endpoint = [e for e in reconstructed.edges if e.type == "HAS_ENDPOINT"]
    has_vuln = [e for e in reconstructed.edges if e.type == "HAS_VULNERABILITY"]

    assert len(has_endpoint) >= 1
    assert len(has_vuln) >= 2


def test_e2e_oauth_full_mission_loop_execution():
    """
    R5: Validates full end-to-end mission loop:
    1. Coverage gap identifies OAuth endpoints
    2. TaskGenerator schedules OAuth task
    3. ToolDispatcher / PluginAdapter executes OAuthCollector
    4. Evidence and vulnerabilities recorded
    5. KnowledgeGraph updated with HAS_VULNERABILITY edges.
    """
    mission = Mission(target="auth.target.com")
    mission.live_hosts = ["https://auth.target.com"]
    mission.endpoints = [
        {"url": "https://auth.target.com/oauth/authorize"},
        {"url": "https://auth.target.com/api/user/profile"},
    ]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    mission.attack_surface_graph = KnowledgeGraph()

    # Step 1: Task generation
    generator = TaskGenerator(mission)
    gap = CoverageGap(
        area="oauth",
        description="OAuth token validation coverage gap",
        category=TaskCategory.AUTHENTICATION_ANALYSIS,
        severity=0.9,
    )
    tasks = generator.from_gaps([gap])
    assert len(tasks) >= 1
    assert tasks[0].metadata.get("tool_id") == "oauth"

    # Step 2: Collector execution with mock responses
    client = MockOAuthHttpClient()
    # alg:none token route
    gen = OAuthPayloadGenerator()
    alg_none_token = next(p["token"] for p in gen.generate_tampered_jwt_payloads() if p["type"] == "alg_none")
    client.set_route(
        f"auth:Bearer {alg_none_token}",
        200,
        '{"user": "admin", "role": "superuser"}',
        headers={"Content-Type": "application/json"},
    )

    collector = OAuthCollector(http_client=client)
    controlled_mission = ControlledMission(mission)
    evidence = collector.execute(controlled_mission)

    # Step 3: Verify results
    assert len(evidence) >= 1
    assert len(mission.vulnerabilities) >= 1

    # Step 4: Verify attack surface graph connectivity
    graph = mission.attack_surface_graph
    assert len(graph.nodes_by_type("vulnerability")) >= 1
    assert any(e.type == "HAS_VULNERABILITY" for e in graph.edges)
