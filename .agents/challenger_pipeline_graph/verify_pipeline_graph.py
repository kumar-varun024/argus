#!/usr/bin/env python3
"""
Empirical Verification & Stress Test Harness for Sprint 17 (GraphQL Security).
Challenger 2: Pipeline & Graph State Challenger.

Tests:
1. DAG Task Generation & Dependency Resolution (task_generator.py)
2. Tool Registry & Alias Resolution (registry.py)
3. Plugin Executor Adapter & Fallback Instantiation (plugins.py)
4. Full Mission Lifecycle Simulation with ControlledMission & KnowledgeGraph
5. AttackSurfaceGraph Node/Edge Integrity & Section 18 Verification
6. CVSS v3.1 Calculation & CWE Mapping across all GraphQL Categories
7. Adversarial Boundary, Stress, and Edge Case Tests
"""
import sys
import os
import json
import time
import traceback
from typing import Any, Dict, List, Optional

# Ensure project root is in sys.path
sys.path.insert(0, "/home/varun/argus")

from argus.planning.models import ResearchTask, CoverageGap, TaskCategory
from argus.planning.task_generator import TaskGenerator, _RECON_TEMPLATES, _SPECIALIST_TEMPLATES
from argus.runtime.models import Tool
from argus.runtime.registry import ToolRegistry, registry
from argus.runtime.plugins import PluginExecutorAdapter
from argus.plugins.interfaces import ControlledMission
from argus.runtime.mission import Mission
from argus.evidence.store import EvidenceStore
from argus.evidence.model import Evidence
from argus.collectors.graphql import (
    GraphQLSecurityCollector,
    GraphQLCollector,
    GraphQLPayloadGenerator,
    GraphQLSecurityAnalyzer,
    GraphQLSecurityResult,
    GraphQLSeverity,
    GraphQLTechnique,
    GraphQLMutationStrategy,
)
from argus.graph.attack_surface import AttackSurfaceGraphBuilder
from argus.graph.graph import KnowledgeGraph
from argus.graph.node import Node
from argus.http.client import HttpResponse
from argus.reporting.cvss import CVSSCalculator
from argus.reporting.models import ReportSeverity, CWEInfo


def json_dumps(obj: Any) -> str:
    return json.dumps(obj)


class MockHttpServerClient:
    """Configurable mock client to simulate GraphQL server responses."""

    def __init__(self, mode: str = "vulnerable"):
        self.mode = mode
        self.call_log: List[Dict[str, Any]] = []

    def get(self, *args, **kwargs) -> HttpResponse:
        url = args[1] if len(args) > 1 else kwargs.get("url", "")
        params = kwargs.get("params", {})
        return self.request(method="GET", url=url, params=params)

    def post(self, *args, **kwargs) -> HttpResponse:
        url = args[1] if len(args) > 1 else kwargs.get("url", "")
        json_data = kwargs.get("json", None)
        data = kwargs.get("data", None)
        return self.request(method="POST", url=url, json=json_data, data=data)

    def request(
        self,
        mission: Any = None,
        method: str = "POST",
        url: str = "",
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Any] = None,
        json: Optional[Any] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        timeout: float = 10.0,
        **kwargs,
    ) -> HttpResponse:
        # Handle positional args if called as client.request(mission, method, url, ...)
        if isinstance(mission, str) and not method:
            method = mission
        self.call_log.append({
            "method": method,
            "url": url,
            "params": params,
            "data": data,
            "json": json,
            "headers": headers,
        })

        if self.mode == "hardened":
            body_str = '{"errors": [{"message": "GraphQL introspection is disabled.", "extensions": {"code": "INTROSPECTION_DISABLED"}}]}'
            return HttpResponse(
                success=False,
                status_code=400,
                raw_body=body_str,
                body=body_str,
                url=url,
                elapsed=0.05,
            )

        if self.mode == "error_500":
            body_str = "<html><body><h1>500 Internal Server Error</h1></body></html>"
            return HttpResponse(
                success=False,
                status_code=500,
                raw_body=body_str,
                body=body_str,
                url=url,
                elapsed=0.05,
            )

        # Vulnerable mode: inspect payload to return appropriate response
        query_str = ""
        if json and isinstance(json, dict):
            query_str = json.get("query", "")
        elif json and isinstance(json, list):
            # Array batching
            batch_resp = [
                {"data": {"__typename": "Query", "user": {"id": "1", "name": "Admin"}}},
                {"data": {"__typename": "Query", "user": {"id": "2", "name": "User2"}}},
                {"data": {"__typename": "Query", "user": {"id": "3", "name": "User3"}}},
            ]
            body_str = json_dumps(batch_resp)
            return HttpResponse(
                success=True,
                status_code=200,
                raw_body=body_str,
                body=body_str,
                url=url,
                elapsed=0.05,
            )
        elif data and isinstance(data, str):
            query_str = data
        elif params and "query" in params:
            query_str = str(params["query"])

        # 1. Baseline query
        if "__typename" in query_str and "__schema" not in query_str and "alias_" not in query_str:
            body_str = '{"data": {"__typename": "Query"}}'
            return HttpResponse(
                success=True,
                status_code=200,
                raw_body=body_str,
                body=body_str,
                url=url,
                elapsed=0.04,
            )

        # 2. Introspection
        if "__schema" in query_str or "_argus_schema" in query_str:
            schema_data = {
                "data": {
                    "__schema": {
                        "queryType": {"name": "Query"},
                        "mutationType": {"name": "Mutation"},
                        "types": [
                            {"name": "User", "kind": "OBJECT", "fields": [{"name": "id"}, {"name": "username"}, {"name": "email"}, {"name": "passwordHash"}]},
                            {"name": "Admin", "kind": "OBJECT", "fields": [{"name": "id"}, {"name": "secretToken"}]},
                        ],
                    }
                }
            }
            body_str = json_dumps(schema_data)
            return HttpResponse(
                success=True,
                status_code=200,
                raw_body=body_str,
                body=body_str,
                url=url,
                elapsed=0.06,
            )

        # 3. Type Introspection
        if "__type" in query_str:
            type_data = {
                "data": {
                    "__type": {
                        "name": "Query",
                        "fields": [{"name": "users"}, {"name": "adminPanel"}, {"name": "systemConfig"}],
                    }
                }
            }
            body_str = json_dumps(type_data)
            return HttpResponse(
                success=True,
                status_code=200,
                raw_body=body_str,
                body=body_str,
                url=url,
                elapsed=0.05,
            )

        # 4. Field Suggestions
        if any(f in query_str for f in ("user_name", "usr", "passwd", "auth_token")):
            body_str = '{"errors": [{"message": "Cannot query field \'user_name\' on type \'Query\'. Did you mean \'username\'?"}]}'
            return HttpResponse(
                success=True,
                status_code=200,
                raw_body=body_str,
                body=body_str,
                url=url,
                elapsed=0.05,
            )

        # 5. Query Depth recursion
        if "author" in query_str and "posts" in query_str:
            nested_data = {
                "data": {
                    "author": {
                        "posts": [
                            {"author": {"posts": [{"author": {"posts": [{"title": "Post 1"}]}}]}}
                        ]
                    }
                }
            }
            body_str = json_dumps(nested_data)
            return HttpResponse(
                success=True,
                status_code=200,
                raw_body=body_str,
                body=body_str,
                url=url,
                elapsed=0.08,
            )

        # 6. Fragment recursion
        if "fragment FragA" in query_str or "...FragA" in query_str:
            body_str = '{"errors": [{"message": "Internal Server Error: Maximum call stack size exceeded"}]}'
            return HttpResponse(
                success=False,
                status_code=500,
                raw_body=body_str,
                body=body_str,
                url=url,
                elapsed=0.10,
            )

        # 7. Alias multiplexing
        if "alias_0" in query_str:
            alias_data = {
                "data": {f"alias_{i}": {"__typename": "Query"} for i in range(20)}
            }
            body_str = json_dumps(alias_data)
            return HttpResponse(
                success=True,
                status_code=200,
                raw_body=body_str,
                body=body_str,
                url=url,
                elapsed=0.07,
            )

        # 8. Sensitive fields / BOPLA
        if any(f in query_str for f in ("admin", "users", "systemConfig", "debug", "tokens", "secrets")):
            body_str = '{"data": {"admin": {"id": "1", "role": "superuser"}, "users": [{"id": 1, "email": "admin@example.com"}], "tokens": ["tok_12345"]}}'
            return HttpResponse(
                success=True,
                status_code=200,
                raw_body=body_str,
                body=body_str,
                url=url,
                elapsed=0.05,
            )

        # 9. SQLi
        if "OR 1=1" in query_str or "SLEEP(" in query_str:
            body_str = '{"errors": [{"message": "SQL syntax error in query: near \'OR 1=1\'"}]}'
            return HttpResponse(
                success=True,
                status_code=200,
                raw_body=body_str,
                body=body_str,
                url=url,
                elapsed=0.05,
            )

        # 10. CmdI
        if "; id" in query_str or "| id" in query_str or "`id`" in query_str:
            body_str = '{"errors": [{"message": "uid=0(root) gid=0(root) groups=0(root)"}]}'
            return HttpResponse(
                success=True,
                status_code=200,
                raw_body=body_str,
                body=body_str,
                url=url,
                elapsed=0.05,
            )

        # Default fallback
        body_str = '{"data": {}}'
        return HttpResponse(
            success=True,
            status_code=200,
            raw_body=body_str,
            body=body_str,
            url=url,
            elapsed=0.04,
        )


def test_suite_dag_task_generator():
    """Verify DAG Task Generator and Dependency Resolution."""
    print("=== [Suite 1] DAG Task Generator & Dependency Resolution ===")
    mission = Mission(
        target="example.com",
        subdomains=["api.example.com", "graphql.example.com"],
        live_hosts=[{"url": "https://api.example.com"}, "https://graphql.example.com"],
        endpoints=[
            {"url": "https://api.example.com/graphql", "method": "POST"},
            {"url": "https://api.example.com/api/query", "method": "POST"},
        ],
    )
    tg = TaskGenerator(mission)

    # Test 1.1: Default Recon Tasks
    recon_tasks = tg.generate_recon_tasks()
    assert len(recon_tasks) >= 4, f"Expected >= 4 recon tasks, got {len(recon_tasks)}"
    tool_ids = [t.metadata.get("tool_id") for t in recon_tasks]
    assert "subfinder" in tool_ids
    assert "httpx" in tool_ids
    assert "katana_crawler" in tool_ids
    assert "nuclei" in tool_ids
    print("  [✓] 1.1 Default recon chain generated successfully.")

    # Test 1.2: Template Definition for graphql_security
    assert "graphql_security" in _RECON_TEMPLATES
    gql_tpl = _RECON_TEMPLATES["graphql_security"]
    assert gql_tpl["title"] == "Validate GraphQL Security"
    assert gql_tpl["dependencies"] == ["Discover API Endpoints"]
    assert gql_tpl["metadata"]["tool_id"] == "graphql_security"
    assert gql_tpl["priority"] == 0.81
    print("  [✓] 1.2 _RECON_TEMPLATES['graphql_security'] has valid title, dependencies, priority, and tool_id.")

    # Test 1.3: Resolve Template for Various Coverage Gap Areas
    test_areas = [
        ("graphql security", "Validate GraphQL Security", "graphql_security"),
        ("graphql vulnerability", "Validate GraphQL Security", "graphql_security"),
        ("graphql injection", "Validate GraphQL Security", "graphql_security"),
        ("graphql dos", "Validate GraphQL Security", "graphql_security"),
        ("graphql introspection", "Validate GraphQL Security", "graphql_security"),
        ("graphql batching", "Validate GraphQL Security", "graphql_security"),
        ("graphql query depth", "Validate GraphQL Security", "graphql_security"),
        ("graphql validation", "Validate GraphQL Security", "graphql_security"),
        ("GRAPHQL SECURITY", "Validate GraphQL Security", "graphql_security"),
    ]
    for area, expected_title, expected_tool_id in test_areas:
        gap = CoverageGap(area=area, description="Coverage gap in GraphQL probing", category=TaskCategory.EVIDENCE_CORRELATION, severity=0.85)
        tpl = tg._resolve_template_for_gap(gap)
        assert tpl["title"] == expected_title, f"For area '{area}', expected '{expected_title}', got '{tpl['title']}'"
        assert tpl["metadata"]["tool_id"] == expected_tool_id, f"For area '{area}', expected tool_id '{expected_tool_id}'"
    print(f"  [✓] 1.3 Resolved {len(test_areas)} GraphQL gap area variations to 'graphql_security'.")

    # Test 1.4: Resolve Gaps via Category Fallback
    gap_desc_test = CoverageGap(
        area="custom_findings",
        description="Active GraphQL introspection testing required",
        category=TaskCategory.EVIDENCE_CORRELATION,
        severity=0.90,
    )
    tpl_desc = tg._resolve_template_for_gap(gap_desc_test)
    assert tpl_desc["metadata"]["tool_id"] == "graphql_security"

    gap_specialist = CoverageGap(
        area="graphql schema",
        description="Analyze GraphQL schema structure",
        category=TaskCategory.GRAPHQL_ANALYSIS,
        severity=0.75,
    )
    tpl_spec = tg._resolve_template_for_gap(gap_specialist)
    assert tpl_spec["metadata"]["tool_id"] == "graphql_specialist"
    print("  [✓] 1.4 Category-based keyword heuristics properly route to graphql_security and graphql_specialist.")

    # Test 1.5: Task Generation from Gaps with and without explicit assets
    gap_with_assets = CoverageGap(
        area="graphql security",
        description="Fuzz target GraphQL endpoint",
        category=TaskCategory.EVIDENCE_CORRELATION,
        severity=0.88,
        related_assets=["https://api.example.com/v1/graphql"],
    )
    gap_without_assets = CoverageGap(
        area="graphql dos",
        description="Fuzz GraphQL query depth",
        category=TaskCategory.EVIDENCE_CORRELATION,
        severity=0.82,
    )
    tasks = tg.from_gaps([gap_with_assets, gap_without_assets])
    # Deduplication test: both resolve to same title "Validate GraphQL Security", so only 1 task generated
    assert len(tasks) == 1
    assert tasks[0].title == "Validate GraphQL Security"
    assert tasks[0].required_inputs == ["https://api.example.com/v1/graphql"]
    assert tasks[0].dependencies == ["Discover API Endpoints"]
    assert tasks[0].metadata["tool_id"] == "graphql_security"
    print("  [✓] 1.5 from_gaps deduplicates tasks by title, binds related_assets, and assigns dependencies.")


def test_suite_tool_registry():
    """Verify ToolRegistry registration, aliases, capabilities, and deterministic ordering."""
    print("\n=== [Suite 2] ToolRegistry & Alias Resolution ===")

    # Test 2.1: Direct lookup
    tool = registry.get("graphql_security")
    assert tool is not None, "Tool 'graphql_security' not found in registry"
    assert tool.id == "graphql_security"
    assert tool.priority == 95
    assert tool.safety_requirements["type"] == "internal"
    print("  [✓] 2.1 Direct lookup of 'graphql_security' retrieved valid Tool with priority 95.")

    # Test 2.2: All registered aliases
    aliases = [
        "graphql_security_collector",
        "graphql_detector",
        "graphql_vuln",
        "graphql_vulnerability",
        "graphql_introspection",
        "graphql_collector",
        "graphql_security_validator",
        "graphql_dos",
        "graphql_batching",
    ]
    for alias in aliases:
        resolved = registry.get(alias)
        assert resolved is not None, f"Alias '{alias}' failed to resolve"
        assert resolved.id == "graphql_security", f"Alias '{alias}' resolved to '{resolved.id}', expected 'graphql_security'"
    print(f"  [✓] 2.2 Successfully resolved all {len(aliases)} aliases to 'graphql_security'.")

    # Test 2.3: Capabilities lookup
    capabilities = [
        "graphql_security_detector",
        "graphql_security_collector",
        "graphql_introspection_detector",
        "graphql_dos_detector",
        "graphql_batching_detector",
        "graphql_access_control",
    ]
    for cap in capabilities:
        resolved = registry.get(cap)
        assert resolved is not None, f"Capability '{cap}' failed to resolve"
        assert resolved.id == "graphql_security"
    print(f"  [✓] 2.3 Successfully resolved all {len(capabilities)} capability strings.")

    # Test 2.4: Compatible tools lookup & deterministic ordering
    tools_for_gql_val = registry.find_compatible_tools("GraphQL Security Validation")
    assert any(t.id == "graphql_security" for t in tools_for_gql_val)

    tools_for_gql_analysis = registry.find_compatible_tools("GraphQL Analysis")
    # For GraphQL Analysis, graphql_specialist (priority 100) must appear before graphql_security (priority 95)
    tool_ids = [t.id for t in tools_for_gql_analysis]
    assert "graphql_specialist" in tool_ids
    assert "graphql_security" in tool_ids
    idx_spec = tool_ids.index("graphql_specialist")
    idx_sec = tool_ids.index("graphql_security")
    assert idx_spec < idx_sec, f"Expected graphql_specialist (priority 100) before graphql_security (priority 95), got {tool_ids}"
    print("  [✓] 2.4 find_compatible_tools returns deterministically sorted tools by priority descending.")


def test_suite_plugin_executor_adapter():
    """Verify PluginExecutorAdapter fallback resolution and ControlledMission execution."""
    print("\n=== [Suite 3] PluginExecutorAdapter & Specialist Fallback ===")
    adapter = PluginExecutorAdapter()

    # Test 3.1: Specialist Fallback Instantiations
    fallback_checks = [
        ("graphql_security", GraphQLSecurityCollector),
        ("graphql_vuln", GraphQLSecurityCollector),
        ("graphql_vulnerability", GraphQLSecurityCollector),
        ("graphql_introspection", GraphQLSecurityCollector),
        ("graphql_collector", GraphQLSecurityCollector),
    ]
    for p_id, expected_cls in fallback_checks:
        inst = adapter._instantiate_specialist_fallback(p_id)
        assert isinstance(inst, expected_cls), f"For '{p_id}', expected instance of {expected_cls.__name__}, got {type(inst)}"
    print(f"  [✓] 3.1 Correct fallback instances for all {len(fallback_checks)} GraphQL security plugin IDs.")

    # Test 3.2: Legacy Specialist vs Security Collector separation
    legacy_inst = adapter._instantiate_specialist_fallback("graphql_specialist")
    assert legacy_inst.__class__.__name__ == "GraphQLPlugin"
    legacy_inst2 = adapter._instantiate_specialist_fallback("graphql")
    assert legacy_inst2.__class__.__name__ == "GraphQLPlugin"
    print("  [✓] 3.2 Legacy 'graphql_specialist' and 'graphql' cleanly separate from 'graphql_security'.")

    # Test 3.3: Execute Plugin with ControlledMission
    mock_client = MockHttpServerClient(mode="vulnerable")
    mission = Mission(
        target="https://target.corp",
        endpoints=[{"url": "https://target.corp/api/graphql", "method": "POST"}],
    )
    collector = GraphQLSecurityCollector(http_client=mock_client)

    # Wrap fallback instantiation
    orig_fallback = adapter._instantiate_specialist_fallback
    adapter._instantiate_specialist_fallback = lambda pid: collector if "graphql_security" in pid else orig_fallback(pid)
    result = adapter.execute_plugin("graphql_security", mission)
    assert result["status"] == "success"
    assert len(mission.evidence) > 0
    assert len(mission.plugin_findings) > 0
    print(f"  [✓] 3.3 execute_plugin wrapped mission in ControlledMission, generated {len(mission.evidence)} evidence items and published {len(mission.plugin_findings)} findings.")


def test_suite_mission_lifecycle_and_attack_surface_graph():
    """Verify Full Mission lifecycle, quadruple state updates, and AttackSurfaceGraph edge topology."""
    print("\n=== [Suite 4] Full Mission Lifecycle & AttackSurfaceGraph Integrity ===")
    mock_client = MockHttpServerClient(mode="vulnerable")
    mission = Mission(
        target="https://target.corp",
        live_hosts=[{"url": "https://target.corp"}],
        endpoints=[{"url": "https://target.corp/api/graphql", "method": "POST"}],
    )

    collector = GraphQLSecurityCollector(http_client=mock_client)
    controlled_mission = ControlledMission(mission)

    # Execute collection
    ev_list = collector.collect(controlled_mission)
    assert len(ev_list) >= 8, f"Expected >= 8 evidence items, got {len(ev_list)}"
    print(f"  [✓] 4.1 Collector executed across all techniques, producing {len(ev_list)} findings.")

    # Verify Quadruple State Updates
    # 1. raw_mission.evidence
    assert len(mission.evidence) == len(ev_list)
    # 2. raw_mission.vulnerabilities
    assert len(mission.vulnerabilities) == len(ev_list)
    # 3. ControlledMission publish_finding
    assert len(mission.plugin_findings) == len(ev_list)
    # 4. AttackSurfaceGraph directly populated
    graph = mission.attack_surface_graph
    assert len(graph.nodes) > 0
    assert len(graph.edges) > 0
    print("  [✓] 4.2 Quadruple state updates verified (evidence, vulnerabilities, plugin_findings, attack_surface_graph).")

    # Verify Node Types in AttackSurfaceGraph
    lh_nodes = graph.nodes_by_type("live_host")
    ep_nodes = graph.nodes_by_type("endpoint")
    vuln_nodes = graph.nodes_by_type("vulnerability")
    assert len(lh_nodes) >= 1, "Expected at least 1 live_host node"
    assert len(ep_nodes) >= 1, "Expected at least 1 endpoint node"
    assert len(vuln_nodes) >= 8, f"Expected >= 8 vulnerability nodes, got {len(vuln_nodes)}"

    # Verify Edge Connectivity
    # Edges: live_host -> endpoint (HAS_ENDPOINT)
    #        live_host -> vulnerability (HAS_VULNERABILITY)
    #        endpoint -> vulnerability (HAS_VULNERABILITY)
    has_endpoint_edges = [e for e in graph.edges if e.type == "HAS_ENDPOINT"]
    has_vuln_edges = [e for e in graph.edges if e.type == "HAS_VULNERABILITY"]

    assert len(has_endpoint_edges) >= 1, "Missing HAS_ENDPOINT edges"
    assert len(has_vuln_edges) >= len(vuln_nodes), f"Expected >= {len(vuln_nodes)} HAS_VULNERABILITY edges, got {len(has_vuln_edges)}"

    # Verify edge source and target integrity
    for edge in has_vuln_edges:
        source_node = graph.get(edge.source)
        target_node = graph.get(edge.target)
        assert source_node is not None, f"Edge source node {edge.source} not found"
        assert target_node is not None, f"Edge target node {edge.target} not found"
        assert source_node.type in ("live_host", "endpoint"), f"Unexpected source type {source_node.type}"
        assert target_node.type == "vulnerability", f"Unexpected target type {target_node.type}"

    print(f"  [✓] 4.3 Verified {len(has_endpoint_edges)} HAS_ENDPOINT and {len(has_vuln_edges)} HAS_VULNERABILITY edges with valid node endpoints.")

    # Test 4.4: Verify AttackSurfaceGraphBuilder.build_from_evidence (Section 18)
    builder_graph = AttackSurfaceGraphBuilder().build_from_evidence(mission.evidence, target="target.corp")
    b_lh = builder_graph.nodes_by_type("live_host")
    b_ep = builder_graph.nodes_by_type("endpoint")
    b_vuln = builder_graph.nodes_by_type("vulnerability")
    b_has_ep = [e for e in builder_graph.edges if e.type == "HAS_ENDPOINT"]
    b_has_vuln = [e for e in builder_graph.edges if e.type == "HAS_VULNERABILITY"]

    assert len(b_lh) >= 1
    assert len(b_ep) >= 1
    assert len(b_vuln) == len(vuln_nodes)
    assert len(b_has_ep) >= 1
    assert len(b_has_vuln) >= len(b_vuln)
    print("  [✓] 4.4 AttackSurfaceGraphBuilder.build_from_evidence (Section 18) independently generated matching graph topology.")


def test_suite_cvss_and_cwe_mappings():
    """Verify CVSS v3.1 calculation and CWE mapping for all GraphQL vulnerability categories."""
    print("\n=== [Suite 5] CVSS v3.1 & CWE Mappings ===")

    # Test 5.1: CWE Mappings for GraphQL categories
    cwe_expectations = {
        "graphql": ("CWE-200", "Exposure of Sensitive Information to an Unauthorized Actor"),
        "graphql_security": ("CWE-200", "Exposure of Sensitive Information to an Unauthorized Actor"),
        "graphql_introspection": ("CWE-200", "Exposure of Sensitive Information to an Unauthorized Actor"),
        "graphql_dos": ("CWE-400", "Uncontrolled Resource Consumption"),
        "graphql_depth_dos": ("CWE-400", "Uncontrolled Resource Consumption"),
        "graphql_batching": ("CWE-799", "Improper Control of Interaction Frequency"),
        "graphql_batching_bypass": ("CWE-799", "Improper Control of Interaction Frequency"),
        "graphql_access_control": ("CWE-285", "Improper Authorization"),
        "sql_injection": ("CWE-89", "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"),
        "command_injection": ("CWE-78", "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')"),
    }

    for cat, (expected_id, expected_name) in cwe_expectations.items():
        info = CVSSCalculator.get_cwe_for_category(cat)
        assert info is not None, f"CWE mapping missing for category '{cat}'"
        assert info.id == expected_id, f"For '{cat}', expected CWE ID '{expected_id}', got '{info.id}'"
        assert info.name == expected_name, f"For '{cat}', expected CWE Name '{expected_name}', got '{info.name}'"
    print(f"  [✓] 5.1 Verified CWE database mappings for all {len(cwe_expectations)} vulnerability categories.")

    # Test 5.2: FIRST CVSS v3.1 Base Score Precision & Vector Parsing
    # Example vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N (Information Disclosure / Introspection)
    score_info = CVSSCalculator.calculate_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
    assert score_info == 7.5, f"Expected 7.5, got {score_info}"

    # DoS vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H
    score_dos = CVSSCalculator.calculate_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H")
    assert score_dos == 7.5, f"Expected 7.5, got {score_dos}"

    # Critical RCE: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    score_rce = CVSSCalculator.calculate_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert score_rce == 9.8, f"Expected 9.8, got {score_rce}"

    print(f"  [✓] 5.2 FIRST CVSS v3.1 base score calculation validated: Info=7.5, DoS=7.5, RCE=9.8.")

    # Test 5.3: Heuristic CVSS Derivation across GraphQL categories and severities
    for cat in ["graphql_security", "graphql_introspection", "graphql_dos", "graphql_batching", "graphql_access_control"]:
        for sev in ["low", "medium", "high", "critical"]:
            cvss_data = CVSSCalculator.get_approximate_cvss(category=cat, severity=sev)
            assert cvss_data.score > 0.0, f"Score for {cat}/{sev} must be > 0"
            assert cvss_data.vector.startswith("CVSS:3.1/")
            sev_enum = CVSSCalculator.score_to_severity(cvss_data.score)
            assert sev_enum.value == sev, f"For {cat}/{sev}, derived score {cvss_data.score} maps to {sev_enum.value}"
    print("  [✓] 5.3 Validated heuristic CVSS derivation and severity round-tripping across all severity bands.")


def test_suite_adversarial_stress_tests():
    """Adversarial stress testing: malformed endpoints, 500 errors, massive inputs, and hardened defenses."""
    print("\n=== [Suite 6] Adversarial Stress & Edge Case Harness ===")

    # Test 6.1: Hardened server response suppression
    hardened_client = MockHttpServerClient(mode="hardened")
    mission_hardened = Mission(
        target="https://hardened.corp",
        endpoints=[{"url": "https://hardened.corp/graphql", "method": "POST"}],
    )
    collector_hardened = GraphQLSecurityCollector(http_client=hardened_client)
    ev_hardened = collector_hardened.collect(mission_hardened)
    assert len(ev_hardened) == 0, f"Expected 0 findings on hardened server, got {len(ev_hardened)}"
    assert len(mission_hardened.vulnerabilities) == 0
    print("  [✓] 6.1 Zero false positives on hardened GraphQL servers.")

    # Test 6.2: Server 500 Error Resiliency
    error_client = MockHttpServerClient(mode="error_500")
    mission_err = Mission(
        target="https://error.corp",
        endpoints=[{"url": "https://error.corp/graphql", "method": "POST"}],
    )
    collector_err = GraphQLSecurityCollector(http_client=error_client)
    ev_err = collector_err.collect(mission_err)
    # Should complete without crashing
    print(f"  [✓] 6.2 Collector gracefully handled HTTP 500 HTML responses ({len(ev_err)} findings).")

    # Test 6.3: Large Candidate List Stress Test (100 candidate URLs)
    stress_endpoints = [{"url": f"https://api{i}.target.com/graphql", "method": "POST"} for i in range(100)]
    mission_stress = Mission(
        target="https://target.com",
        endpoints=stress_endpoints,
    )
    # Measure discovery time
    t0 = time.perf_counter()
    candidates = collector_hardened._discover_candidate_endpoints(mission_stress)
    t_discovery = (time.perf_counter() - t0) * 1000.0
    assert len(candidates) >= 100
    print(f"  [✓] 6.3 Candidate discovery on 100 endpoints completed in {t_discovery:.2f}ms.")

    # Test 6.4: Malformed URLs and null inputs
    malformed_mission = Mission(
        target="not-a-valid-url",
        live_hosts=["localhost:8080", "127.0.0.1", None],
        endpoints=[{"url": None}, {"url": "httpx://invalid"}, "ftp://not-http"],
    )
    candidates_malformed = collector_hardened._discover_candidate_endpoints(malformed_mission)
    assert isinstance(candidates_malformed, list)
    print(f"  [✓] 6.4 Malformed URLs and None assets handled without unhandled exceptions ({len(candidates_malformed)} normalized candidates).")


def main():
    print("=======================================================================")
    print("   ARGUS Sprint 17 (GraphQL Security) - Challenger 2 Verification    ")
    print("=======================================================================\n")

    t_start = time.perf_counter()
    suites = [
        test_suite_dag_task_generator,
        test_suite_tool_registry,
        test_suite_plugin_executor_adapter,
        test_suite_mission_lifecycle_and_attack_surface_graph,
        test_suite_cvss_and_cwe_mappings,
        test_suite_adversarial_stress_tests,
    ]

    total_passed = 0
    for suite in suites:
        try:
            suite()
            total_passed += 1
        except Exception as e:
            print(f"\n[!] SUITE FAILED: {suite.__name__}")
            traceback.print_exc()
            sys.exit(1)

    t_elapsed = time.perf_counter() - t_start
    print(f"\n=======================================================================")
    print(f"   ALL {total_passed}/{len(suites)} VERIFICATION SUITES PASSED in {t_elapsed:.3f}s")
    print("=======================================================================")


if __name__ == "__main__":
    main()
