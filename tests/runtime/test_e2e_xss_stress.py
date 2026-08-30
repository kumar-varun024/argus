"""
Adversarial Stress Harness and Invariant Verification Suite for Sprint 10 M4.
Evaluates Mock HTTP fidelity, DAG task generation, ToolRegistry lookup,
KnowledgeGraph invariants, and XSSCollector robustness under boundary conditions.
"""

from __future__ import annotations

import concurrent.futures
import html
import urllib.parse
from typing import Any, Dict, List

import pytest

from argus.collectors.sql_injection import SQLInjectionCollector
from argus.collectors.xss import (
    XSSAnalyzer,
    XSSCollector,
    XSSContext,
    XSSPayloadGenerator,
)
from argus.evidence.model import Evidence, ProvenanceData
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
from argus.utils.environment import EnvironmentDetector
from tests.runtime.test_e2e_xss import MockE2EXSSHttpClient


def test_stress_canary_generation_uniqueness_and_performance():
    """Verify 5,000 generated canaries are strictly unique and alphanumeric."""
    generator = XSSPayloadGenerator()
    canaries = [generator.generate_canary("stress") for _ in range(5000)]
    assert len(canaries) == 5000
    assert len(set(canaries)) == 5000
    for c in canaries:
        assert c.startswith("stress")
        assert c.isalnum()


def test_stress_context_payload_completeness():
    """Verify all XSSContext enum members return valid, non-empty payload lists."""
    generator = XSSPayloadGenerator()
    canary = "TESTCANARY123"
    for ctx in XSSContext:
        payloads = generator.get_context_payloads(ctx, canary)
        assert isinstance(payloads, list)
        assert len(payloads) >= 1
        for p in payloads:
            assert "payload" in p
            assert "breakout" in p
            assert canary in p["payload"] or "alert" in p["payload"]


def test_stress_xss_analyzer_escaped_vs_unescaped_oracle():
    """Oracle test comparing XSSAnalyzer against extensive safe and vulnerable HTML patterns."""
    analyzer = XSSAnalyzer()
    canary = "ORACLETESTCANARY"

    safe_patterns = [
        f"&lt;script&gt;/*{canary}*/&lt;/script&gt;",
        f"&lt;img src=x onerror=alert(&#39;{canary}&#39;)&gt;",
        f"&#x3c;svg onload=alert(&#x27;{canary}&#x27;)&#x3e;",
        f"&lt;b&gt;{canary}&lt;/b&gt;",
        f"&quot; onfocus=&quot;alert(&#39;{canary}&#39;)",
        f"&#0000060;script&#0000062;{canary}&#0000060;/script&#0000062;",
        f"Search results for: <span>{html.escape(f'<script>{canary}</script>')}</span>",
        f"<div>Hello &lt;img src=x onerror=alert({canary})&gt; User</div>",
    ]

    for body in safe_patterns:
        assert (
            analyzer.is_properly_escaped(body, canary) is True
        ), f"False negative: Expected safe for {body}"
        fake_resp = HttpResponse(
            success=True,
            status_code=200,
            body=body,
            raw_body=body,
            headers={"Content-Type": "text/html; charset=utf-8"},
        )
        assert (
            analyzer.analyze_reflected(
                fake_resp, canary, f"<script>{canary}</script>", XSSContext.HTML_BODY
            )
            is None
        )

    vulnerable_patterns = [
        f"<script>/*{canary}*/</script>",
        f"<img src=x onerror=alert('{canary}')>",
        f"<svg onload=alert('{canary}')>",
        f'"><script>/*{canary}*/</script>',
        f'<input value="{canary}" onfocus="alert(\'{canary}\')">',
        f"<input value='{canary}' onfocus='alert(\"{canary}\")'>",
        f"<input value={canary} onfocus=alert('{canary}')>",
        f'<script>var x = "{canary}";alert("{canary}");//";</script>',
        f"<script>var x = '{canary}';alert('{canary}');//';</script>",
        f'<a href="javascript:alert(\'{canary}\')">Click</a>',
        f"<!-- --> <script>/*{canary}*/</script>",
    ]

    for body in vulnerable_patterns:
        assert (
            analyzer.is_properly_escaped(body, canary) is False
        ), f"False positive: Expected vulnerable for {body}"
        fake_resp = HttpResponse(
            success=True,
            status_code=200,
            body=body,
            raw_body=body,
            headers={"Content-Type": "text/html; charset=utf-8"},
        )
        finding = analyzer.analyze_reflected(
            fake_resp, canary, f"<script>{canary}</script>"
        )
        assert finding is not None
        assert finding["xss_type"] == "reflected"
        assert finding["canary"] == canary


def test_stress_mock_http_client_query_param_parsing():
    """Verify MockE2EXSSHttpClient query parameter extraction with complex query encodings."""
    client = MockE2EXSSHttpClient()
    client.set_route(
        "reflect:q",
        200,
        "<html><body>Reflection: {val}</body></html>",
    )

    # 1. URL encoded payload in GET query
    raw_payload = "<script>alert(1)</script>"
    encoded_query = urllib.parse.urlencode({"q": raw_payload})
    target_url = f"https://mock.local/search?{encoded_query}"
    resp = client.get(target_url)

    assert resp.status_code == 200
    assert raw_payload in resp.body
    assert f"Reflection: {raw_payload}" in resp.body


def test_stress_mock_http_client_post_persistence_and_overwrites():
    """Verify MockE2EXSSHttpClient stateful POST-then-GET persistence and path isolation."""
    client = MockE2EXSSHttpClient()

    # Post to /blog/post1
    p1 = "<b id='post1'>payload1</b>"
    resp1 = client.post("https://app.test/blog/post1", data={"comment": p1})
    assert resp1.status_code == 200

    # Post to /blog/post2
    p2 = "<b id='post2'>payload2</b>"
    resp2 = client.post("https://app.test/blog/post2", data={"content": p2})
    assert resp2.status_code == 200

    # Verify /blog/post1 contains p1, not p2
    get1 = client.get("https://app.test/blog/post1")
    assert p1 in get1.body
    assert p2 not in get1.body

    # Verify /blog/post2 contains p2, not p1
    get2 = client.get("https://app.test/blog/post2")
    assert p2 in get2.body
    assert p1 not in get2.body

    # Overwrite /blog/post1
    p1_new = "<b id='post1_updated'>new_payload1</b>"
    client.post("https://app.test/blog/post1", data={"message": p1_new})
    get1_updated = client.get("https://app.test/blog/post1")
    assert p1_new in get1_updated.body
    assert p1 not in get1_updated.body


def test_stress_dag_task_generation_and_dependency_integrity():
    """Verify TaskGenerator handles multi-gap batches and maintains dependency invariants."""
    mission = Mission(target="portal.internal")
    task_gen = TaskGenerator(mission)

    gaps = [
        CoverageGap(area="xss", description="Audit for reflected XSS", severity=0.9),
        CoverageGap(
            area="sql_injection", description="Audit database queries", severity=0.95
        ),
        CoverageGap(
            area="path_traversal", description="Audit file inclusion", severity=0.8
        ),
        CoverageGap(
            area="info_disclosure",
            description="Audit headers and comments",
            severity=0.7,
        ),
    ]

    tasks = task_gen.from_gaps(gaps)
    assert len(tasks) == 4

    xss_tasks = [t for t in tasks if t.metadata.get("tool_id") == "xss"]
    assert len(xss_tasks) == 1
    xss_t = xss_tasks[0]
    assert xss_t.title == "Fuzz Cross-Site Scripting (XSS)"
    assert "Discover API Endpoints" in xss_t.dependencies
    assert xss_t.priority == 0.9


def test_stress_tool_registry_and_plugin_adapter_dispatch():
    """Verify ToolRegistry and PluginExecutorAdapter capabilities and aliases."""
    # ToolRegistry aliases
    t1 = registry.get("xss")
    t2 = registry.get("cross_site_scripting")
    assert t1 is not None
    assert t2 is not None
    assert t1.id == t2.id == "xss"
    assert "xss_detector" in t1.capabilities
    assert "xss_collector" in t1.capabilities

    # PluginExecutorAdapter fallback execution
    adapter = PluginExecutorAdapter()
    mission = Mission(target="test.org")
    mission.endpoints = []

    # execute_plugin should return success dict with instantiated plugin
    res_xss = adapter.execute_plugin("xss", mission)
    assert isinstance(res_xss, dict)
    assert res_xss["status"] == "success"
    assert isinstance(res_xss["plugin_instance"], XSSCollector)

    res_alias = adapter.execute_plugin("cross_site_scripting", mission)
    assert isinstance(res_alias, dict)
    assert res_alias["status"] == "success"
    assert isinstance(res_alias["plugin_instance"], XSSCollector)


def test_stress_knowledge_graph_node_and_edge_invariants():
    """Verify KnowledgeGraph maintains node uniqueness, edge topology, and type queries."""
    graph = KnowledgeGraph()

    # Add host, endpoint, and vulnerability nodes
    lh_id = "live_host:https://test.net"
    ep_id = "endpoint:https://test.net/search?q=1"
    vuln_id = "vulnerability:xss-reflected:https://test.net/search?q=1:q"

    from argus.graph.node import Node

    graph.add(
        Node(
            id=lh_id,
            type="live_host",
            value="https://test.net",
            metadata={"url": "https://test.net"},
        )
    )
    graph.add(
        Node(
            id=ep_id,
            type="endpoint",
            value="https://test.net/search?q=1",
            metadata={"url": "https://test.net/search?q=1"},
        )
    )
    graph.add(
        Node(
            id=vuln_id,
            type="vulnerability",
            value="Reflected XSS",
            metadata={"severity": "high", "category": "xss"},
        )
    )

    # Connect edges
    graph.connect(lh_id, ep_id, edge_type="HAS_ENDPOINT")
    graph.connect(lh_id, vuln_id, edge_type="HAS_VULNERABILITY")
    graph.connect(ep_id, vuln_id, edge_type="HAS_VULNERABILITY")

    # Verify query APIs
    assert len(graph.nodes_by_type("live_host")) == 1
    assert len(graph.nodes_by_type("endpoint")) == 1
    assert len(graph.nodes_by_type("vulnerability")) == 1

    edges_has_vuln = [e for e in graph.edges if e.type == "HAS_VULNERABILITY"]
    assert len(edges_has_vuln) == 2

    # Verify idempotency when re-adding existing node
    graph.add(
        Node(
            id=lh_id,
            type="live_host",
            value="https://test.net",
            metadata={"url": "https://test.net"},
        )
    )
    assert len(graph.nodes_by_type("live_host")) == 1


def test_stress_attack_surface_builder_reconstruction_with_diverse_vulns():
    """Verify AttackSurfaceGraphBuilder correctly maps severities and edges for multi-vuln evidence."""
    builder = AttackSurfaceGraphBuilder()
    evidence_list = [
        Evidence(
            title="Reflected XSS on /search",
            category="xss",
            severity="high",
            source="https://target.com/search?q=test",
            metadata={
                "url": "https://target.com/search?q=test",
                "host": "https://target.com",
                "xss_type": "reflected",
                "severity": "high",
            },
        ),
        Evidence(
            title="Stored XSS on /comments",
            category="xss",
            severity="critical",
            source="https://target.com/comments",
            metadata={
                "url": "https://target.com/comments",
                "host": "https://target.com",
                "xss_type": "stored",
                "severity": "critical",
            },
        ),
        Evidence(
            title="Header DOM XSS on /view",
            category="xss",
            severity="medium",
            source="https://target.com/view",
            metadata={
                "url": "https://target.com/view",
                "host": "https://target.com",
                "xss_type": "header",
                "severity": "medium",
            },
        ),
        Evidence(
            title="SQLi on /api/user",
            category="sql_injection",
            severity="critical",
            source="https://target.com/api/user?id=1",
            metadata={
                "url": "https://target.com/api/user?id=1",
                "host": "https://target.com",
                "severity": "critical",
            },
        ),
    ]

    graph = builder.build_from_evidence(evidence_list, target="target.com")
    vuln_nodes = graph.nodes_by_type("vulnerability")
    assert len(vuln_nodes) == 4

    severities = {n.metadata.get("severity") for n in vuln_nodes}
    assert "critical" in severities
    assert "high" in severities
    assert "medium" in severities

    has_vuln_edges = [e for e in graph.edges if e.type == "HAS_VULNERABILITY"]
    assert len(has_vuln_edges) >= 4


def test_stress_xss_collector_concurrency_and_cross_mission_isolation():
    """Verify XSSCollector behaves safely when executed across multiple concurrent missions."""
    collector = XSSCollector(http_client=MockE2EXSSHttpClient())

    def run_mission(idx: int):
        target = f"site{idx}.internal"
        m = Mission(target=target)
        m.scope = [target]
        m.live_hosts = [{"url": f"https://{target}", "host": target}]
        m.endpoints = [
            {
                "url": f"https://{target}/search?q=test{idx}",
                "path": "/search",
                "params": {"q": f"test{idx}"},
                "host": f"https://{target}",
            }
        ]
        m.evidence = EvidenceStore()
        m.vulnerabilities = []
        m.attack_surface_graph = KnowledgeGraph()

        res = collector.collect(m)
        assert len(res) >= 1
        assert res[0].category == "xss"
        assert target in res[0].metadata["host"]
        return len(res)

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(run_mission, i) for i in range(10)]
        results = [f.result() for f in concurrent.futures.as_completed(futures)]

    assert len(results) == 10
    assert all(r >= 1 for r in results)


def test_stress_environment_detector_with_extreme_inputs():
    """Verify EnvironmentDetector resilience to invalid/extreme target inputs."""
    detector = EnvironmentDetector(timeout=0.5)

    # Empty target
    res_empty = detector.detect("")
    assert res_empty["network"]["dns_resolvable"] is False
    assert res_empty["network"]["http_reachable"] is False

    # Non-existent domain
    res_nonexistent = detector.detect("this-domain-cannot-exist-123456789.invalid")
    assert res_nonexistent["network"]["dns_resolvable"] is False
    assert res_nonexistent["network"]["http_reachable"] is False

    # Check tools with empty list
    tools_empty = detector.check_tools([])
    assert tools_empty == {}

    # Check tools with arbitrary names
    tools_custom = detector.check_tools(["non_existent_binary_xyz_999"])
    assert tools_custom["non_existent_binary_xyz_999"] is False
