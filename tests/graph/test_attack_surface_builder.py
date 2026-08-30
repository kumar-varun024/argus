"""
Unit tests for AttackSurfaceGraphBuilder (R1).
"""
import pytest
from argus.graph import KnowledgeGraph, Node, Edge, AttackSurfaceGraphBuilder
from argus.evidence.store import EvidenceStore
from argus.evidence.model import Evidence
from argus.runtime.mission import Mission


@pytest.fixture
def standard_evidence_fixture() -> EvidenceStore:
    """
    Standard fixture with:
    - 2 subdomains (api.example.com, admin.example.com)
    - 2 live hosts (http://api.example.com, http://admin.example.com)
    - 3 endpoints (/v1/users, /v1/login, /admin/login)
    - 1 technology (nginx)
    - 1 vulnerability (CVE-2023-XXXX)
    """
    store = EvidenceStore()
    # 2 Subdomains
    store.add(Evidence(category="subdomain", value="api.example.com", source="subfinder", metadata={"hostname": "api.example.com"}))
    store.add(Evidence(category="subdomain", value="admin.example.com", source="subfinder", metadata={"hostname": "admin.example.com"}))

    # 2 Live Hosts
    store.add(Evidence(
        category="live_host",
        value="http://api.example.com",
        source="httpx",
        metadata={"url": "http://api.example.com", "host": "api.example.com", "status": 200, "server": "nginx", "technologies": ["nginx"]}
    ))
    store.add(Evidence(
        category="live_host",
        value="http://admin.example.com",
        source="httpx",
        metadata={"url": "http://admin.example.com", "host": "admin.example.com", "status": 403, "server": "nginx", "technologies": ["nginx"]}
    ))

    # 3 Endpoints
    store.add(Evidence(
        category="endpoint",
        value="http://api.example.com/v1/users",
        source="katana",
        metadata={"url": "http://api.example.com/v1/users", "host": "api.example.com", "path": "/v1/users", "method": "GET"}
    ))
    store.add(Evidence(
        category="endpoint",
        value="http://api.example.com/v1/login",
        source="katana",
        metadata={"url": "http://api.example.com/v1/login", "host": "api.example.com", "path": "/v1/login", "method": "POST"}
    ))
    store.add(Evidence(
        category="endpoint",
        value="http://admin.example.com/admin/login",
        source="katana",
        metadata={"url": "http://admin.example.com/admin/login", "host": "admin.example.com", "path": "/admin/login", "method": "GET"}
    ))

    # 1 Vulnerability
    store.add(Evidence(
        category="vulnerability",
        value="CVE-2023-XXXX",
        source="nuclei",
        severity="high",
        metadata={"template_id": "CVE-2023-XXXX", "name": "CVE-2023-XXXX", "severity": "high", "host": "http://api.example.com"}
    ))

    return store


class TestAttackSurfaceGraphBuilder:
    """Test suite for AttackSurfaceGraphBuilder."""

    def test_r1_standard_10_node_count(self, standard_evidence_fixture):
        """Verify 1 target + 2 subs + 2 hosts + 3 eps + 1 tech + 1 vuln = 10 nodes."""
        builder = AttackSurfaceGraphBuilder()
        graph = builder.build_from_evidence(standard_evidence_fixture, target="example.com")

        assert graph.node_count() == 10
        assert len(graph.nodes_by_type("target")) == 1
        assert len(graph.nodes_by_type("subdomain")) == 2
        assert len(graph.nodes_by_type("live_host")) == 2
        assert len(graph.nodes_by_type("endpoint")) == 3
        assert len(graph.nodes_by_type("technology")) == 1
        assert len(graph.nodes_by_type("vulnerability")) == 1

    def test_r1_node_type_filtering(self, standard_evidence_fixture):
        """Verify nodes_by_type retrieves exact node instances and values."""
        builder = AttackSurfaceGraphBuilder()
        graph = builder.build_from_evidence(standard_evidence_fixture, target="example.com")

        sub_values = {n.value for n in graph.nodes_by_type("subdomain")}
        assert sub_values == {"api.example.com", "admin.example.com"}

        host_values = {n.value for n in graph.nodes_by_type("live_host")}
        assert host_values == {"http://api.example.com", "http://admin.example.com"}

        ep_values = {n.value for n in graph.nodes_by_type("endpoint")}
        assert ep_values == {
            "http://api.example.com/v1/users",
            "http://api.example.com/v1/login",
            "http://admin.example.com/admin/login",
        }

        tech_values = {n.value for n in graph.nodes_by_type("technology")}
        assert tech_values == {"nginx"}

        vuln_values = {n.value for n in graph.nodes_by_type("vulnerability")}
        assert vuln_values == {"CVE-2023-XXXX"}

    def test_r1_edge_types_and_topology(self, standard_evidence_fixture):
        """Verify all 5 typed relationships exist and connect correct tiers."""
        builder = AttackSurfaceGraphBuilder()
        graph = builder.build_from_evidence(standard_evidence_fixture, target="example.com")

        edge_types = {e.type for e in graph.edges}
        expected_types = {"RESOLVES_TO", "HOSTS", "HAS_ENDPOINT", "RUNS_TECHNOLOGY", "HAS_VULNERABILITY"}
        assert expected_types.issubset(edge_types)

        # Target -> Subdomain (RESOLVES_TO)
        target_node = graph.get("target:example.com")
        assert target_node is not None
        target_edges = [e for e in graph.edges_from(target_node) if e.type == "RESOLVES_TO"]
        assert len(target_edges) == 2

        # Subdomain -> Live Host (HOSTS)
        sub_api = graph.get("subdomain:api.example.com")
        api_hosts = [e for e in graph.edges_from(sub_api) if e.type == "HOSTS"]
        assert len(api_hosts) == 1
        assert api_hosts[0].target == "live_host:http://api.example.com"

        # Live Host -> Endpoints (HAS_ENDPOINT)
        api_host_node = graph.get("live_host:http://api.example.com")
        api_eps = [e for e in graph.edges_from(api_host_node) if e.type == "HAS_ENDPOINT"]
        assert len(api_eps) == 2

        # Live Host -> Technology (RUNS_TECHNOLOGY)
        api_techs = [e for e in graph.edges_from(api_host_node) if e.type == "RUNS_TECHNOLOGY"]
        assert len(api_techs) == 1
        assert api_techs[0].target == "technology:nginx"

        # Live Host -> Vulnerability (HAS_VULNERABILITY)
        api_vulns = [e for e in graph.edges_from(api_host_node) if e.type == "HAS_VULNERABILITY"]
        assert len(api_vulns) == 1
        assert api_vulns[0].target == "vulnerability:CVE-2023-XXXX"

    def test_r1_idempotent_building(self, standard_evidence_fixture):
        """Building twice on the same graph/evidence yields identical node and edge counts."""
        builder = AttackSurfaceGraphBuilder()
        graph = KnowledgeGraph()

        builder.build_from_evidence(standard_evidence_fixture, target="example.com", graph=graph)
        node_count_1 = graph.node_count()
        edge_count_1 = graph.edge_count()

        # Run again on same graph
        builder.build_from_evidence(standard_evidence_fixture, target="example.com", graph=graph)
        assert graph.node_count() == node_count_1
        assert graph.edge_count() == edge_count_1

    def test_r1_build_from_mission_object(self, standard_evidence_fixture):
        """Verify building from a Mission instance attaches to mission.attack_surface_graph and mission.graph."""
        mission = Mission(target="example.com")
        mission.evidence = standard_evidence_fixture

        builder = AttackSurfaceGraphBuilder()
        graph = builder.build(mission)

        assert graph is mission.attack_surface_graph
        assert graph is mission.graph
        assert graph.node_count() == 10

    def test_r1_build_from_bare_mission_attributes(self):
        """Verify building from structured attributes when evidence store is empty."""
        mission = Mission(target="example.com")
        mission.subdomains = ["api.example.com", "web.example.com"]
        mission.live_hosts = [
            {"url": "https://api.example.com", "host": "api.example.com", "technologies": ["express"]},
            {"url": "https://web.example.com", "host": "web.example.com", "technologies": ["react"]},
        ]
        mission.endpoints = [
            {"url": "https://api.example.com/v1/auth", "host": "api.example.com"},
            {"url": "https://web.example.com/index.html", "host": "web.example.com"},
        ]
        mission.vulnerabilities = [
            {"template_id": "cve-2024-1111", "host": "https://api.example.com", "severity": "critical"}
        ]

        builder = AttackSurfaceGraphBuilder()
        graph = builder.build(mission)

        # target(1) + subs(2) + hosts(2) + eps(2) + techs(2) + vulns(1) = 10
        assert graph.node_count() == 10
        assert mission.attack_surface_graph.node_count() == 10

    def test_r1_empty_mission(self):
        """Building from an empty mission gracefully creates 1 target node."""
        mission = Mission(target="empty.example.com")
        builder = AttackSurfaceGraphBuilder()
        graph = builder.build(mission)

        assert graph.node_count() == 1
        assert graph.get("target:empty.example.com") is not None
        assert graph.edge_count() == 0

    def test_xss_reflected_attack_surface_graph_reconstruction(self):
        """Verify Reflected XSS evidence creates endpoint, vuln (high severity), and edges."""
        ev = Evidence(
            title="Reflected XSS on https://example.com/search?q=test",
            category="xss",
            severity="high",
            value="https://example.com/search?q=test",
            metadata={
                "url": "https://example.com/search?q=test",
                "host": "https://example.com",
                "parameter": "q",
                "template_id": "xss-reflected-html",
                "xss_type": "reflected",
                "status_code": 200,
            },
        )

        builder = AttackSurfaceGraphBuilder()
        graph = builder.build_from_evidence([ev], target="example.com")

        assert "live_host:https://example.com" in graph.nodes
        assert "endpoint:https://example.com/search?q=test" in graph.nodes
        vuln_id = "vulnerability:xss-reflected-html:https://example.com/search?q=test:q"
        assert vuln_id in graph.nodes
        vuln_node = graph.get(vuln_id)
        assert vuln_node.metadata["severity"] == "high"

        # Verify edge relationships
        assert any(e.source == "live_host:https://example.com" and e.target == "endpoint:https://example.com/search?q=test" and e.type == "HAS_ENDPOINT" for e in graph.edges)
        assert any(e.source == "live_host:https://example.com" and e.target == vuln_id and e.type == "HAS_VULNERABILITY" for e in graph.edges)
        assert any(e.source == "endpoint:https://example.com/search?q=test" and e.target == vuln_id and e.type == "HAS_VULNERABILITY" for e in graph.edges)

    def test_xss_stored_attack_surface_graph_reconstruction(self):
        """Verify Stored XSS evidence is mapped to critical severity."""
        ev = Evidence(
            title="Stored XSS on https://example.com/comments",
            category="xss",
            value="https://example.com/comments",
            metadata={
                "url": "https://example.com/comments",
                "host": "https://example.com",
                "parameter": "comment",
                "template_id": "xss-stored",
                "xss_type": "stored",
            },
        )

        builder = AttackSurfaceGraphBuilder()
        graph = builder.build_from_evidence([ev], target="example.com")

        vuln_id = "vulnerability:xss-stored:https://example.com/comments:comment"
        assert vuln_id in graph.nodes
        vuln_node = graph.get(vuln_id)
        assert vuln_node.metadata["severity"] == "critical"

    def test_xss_dom_attack_surface_graph_reconstruction(self):
        """Verify DOM XSS evidence is mapped to medium severity."""
        ev = Evidence(
            title="DOM XSS on https://example.com/app",
            category="cross_site_scripting",
            value="https://example.com/app",
            metadata={
                "url": "https://example.com/app",
                "host": "https://example.com",
                "parameter": "hash",
                "template_id": "xss-dom",
                "xss_type": "dom",
            },
        )

        builder = AttackSurfaceGraphBuilder()
        graph = builder.build_from_evidence([ev], target="example.com")

        vuln_id = "vulnerability:xss-dom:https://example.com/app:hash"
        assert vuln_id in graph.nodes
        vuln_node = graph.get(vuln_id)
        assert vuln_node.metadata["severity"] == "medium"

