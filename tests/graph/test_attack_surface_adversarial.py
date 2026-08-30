"""
Adversarial and stress test harness for Sprint 2:
AttackSurfaceGraphBuilder, AttackSurfaceDiffEngine, KnowledgeGraph queries, and GapAnalyzer integration.
"""
import time
import pytest
from argus.graph import (
    KnowledgeGraph, Node, Edge,
    AttackSurfaceGraphBuilder,
    AttackSurfaceDiffEngine,
    AttackSurfaceDiff,
    HostChange,
)
from argus.evidence.store import EvidenceStore
from argus.evidence.model import Evidence
from argus.runtime.mission import Mission
from argus.planning.gap_analysis import GapAnalyzer
from argus.planning.models import TaskCategory


class TestAdversarialGraphBuilder:
    """Stress testing AttackSurfaceGraphBuilder against hostile/malformed inputs and edge cases."""

    def test_empty_and_none_inputs(self):
        builder = AttackSurfaceGraphBuilder()

        # 1. None evidence, empty target
        g1 = builder.build_from_evidence(None, target="")
        assert g1.node_count() == 0
        assert g1.edge_count() == 0

        # 2. Empty evidence store, target provided
        s_empty = EvidenceStore()
        g2 = builder.build_from_evidence(s_empty, target="empty.com")
        assert g2.node_count() == 1
        assert g2.get("target:empty.com") is not None

        # 3. None target on Mission
        m_no_target = Mission(target="")
        g3 = builder.build(m_no_target)
        assert g3.node_count() == 0

        # 4. Mission with empty lists
        m_empty = Mission(target="target.com")
        m_empty.subdomains = []
        m_empty.live_hosts = []
        m_empty.endpoints = []
        m_empty.technologies = []
        m_empty.vulnerabilities = []
        g4 = builder.build(m_empty)
        assert g4.node_count() == 1
        assert g4.get("target:target.com") is not None

    def test_malformed_and_extreme_urls(self):
        builder = AttackSurfaceGraphBuilder()
        store = EvidenceStore()

        # Subdomain with unusual formats
        store.add(Evidence(category="subdomain", value="API.EXAMPLE.COM", source="subfinder", metadata={"hostname": "API.EXAMPLE.COM"}))
        store.add(Evidence(category="subdomain", value="sub_domain-1.test.co.uk", source="subfinder"))
        store.add(Evidence(category="subdomain", value="192.168.1.100", source="subfinder"))
        store.add(Evidence(category="subdomain", value="[2001:db8::1]", source="subfinder"))

        # Live hosts with extreme URL schemes, IPv6, auth, ports, query params
        store.add(Evidence(
            category="live_host",
            value="https://admin:secret@api.example.com:8443/v1/health?param=1#debug",
            source="httpx",
            metadata={
                "url": "https://admin:secret@api.example.com:8443/v1/health?param=1#debug",
                "host": "api.example.com",
                "status": 200,
                "technologies": ["express", "node.js"]
            }
        ))
        store.add(Evidence(
            category="live_host",
            value="http://192.168.1.100:8080",
            source="httpx",
            metadata={"url": "http://192.168.1.100:8080", "host": "192.168.1.100", "status": 200}
        ))
        store.add(Evidence(
            category="live_host",
            value="http://[2001:db8::1]:80",
            source="httpx",
            metadata={"url": "http://[2001:db8::1]:80", "host": "[2001:db8::1]", "status": 200}
        ))

        # Endpoints with percent-encoding, query strings, and paths
        store.add(Evidence(
            category="endpoint",
            value="https://admin:secret@api.example.com:8443/v1/health?param=1#debug",
            source="katana",
            metadata={"url": "https://admin:secret@api.example.com:8443/v1/health?param=1#debug", "host": "api.example.com"}
        ))
        store.add(Evidence(
            category="endpoint",
            value="https://admin:secret@api.example.com:8443/api%20v2/users?filter=<script>",
            source="katana",
            metadata={"url": "https://admin:secret@api.example.com:8443/api%20v2/users?filter=<script>", "host": "api.example.com"}
        ))

        # Vulnerabilities with special characters in template_id
        store.add(Evidence(
            category="vulnerability",
            value="http-missing-security-headers:x-frame-options",
            source="nuclei",
            severity="info",
            metadata={
                "template_id": "http-missing-security-headers:x-frame-options",
                "name": "Missing X-Frame-Options Header",
                "host": "https://admin:secret@api.example.com:8443/v1/health?param=1#debug"
            }
        ))

        graph = builder.build_from_evidence(store, target="example.com")

        assert graph.get("target:example.com") is not None
        assert graph.get("subdomain:API.EXAMPLE.COM") is not None
        assert graph.get("subdomain:192.168.1.100") is not None
        assert graph.get("subdomain:[2001:db8::1]") is not None
        assert graph.get("live_host:https://admin:secret@api.example.com:8443/v1/health?param=1#debug") is not None
        assert graph.get("live_host:http://192.168.1.100:8080") is not None
        assert graph.get("technology:express") is not None
        assert graph.get("technology:node.js") is not None
        assert graph.get("vulnerability:http-missing-security-headers:x-frame-options") is not None

        # Verify edge connections survive extreme URLs
        lh_node = graph.get("live_host:https://admin:secret@api.example.com:8443/v1/health?param=1#debug")
        edges_out = graph.edges_from(lh_node)
        edge_types = {e.type for e in edges_out}
        assert "RUNS_TECHNOLOGY" in edge_types
        assert "HAS_ENDPOINT" in edge_types
        assert "HAS_VULNERABILITY" in edge_types

    def test_special_technology_formats(self):
        """Test varied technology formats: string, comma-separated string, dict, list."""
        builder = AttackSurfaceGraphBuilder()
        store = EvidenceStore()

        # String comma-separated
        store.add(Evidence(
            category="live_host",
            value="http://app.example.com",
            source="httpx",
            metadata={
                "url": "http://app.example.com",
                "host": "app.example.com",
                "technologies": "Nginx, PHP/8.1, Cloudflare, ASP.NET Core 8.0"
            }
        ))
        # Dedicated technology evidence items
        store.add(Evidence(
            category="technology",
            value="Vue.js",
            source="httpx",
            metadata={"name": "Vue.js", "url": "http://app.example.com"}
        ))
        store.add(Evidence(
            category="technology",
            value="Webpack",
            source="httpx",
            metadata={"name": "Webpack", "host": "app.example.com"}
        ))

        graph = builder.build_from_evidence(store, target="example.com")
        tech_names = {n.value for n in graph.nodes_by_type("technology")}
        expected_techs = {"Nginx", "PHP/8.1", "Cloudflare", "ASP.NET Core 8.0", "Vue.js", "Webpack"}
        assert expected_techs.issubset(tech_names)

        # Verify connections to the live host
        lh = graph.get("live_host:http://app.example.com")
        tech_edges = [e for e in graph.edges_from(lh) if e.type == "RUNS_TECHNOLOGY"]
        connected_techs = {e.target for e in tech_edges}
        for t in expected_techs:
            assert f"technology:{t}" in connected_techs

    def test_idempotency_and_duplicate_evidence_stress(self):
        """Verify building from duplicated evidence and repeating build yields exact same graph."""
        builder = AttackSurfaceGraphBuilder()
        store = EvidenceStore()

        # Add 100 duplicates of each evidence item
        for _ in range(100):
            store.add(Evidence(category="subdomain", value="api.example.com", source="subfinder", metadata={"hostname": "api.example.com"}))
            store.add(Evidence(category="live_host", value="http://api.example.com", source="httpx", metadata={"url": "http://api.example.com", "host": "api.example.com", "technologies": ["nginx"]}))
            store.add(Evidence(category="endpoint", value="http://api.example.com/v1", source="katana", metadata={"url": "http://api.example.com/v1", "host": "api.example.com"}))
            store.add(Evidence(category="technology", value="nginx", source="httpx", metadata={"name": "nginx", "url": "http://api.example.com"}))
            store.add(Evidence(category="vulnerability", value="CVE-2024-0001", source="nuclei", metadata={"template_id": "CVE-2024-0001", "host": "http://api.example.com"}))

        graph = KnowledgeGraph()
        # Build 10 times consecutively
        for _ in range(10):
            builder.build_from_evidence(store, target="example.com", graph=graph)

        # target(1) + sub(1) + host(1) + tech(1) + ep(1) + vuln(1) = 6 nodes
        assert graph.node_count() == 6
        assert len(graph.nodes_by_type("target")) == 1
        assert len(graph.nodes_by_type("subdomain")) == 1
        assert len(graph.nodes_by_type("live_host")) == 1
        assert len(graph.nodes_by_type("technology")) == 1
        assert len(graph.nodes_by_type("endpoint")) == 1
        assert len(graph.nodes_by_type("vulnerability")) == 1

        # Target->Sub(1) + Sub->Host(1) + Host->Tech(1) + Host->EP(1) + Host->Vuln(1) = 5 edges
        assert graph.edge_count() == 5

    def test_multi_host_exact_entity_resolution(self):
        """Verify endpoints, tech, and vulns are attached to the CORRECT live host among multiple."""
        builder = AttackSurfaceGraphBuilder()
        store = EvidenceStore()

        # 3 distinct live hosts
        store.add(Evidence(category="subdomain", value="api.example.com", source="subfinder"))
        store.add(Evidence(category="subdomain", value="admin.example.com", source="subfinder"))
        store.add(Evidence(category="subdomain", value="auth.example.com", source="subfinder"))

        store.add(Evidence(category="live_host", value="http://api.example.com", source="httpx", metadata={"url": "http://api.example.com", "host": "api.example.com", "technologies": ["express"]}))
        store.add(Evidence(category="live_host", value="http://admin.example.com", source="httpx", metadata={"url": "http://admin.example.com", "host": "admin.example.com", "technologies": ["django"]}))
        store.add(Evidence(category="live_host", value="http://auth.example.com", source="httpx", metadata={"url": "http://auth.example.com", "host": "auth.example.com", "technologies": ["keycloak"]}))

        # Endpoints explicitly partitioned
        store.add(Evidence(category="endpoint", value="http://api.example.com/v1/users", source="katana", metadata={"url": "http://api.example.com/v1/users", "host": "api.example.com"}))
        store.add(Evidence(category="endpoint", value="http://admin.example.com/manage", source="katana", metadata={"url": "http://admin.example.com/manage", "host": "admin.example.com"}))

        # Vulnerability only on auth.example.com
        store.add(Evidence(category="vulnerability", value="CVE-KEYCLOAK-01", source="nuclei", metadata={"template_id": "CVE-KEYCLOAK-01", "host": "http://auth.example.com"}))

        graph = builder.build_from_evidence(store, target="example.com")

        # api host checks
        api_node = graph.get("live_host:http://api.example.com")
        api_eps = [e.target for e in graph.edges_from(api_node) if e.type == "HAS_ENDPOINT"]
        assert api_eps == ["endpoint:http://api.example.com/v1/users"]
        api_vulns = [e.target for e in graph.edges_from(api_node) if e.type == "HAS_VULNERABILITY"]
        assert api_vulns == []

        # admin host checks
        admin_node = graph.get("live_host:http://admin.example.com")
        admin_eps = [e.target for e in graph.edges_from(admin_node) if e.type == "HAS_ENDPOINT"]
        assert admin_eps == ["endpoint:http://admin.example.com/manage"]

        # auth host checks
        auth_node = graph.get("live_host:http://auth.example.com")
        auth_eps = [e.target for e in graph.edges_from(auth_node) if e.type == "HAS_ENDPOINT"]
        assert auth_eps == []
        auth_vulns = [e.target for e in graph.edges_from(auth_node) if e.type == "HAS_VULNERABILITY"]
        assert auth_vulns == ["vulnerability:CVE-KEYCLOAK-01"]


class TestAdversarialDiffEngine:
    """Stress testing AttackSurfaceDiffEngine against edge cases, complex drift, and symmetry."""

    def test_diff_empty_inputs(self):
        g_empty1 = KnowledgeGraph()
        g_empty2 = KnowledgeGraph()

        diff = AttackSurfaceDiffEngine.diff_graphs(g_empty1, g_empty2)
        assert diff.has_changes is False
        assert diff.total_changes() == 0
        assert diff.summary()["total_changes"] == 0

    def test_diff_all_removed_and_all_added(self):
        g_full = KnowledgeGraph()
        g_full.add(Node(id="target:example.com", type="target", value="example.com"))
        g_full.add(Node(id="subdomain:api.example.com", type="subdomain", value="api.example.com"))
        g_full.add(Node(id="live_host:http://api.example.com", type="live_host", value="http://api.example.com"))
        g_full.add(Node(id="endpoint:http://api.example.com/v1", type="endpoint", value="http://api.example.com/v1"))
        g_full.add(Node(id="technology:nginx", type="technology", value="nginx"))
        g_full.add(Node(id="vulnerability:cve-1", type="vulnerability", value="cve-1", metadata={"template_id": "cve-1"}))

        g_empty = KnowledgeGraph()

        # 1. Full -> Empty (All removed)
        diff_removed = AttackSurfaceDiffEngine.diff_graphs(g_full, g_empty)
        assert diff_removed.has_changes is True
        assert diff_removed.removed_subdomains == ["api.example.com"]
        assert diff_removed.removed_live_hosts == ["http://api.example.com"]
        assert diff_removed.removed_endpoints == ["http://api.example.com/v1"]
        assert diff_removed.removed_technologies == ["nginx"]
        assert len(diff_removed.removed_vulnerabilities) == 1
        assert diff_removed.new_subdomains == []
        assert diff_removed.new_live_hosts == []

        # 2. Empty -> Full (All added)
        diff_added = AttackSurfaceDiffEngine.diff_graphs(g_empty, g_full)
        assert diff_added.has_changes is True
        assert diff_added.new_subdomains == ["api.example.com"]
        assert diff_added.new_live_hosts == ["http://api.example.com"]
        assert diff_added.new_endpoints == ["http://api.example.com/v1"]
        assert diff_added.new_technologies == ["nginx"]
        assert len(diff_added.new_vulnerabilities) == 1
        assert diff_added.removed_subdomains == []

        # 3. Symmetry of counts
        assert diff_removed.total_changes() == diff_added.total_changes()

    def test_diff_fine_grained_host_drift(self):
        """Test isolated changes on a single live host."""
        # Baseline
        g1 = KnowledgeGraph()
        h1 = Node(id="live_host:http://api.example.com", type="live_host", value="http://api.example.com", metadata={"status": 200, "server": "nginx/1.18"})
        g1.add(h1)

        # 1. Only status code changes
        g2 = KnowledgeGraph()
        h2 = Node(id="live_host:http://api.example.com", type="live_host", value="http://api.example.com", metadata={"status": 502, "server": "nginx/1.18"})
        g2.add(h2)

        diff1 = AttackSurfaceDiffEngine.diff_graphs(g1, g2)
        assert len(diff1.changed_hosts) == 1
        ch = diff1.changed_hosts[0]
        assert ch.status_changed is True
        assert ch.old_status == 200
        assert ch.new_status == 502
        assert ch.server_changed is False
        assert ch.added_technologies == []
        assert ch.removed_technologies == []
        assert ch.has_changes is True

        # 2. Only server header changes
        g3 = KnowledgeGraph()
        h3 = Node(id="live_host:http://api.example.com", type="live_host", value="http://api.example.com", metadata={"status": 200, "server": "cloudflare"})
        g3.add(h3)

        diff2 = AttackSurfaceDiffEngine.diff_graphs(g1, g3)
        assert len(diff2.changed_hosts) == 1
        assert diff2.changed_hosts[0].status_changed is False
        assert diff2.changed_hosts[0].server_changed is True
        assert diff2.changed_hosts[0].old_server == "nginx/1.18"
        assert diff2.changed_hosts[0].new_server == "cloudflare"

    def test_diff_evidence_stores_with_different_targets(self):
        s1 = EvidenceStore()
        s1.add(Evidence(category="subdomain", value="sub1.corp.com", source="subfinder"))

        s2 = EvidenceStore()
        s2.add(Evidence(category="subdomain", value="sub1.corp.com", source="subfinder"))
        s2.add(Evidence(category="subdomain", value="sub2.corp.com", source="subfinder"))

        diff = AttackSurfaceDiffEngine.diff_evidence(s1, s2, base_target="corp.com", current_target="corp.com")
        assert diff.new_subdomains == ["sub2.corp.com"]
        assert diff.removed_subdomains == []


class TestAdversarialQueriesAndPlanning:
    """Stress testing graph queries and GapAnalyzer graph awareness."""

    def test_query_behavior_on_unconnected_nodes(self):
        graph = KnowledgeGraph()
        # 5 live hosts, none have endpoints, 2 have vulns
        for i in range(5):
            graph.add(Node(id=f"live_host:http://host{i}.com", type="live_host", value=f"http://host{i}.com"))

        graph.add(Node(id="vulnerability:cve-0", type="vulnerability", value="cve-0"))
        graph.add(Node(id="vulnerability:cve-1", type="vulnerability", value="cve-1"))
        graph.connect("live_host:http://host0.com", "vulnerability:cve-0", "HAS_VULNERABILITY")
        graph.connect("live_host:http://host1.com", "vulnerability:cve-1", "HAS_VULNERABILITY")

        # All 5 without endpoints
        uncovered_eps = graph.get_hosts_without_endpoints()
        assert len(uncovered_eps) == 5

        # 3 without vulns (host2, host3, host4)
        uncovered_vulns = graph.get_hosts_without_vulnerabilities()
        assert len(uncovered_vulns) == 3
        uncovered_vuln_ids = {n.id for n in uncovered_vulns}
        assert uncovered_vuln_ids == {
            "live_host:http://host2.com",
            "live_host:http://host3.com",
            "live_host:http://host4.com",
        }

        # Asset counts
        counts = graph.get_asset_counts()
        assert counts["live_host"] == 5
        assert counts["vulnerability"] == 2
        assert counts["endpoint"] == 0
        assert counts["target"] == 0

    def test_gap_analyzer_capped_related_assets(self):
        """Ensure GapAnalyzer handles large number of uncrawled hosts without exploding related_assets list."""
        mission = Mission(target="scale.test")
        store = EvidenceStore()
        for i in range(50):
            store.add(Evidence(category="subdomain", value=f"host{i}.scale.test", source="subfinder"))
            store.add(Evidence(category="live_host", value=f"http://host{i}.scale.test", source="httpx", metadata={"url": f"http://host{i}.scale.test", "host": f"host{i}.scale.test"}))

        AttackSurfaceGraphBuilder().build_from_evidence(store, target="scale.test", graph=mission.attack_surface_graph)

        gaps = GapAnalyzer(mission).analyze()
        ep_gap = next((g for g in gaps if g.area == "Endpoints"), None)
        assert ep_gap is not None
        # Must be capped at 10 to keep planner prompt sizes sane
        assert len(ep_gap.related_assets) <= 10


class TestScaleAndPerformance:
    """Stress testing scale limits: 1000+ assets with execution time benchmarks."""

    def test_large_scale_graph_building_benchmark(self):
        """Construct graph with 500 subdomains, 500 live hosts, 2500 endpoints, 100 techs, 500 vulns."""
        store = EvidenceStore()
        num_subs = 500
        num_eps_per_host = 5

        for i in range(num_subs):
            sub = f"sub{i}.bigtarget.com"
            url = f"https://{sub}"
            store.add(Evidence(category="subdomain", value=sub, source="subfinder", metadata={"hostname": sub}))
            store.add(Evidence(category="live_host", value=url, source="httpx", metadata={"url": url, "host": sub, "technologies": [f"tech_{i % 50}"]}))
            for ep_i in range(num_eps_per_host):
                ep_url = f"{url}/api/v1/resource_{ep_i}"
                store.add(Evidence(category="endpoint", value=ep_url, source="katana", metadata={"url": ep_url, "host": sub}))
            store.add(Evidence(category="vulnerability", value=f"CVE-2024-{10000+i}", source="nuclei", metadata={"template_id": f"CVE-2024-{10000+i}", "host": url}))

        builder = AttackSurfaceGraphBuilder()

        t_start = time.perf_counter()
        graph = builder.build_from_evidence(store, target="bigtarget.com")
        t_elapsed = time.perf_counter() - t_start

        # Target(1) + Subs(500) + Hosts(500) + EPs(2500) + Techs(50) + Vulns(500) = 4051 nodes
        assert graph.node_count() == 4051
        assert len(graph.nodes_by_type("endpoint")) == 2500
        assert len(graph.nodes_by_type("live_host")) == 500
        assert len(graph.nodes_by_type("subdomain")) == 500
        assert len(graph.nodes_by_type("vulnerability")) == 500

        # Query benchmarks on 4000+ node graph
        t_q_start = time.perf_counter()
        no_eps = graph.get_hosts_without_endpoints()
        no_vulns = graph.get_hosts_without_vulnerabilities()
        asset_counts = graph.get_asset_counts()
        t_q_elapsed = time.perf_counter() - t_q_start

        assert len(no_eps) == 0
        assert len(no_vulns) == 0
        assert asset_counts["endpoint"] == 2500

        # Performance assertions: Graph building under 2.5s, querying under 0.2s
        assert t_elapsed < 2.5, f"Graph building took too long: {t_elapsed:.3f}s"
        assert t_q_elapsed < 0.2, f"Graph querying took too long: {t_q_elapsed:.3f}s"

    def test_large_scale_diff_benchmark(self):
        """Diff two large graphs with 10% drift."""
        g1 = KnowledgeGraph()
        g2 = KnowledgeGraph()

        num_nodes = 1000
        for i in range(num_nodes):
            g1.add(Node(id=f"endpoint:http://app.com/api_{i}", type="endpoint", value=f"http://app.com/api_{i}"))

        # g2 has 900 common, 100 removed, 100 new
        for i in range(100, num_nodes + 100):
            g2.add(Node(id=f"endpoint:http://app.com/api_{i}", type="endpoint", value=f"http://app.com/api_{i}"))

        t_start = time.perf_counter()
        diff = AttackSurfaceDiffEngine.diff_graphs(g1, g2)
        t_elapsed = time.perf_counter() - t_start

        assert len(diff.new_endpoints) == 100
        assert len(diff.removed_endpoints) == 100
        assert diff.total_changes() == 200
        assert t_elapsed < 0.5, f"Large scale diff took too long: {t_elapsed:.3f}s"


class TestAdversarialComplexTopologies:
    """Stress tests on complex topological structures and namespace collisions."""

    def test_target_subdomain_livehost_same_name(self):
        """Test entity where target, subdomain, and live_host share exact same name string."""
        builder = AttackSurfaceGraphBuilder()
        store = EvidenceStore()
        store.add(Evidence(category="subdomain", value="target.com", source="subfinder"))
        store.add(Evidence(category="live_host", value="target.com", source="httpx", metadata={"host": "target.com"}))

        graph = builder.build_from_evidence(store, target="target.com")

        # 3 distinct nodes due to prefixing
        assert graph.node_count() == 3
        assert graph.get("target:target.com") is not None
        assert graph.get("subdomain:target.com") is not None
        assert graph.get("live_host:target.com") is not None

        # Edges: target -> subdomain (RESOLVES_TO), subdomain -> live_host (HOSTS)
        assert graph.edge_count() == 2

    def test_orphan_endpoints_and_vulnerabilities(self):
        """When multiple live hosts exist and endpoints/vulns don't match any host, they are preserved as nodes without incorrect edges."""
        builder = AttackSurfaceGraphBuilder()
        store = EvidenceStore()
        # 2 live hosts
        store.add(Evidence(category="live_host", value="http://h1.com", source="httpx", metadata={"url": "http://h1.com", "host": "h1.com"}))
        store.add(Evidence(category="live_host", value="http://h2.com", source="httpx", metadata={"url": "http://h2.com", "host": "h2.com"}))

        # Orphan endpoint (host = "h3.com")
        store.add(Evidence(category="endpoint", value="http://h3.com/api", source="katana", metadata={"url": "http://h3.com/api", "host": "h3.com"}))

        # Orphan vulnerability (host = "h4.com")
        store.add(Evidence(category="vulnerability", value="CVE-ORPHAN", source="nuclei", metadata={"template_id": "CVE-ORPHAN", "host": "http://h4.com"}))

        graph = builder.build_from_evidence(store, target="test.com")

        # Target(1) + Hosts(2) + EP(1) + Vuln(1) + Target auto-subdomains(2) = 6 nodes
        assert graph.get("endpoint:http://h3.com/api") is not None
        assert graph.get("vulnerability:CVE-ORPHAN") is not None

        # Verify no HAS_ENDPOINT or HAS_VULNERABILITY edges connected to h1 or h2
        h1 = graph.get("live_host:http://h1.com")
        h2 = graph.get("live_host:http://h2.com")
        assert len([e for e in graph.edges_from(h1) if e.type in ("HAS_ENDPOINT", "HAS_VULNERABILITY")]) == 0
        assert len([e for e in graph.edges_from(h2) if e.type in ("HAS_ENDPOINT", "HAS_VULNERABILITY")]) == 0

    def test_diff_engine_symmetric_and_inversion_properties(self):
        """Verify mathematical symmetry: diff(A, B).new == diff(B, A).removed."""
        m1 = Mission(target="example.com")
        m1.subdomains = ["a.com", "b.com"]
        m1.live_hosts = [{"url": "http://a.com", "status": 200, "technologies": ["techA"]}]

        m2 = Mission(target="example.com")
        m2.subdomains = ["b.com", "c.com"]
        m2.live_hosts = [{"url": "http://a.com", "status": 500, "technologies": ["techB"]}]

        diff_forward = AttackSurfaceDiffEngine.diff_missions(m1, m2)
        diff_reverse = AttackSurfaceDiffEngine.diff_missions(m2, m1)

        assert diff_forward.new_subdomains == diff_reverse.removed_subdomains
        assert diff_forward.removed_subdomains == diff_reverse.new_subdomains

        ch_f = diff_forward.changed_hosts[0]
        ch_r = diff_reverse.changed_hosts[0]
        assert ch_f.old_status == ch_r.new_status
        assert ch_f.new_status == ch_r.old_status
        assert ch_f.added_technologies == ch_r.removed_technologies
        assert ch_f.removed_technologies == ch_r.added_technologies

    def test_knowledge_graph_summary_vs_asset_counts(self):
        """Verify KnowledgeGraph summary() and get_asset_counts() are completely in sync."""
        graph = KnowledgeGraph()
        graph.add(Node(id="target:x.com", type="target", value="x.com"))
        graph.add(Node(id="subdomain:x.com", type="subdomain", value="x.com"))
        graph.add(Node(id="live_host:http://x.com", type="live_host", value="http://x.com"))
        graph.add(Node(id="endpoint:http://x.com/a", type="endpoint", value="http://x.com/a"))
        graph.add(Node(id="endpoint:http://x.com/b", type="endpoint", value="http://x.com/b"))
        graph.add(Node(id="technology:nginx", type="technology", value="nginx"))
        graph.add(Node(id="vulnerability:cve-1", type="vulnerability", value="cve-1"))

        graph.connect("target:x.com", "subdomain:x.com", "RESOLVES_TO")
        graph.connect("subdomain:x.com", "live_host:http://x.com", "HOSTS")

        summary = graph.summary()
        assert summary["Node Count"] == 7
        assert summary["Relationship Count"] == 2
        assert summary["target Nodes"] == 1
        assert summary["subdomain Nodes"] == 1
        assert summary["live_host Nodes"] == 1
        assert summary["endpoint Nodes"] == 2
        assert summary["technology Nodes"] == 1
        assert summary["vulnerability Nodes"] == 1

        asset_counts = graph.get_asset_counts()
        assert asset_counts["target"] == 1
        assert asset_counts["subdomain"] == 1
        assert asset_counts["live_host"] == 1
        assert asset_counts["endpoint"] == 2
        assert asset_counts["technology"] == 1
        assert asset_counts["vulnerability"] == 1
