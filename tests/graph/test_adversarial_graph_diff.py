import pytest
import random
import string
import urllib.parse
from argus.graph.graph import KnowledgeGraph
from argus.graph.node import Node
from argus.graph.edge import Edge
from argus.graph.attack_surface import AttackSurfaceGraphBuilder
from argus.graph.diff import AttackSurfaceDiffEngine, HostChange, AttackSurfaceDiff
from argus.evidence.store import EvidenceStore
from argus.evidence.model import Evidence
from argus.runtime.mission import Mission, MissionState
from argus.planning.gap_analysis import GapAnalyzer
from argus.planning.models import TaskCategory

class TestAdversarialGraphQueries:
    """
    Stress-testing graph query correctness, boundary cases, and edge filtering.
    """

    def test_empty_graph_queries(self):
        graph = KnowledgeGraph()
        assert graph.get_hosts_without_endpoints() == []
        assert graph.get_hosts_without_vulnerabilities() == []
        counts = graph.get_asset_counts()
        assert counts == {
            "target": 0,
            "subdomain": 0,
            "live_host": 0,
            "endpoint": 0,
            "technology": 0,
            "vulnerability": 0,
        }

    def test_queries_with_non_host_nodes_and_spurious_edges(self):
        """Ensure other node types with/without edges don't get misidentified as live hosts."""
        graph = KnowledgeGraph()
        graph.add(Node(id="target:example.com", type="target", value="example.com"))
        graph.add(Node(id="subdomain:api.example.com", type="subdomain", value="api.example.com"))
        graph.add(Node(id="endpoint:https://api.example.com/login", type="endpoint", value="https://api.example.com/login"))
        graph.add(Node(id="technology:nginx", type="technology", value="nginx"))
        graph.add(Node(id="vulnerability:cve-2023-1234", type="vulnerability", value="cve-2023-1234"))
        
        # Connect target -> subdomain (RESOLVES_TO)
        graph.connect("target:example.com", "subdomain:api.example.com", "RESOLVES_TO")
        # Spurious HAS_ENDPOINT from subdomain to endpoint
        graph.connect("subdomain:api.example.com", "endpoint:https://api.example.com/login", "HAS_ENDPOINT")
        # Spurious HAS_VULNERABILITY from target to vuln
        graph.connect("target:example.com", "vulnerability:cve-2023-1234", "HAS_VULNERABILITY")

        # Zero live hosts exist, so query results MUST be empty
        assert graph.get_hosts_without_endpoints() == []
        assert graph.get_hosts_without_vulnerabilities() == []

    def test_partially_covered_hosts_matrix(self):
        """
        Matrix of 4 live hosts:
        H1: Has endpoints, Has vulns -> excluded from both
        H2: Has endpoints, No vulns -> excluded from endpoints, included in vulns
        H3: No endpoints, Has vulns -> included in endpoints, excluded from vulns
        H4: No endpoints, No vulns -> included in both
        """
        graph = KnowledgeGraph()
        h1 = Node(id="live_host:https://h1.com", type="live_host", value="https://h1.com")
        h2 = Node(id="live_host:https://h2.com", type="live_host", value="https://h2.com")
        h3 = Node(id="live_host:https://h3.com", type="live_host", value="https://h3.com")
        h4 = Node(id="live_host:https://h4.com", type="live_host", value="https://h4.com")
        for h in [h1, h2, h3, h4]:
            graph.add(h)

        ep1 = Node(id="endpoint:https://h1.com/api", type="endpoint", value="https://h1.com/api")
        ep2 = Node(id="endpoint:https://h2.com/api", type="endpoint", value="https://h2.com/api")
        v1 = Node(id="vulnerability:cve-1", type="vulnerability", value="cve-1")
        v3 = Node(id="vulnerability:cve-3", type="vulnerability", value="cve-3")
        for item in [ep1, ep2, v1, v3]:
            graph.add(item)

        # H1 has ep1 and v1
        graph.connect(h1.id, ep1.id, "HAS_ENDPOINT")
        graph.connect(h1.id, v1.id, "HAS_VULNERABILITY")

        # H2 has ep2 only
        graph.connect(h2.id, ep2.id, "HAS_ENDPOINT")

        # H3 has v3 only
        graph.connect(h3.id, v3.id, "HAS_VULNERABILITY")

        # H4 has nothing

        no_ep = graph.get_hosts_without_endpoints()
        no_ep_ids = {n.id for n in no_ep}
        assert no_ep_ids == {h3.id, h4.id}

        no_vuln = graph.get_hosts_without_vulnerabilities()
        no_vuln_ids = {n.id for n in no_vuln}
        assert no_vuln_ids == {h2.id, h4.id}

    def test_custom_and_unknown_node_types_in_asset_counts(self):
        graph = KnowledgeGraph()
        graph.add(Node(id="target:t", type="target", value="t"))
        graph.add(Node(id="custom:1", type="cloud_bucket", value="s3://secret"))
        graph.add(Node(id="custom:2", type="api_gateway", value="apigw-1"))

        counts = graph.get_asset_counts()
        assert counts["target"] == 1
        assert counts["cloud_bucket"] == 1
        assert counts["api_gateway"] == 1
        assert counts["live_host"] == 0


class TestAdversarialDiffEngine:
    """
    Stress-testing diff engine accuracy, in-place host drift detection, and randomized mutations.
    """

    def test_identical_complex_graphs_produce_zero_diff(self):
        builder = AttackSurfaceGraphBuilder()
        store = EvidenceStore()
        store.add(Evidence(category="subdomain", value="sub1.target.com", source="subfinder"))
        store.add(Evidence(category="live_host", value="https://sub1.target.com", source="httpx", metadata={"status": 200, "server": "nginx", "technologies": ["react", "express"]}))
        store.add(Evidence(category="endpoint", value="https://sub1.target.com/api/v1", source="katana"))
        store.add(Evidence(category="vulnerability", value="cors-misconfig", source="nuclei", metadata={"severity": "medium"}))

        g1 = builder.build_from_evidence(store, target="target.com")
        g2 = builder.build_from_evidence(store, target="target.com")

        diff = AttackSurfaceDiffEngine.diff_graphs(g1, g2)
        assert not diff.has_changes
        assert diff.total_changes() == 0
        assert len(diff.changed_hosts) == 0

    def test_in_place_host_drift_all_dimensions(self):
        """Test status change, server change, tech added/removed, ep added/removed, vuln added/removed."""
        g_base = KnowledgeGraph()
        g_curr = KnowledgeGraph()

        # Host node in base
        h_base = Node(
            id="live_host:https://app.target.com",
            type="live_host",
            value="https://app.target.com",
            metadata={"status": 200, "server": "Apache/2.4"}
        )
        # Host node in current: status 200 -> 500, server Apache -> Nginx
        h_curr = Node(
            id="live_host:https://app.target.com",
            type="live_host",
            value="https://app.target.com",
            metadata={"status": 500, "server": "Nginx/1.24"}
        )
        g_base.add(h_base)
        g_curr.add(h_curr)

        # Base technologies: php, jquery
        # Curr technologies: jquery, nodejs (php removed, nodejs added)
        t_php = Node(id="technology:PHP", type="technology", value="PHP")
        t_jq = Node(id="technology:jQuery", type="technology", value="jQuery")
        t_node = Node(id="technology:NodeJS", type="technology", value="NodeJS")
        g_base.add(t_php); g_base.add(t_jq)
        g_curr.add(t_jq); g_curr.add(t_node)
        g_base.connect(h_base.id, t_php.id, "RUNS_TECHNOLOGY")
        g_base.connect(h_base.id, t_jq.id, "RUNS_TECHNOLOGY")
        g_curr.connect(h_curr.id, t_jq.id, "RUNS_TECHNOLOGY")
        g_curr.connect(h_curr.id, t_node.id, "RUNS_TECHNOLOGY")

        # Base endpoints: /login, /old-api
        # Curr endpoints: /login, /new-api (/old-api removed, /new-api added)
        ep_login = Node(id="endpoint:https://app.target.com/login", type="endpoint", value="https://app.target.com/login")
        ep_old = Node(id="endpoint:https://app.target.com/old-api", type="endpoint", value="https://app.target.com/old-api")
        ep_new = Node(id="endpoint:https://app.target.com/new-api", type="endpoint", value="https://app.target.com/new-api")
        g_base.add(ep_login); g_base.add(ep_old)
        g_curr.add(ep_login); g_curr.add(ep_new)
        g_base.connect(h_base.id, ep_login.id, "HAS_ENDPOINT")
        g_base.connect(h_base.id, ep_old.id, "HAS_ENDPOINT")
        g_curr.connect(h_curr.id, ep_login.id, "HAS_ENDPOINT")
        g_curr.connect(h_curr.id, ep_new.id, "HAS_ENDPOINT")

        # Base vulns: vuln-1
        # Curr vulns: vuln-2 (vuln-1 removed, vuln-2 added)
        v1 = Node(id="vulnerability:cve-old", type="vulnerability", value="cve-old", metadata={"template_id": "cve-old"})
        v2 = Node(id="vulnerability:cve-new", type="vulnerability", value="cve-new", metadata={"template_id": "cve-new"})
        g_base.add(v1)
        g_curr.add(v2)
        g_base.connect(h_base.id, v1.id, "HAS_VULNERABILITY")
        g_curr.connect(h_curr.id, v2.id, "HAS_VULNERABILITY")

        diff = AttackSurfaceDiffEngine.diff_graphs(g_base, g_curr)
        assert diff.has_changes
        assert len(diff.changed_hosts) == 1
        hc = diff.changed_hosts[0]

        assert hc.host == "https://app.target.com"
        assert hc.status_changed is True
        assert hc.old_status == 200
        assert hc.new_status == 500
        assert hc.server_changed is True
        assert hc.old_server == "Apache/2.4"
        assert hc.new_server == "Nginx/1.24"

        assert hc.added_technologies == ["NodeJS"]
        assert hc.removed_technologies == ["PHP"]
        assert hc.added_endpoints == ["https://app.target.com/new-api"]
        assert hc.removed_endpoints == ["https://app.target.com/old-api"]
        assert hc.added_vulnerabilities == ["cve-new"]
        assert hc.removed_vulnerabilities == ["cve-old"]

    def test_randomized_fuzzing_diff_invariants(self):
        """
        Property-based fuzzing:
        Generate random sets of subdomains, hosts, endpoints, tech, and vulns.
        Verify diff engine invariants:
        - len(new) + len(common) == len(current)
        - len(removed) + len(common) == len(base)
        - total_changes matches summary()['total_changes']
        """
        rng = random.Random(42)
        
        for iteration in range(25):
            all_subs = [f"sub{i}.target.com" for i in range(20)]
            all_eps = [f"https://target.com/path{i}" for i in range(30)]
            all_techs = [f"tech_{i}" for i in range(10)]
            
            base_subs = set(rng.sample(all_subs, k=rng.randint(0, 15)))
            curr_subs = set(rng.sample(all_subs, k=rng.randint(0, 15)))
            
            base_eps = set(rng.sample(all_eps, k=rng.randint(0, 20)))
            curr_eps = set(rng.sample(all_eps, k=rng.randint(0, 20)))
            
            base_techs = set(rng.sample(all_techs, k=rng.randint(0, 8)))
            curr_techs = set(rng.sample(all_techs, k=rng.randint(0, 8)))

            g_base = KnowledgeGraph()
            for s in base_subs: g_base.add(Node(id=f"subdomain:{s}", type="subdomain", value=s))
            for e in base_eps: g_base.add(Node(id=f"endpoint:{e}", type="endpoint", value=e))
            for t in base_techs: g_base.add(Node(id=f"technology:{t}", type="technology", value=t))

            g_curr = KnowledgeGraph()
            for s in curr_subs: g_curr.add(Node(id=f"subdomain:{s}", type="subdomain", value=s))
            for e in curr_eps: g_curr.add(Node(id=f"endpoint:{e}", type="endpoint", value=e))
            for t in curr_techs: g_curr.add(Node(id=f"technology:{t}", type="technology", value=t))

            diff = AttackSurfaceDiffEngine.diff_graphs(g_base, g_curr)

            # Invariant check: Subdomains
            assert set(diff.new_subdomains) == (curr_subs - base_subs)
            assert set(diff.removed_subdomains) == (base_subs - curr_subs)

            # Invariant check: Endpoints
            assert set(diff.new_endpoints) == (curr_eps - base_eps)
            assert set(diff.removed_endpoints) == (base_eps - curr_eps)

            # Invariant check: Technologies
            assert set(diff.new_technologies) == (curr_techs - base_techs)
            assert set(diff.removed_technologies) == (base_techs - curr_techs)

            # Summary invariant
            summary = diff.summary()
            assert summary["total_changes"] == diff.total_changes()
            assert (diff.has_changes == (diff.total_changes() > 0))


class TestAdversarialGraphBuilder:
    """
    Stress-testing builder with strange URLs, weird metadata, and complex topologies.
    """

    def test_urls_with_ports_schemes_and_query_parameters(self):
        builder = AttackSurfaceGraphBuilder()
        store = EvidenceStore()

        store.add(Evidence(category="subdomain", value="api.example.com", source="subfinder"))
        store.add(Evidence(category="live_host", value="https://api.example.com:8443", source="httpx", metadata={"url": "https://api.example.com:8443", "host": "api.example.com"}))
        store.add(Evidence(category="endpoint", value="https://api.example.com:8443/graphql?query={user}", source="katana"))
        store.add(Evidence(category="vulnerability", value="cve-2024-0001", source="nuclei", metadata={"host": "https://api.example.com:8443", "template_id": "cve-2024-0001"}))

        graph = builder.build_from_evidence(store, target="example.com")
        
        # Verify node counts: 1 target, 1 subdomain, 1 live_host, 1 endpoint, 1 vulnerability = 5
        assert graph.node_count() == 5
        assert graph.get_asset_counts()["live_host"] == 1
        assert graph.get_asset_counts()["endpoint"] == 1
        assert graph.get_asset_counts()["vulnerability"] == 1

        # Verify edge connections
        lh_node = graph.nodes_by_type("live_host")[0]
        outgoing_edges = graph.edges_from(lh_node)
        edge_types = {e.type for e in outgoing_edges}
        assert "HAS_ENDPOINT" in edge_types
        assert "HAS_VULNERABILITY" in edge_types

        # Queries
        assert graph.get_hosts_without_endpoints() == []
        assert graph.get_hosts_without_vulnerabilities() == []

    def test_missing_metadata_and_fallbacks(self):
        """Test builder robustness when evidence items have no metadata or non-standard fields."""
        builder = AttackSurfaceGraphBuilder()
        store = EvidenceStore()

        # Evidence with None metadata
        store.add(Evidence(category="subdomain", value="fallback.example.com", source="manual", metadata={}))
        store.add(Evidence(category="live_host", value="http://fallback.example.com", source="manual", metadata={}))
        store.add(Evidence(category="technology", value="ExpressJS", source="manual", metadata={}))
        store.add(Evidence(category="endpoint", value="http://fallback.example.com/health", source="manual", metadata={}))
        store.add(Evidence(category="vulnerability", value="info-leak", source="manual", metadata={}))

        graph = builder.build_from_evidence(store, target="example.com")
        assert graph.node_count() == 6 # target + 5 assets
        assert graph.edge_count() >= 5


class TestAdversarialRuntimeAndPlanningIntegration:
    """
    Stress-testing mission runtime integration, dual-mode gap analysis, and replanning.
    """

    def test_gap_analyzer_graph_vs_bare_fallback_equivalence(self):
        """
        Verify that GapAnalyzer behaves consistently whether mission has a populated graph
        or bare mission lists.
        """
        # Case A: Bare mission (no graph)
        mission_bare = Mission(
            target="example.com",
            subdomains=["sub1.example.com"],
            live_hosts=[{"url": "https://sub1.example.com", "host": "sub1.example.com"}],
            endpoints=[], # No endpoints
            vulnerabilities=[] # No vulns
        )
        mission_bare.attack_surface_graph = None
        mission_bare.graph = None
        analyzer_bare = GapAnalyzer(mission_bare)
        gaps_bare = analyzer_bare._check_recon_gaps()
        bare_areas = {g.area for g in gaps_bare}
        assert "Endpoints" in bare_areas
        assert "Vulnerability Scanning" in bare_areas

        # Case B: Graph-populated mission
        mission_graph = Mission(
            target="example.com",
            subdomains=["sub1.example.com"],
            live_hosts=[{"url": "https://sub1.example.com", "host": "sub1.example.com"}],
            endpoints=[],
            vulnerabilities=[]
        )
        AttackSurfaceGraphBuilder().build(mission_graph)
        analyzer_graph = GapAnalyzer(mission_graph)
        gaps_graph = analyzer_graph._check_recon_gaps()
        graph_areas = {g.area for g in gaps_graph}
        assert "Endpoints" in graph_areas
        assert "Vulnerability Scanning" in graph_areas
        # Verify related_assets has the specific uncrawled/unscanned host
        endpoint_gap = next(g for g in gaps_graph if g.area == "Endpoints")
        assert "https://sub1.example.com" in endpoint_gap.related_assets

class TestAdversarialComplexTopologies:
    """
    Stress-testing large-scale, heterogeneous, and multi-tenant asset graphs.
    """

    def test_multi_host_heterogeneous_graph(self):
        builder = AttackSurfaceGraphBuilder()
        store = EvidenceStore()

        # 5 Subdomains
        for i in range(5):
            store.add(Evidence(category="subdomain", value=f"sub{i}.corp.com", source="subfinder"))

        # 5 Live hosts:
        # Host 0: http://sub0.corp.com (has ep, has tech, has vuln)
        # Host 1: https://sub1.corp.com:8443 (has ep, no tech, no vuln)
        # Host 2: sub2.corp.com (no ep, has tech, has vuln)
        # Host 3: https://sub3.corp.com (no ep, no tech, has vuln)
        # Host 4: https://sub4.corp.com (no ep, no tech, no vuln)
        store.add(Evidence(category="live_host", value="http://sub0.corp.com", source="httpx", metadata={"host": "sub0.corp.com", "technologies": ["nginx"]}))
        store.add(Evidence(category="live_host", value="https://sub1.corp.com:8443", source="httpx", metadata={"host": "sub1.corp.com"}))
        store.add(Evidence(category="live_host", value="sub2.corp.com", source="httpx", metadata={"host": "sub2.corp.com", "technologies": ["apache"]}))
        store.add(Evidence(category="live_host", value="https://sub3.corp.com", source="httpx", metadata={"host": "sub3.corp.com"}))
        store.add(Evidence(category="live_host", value="https://sub4.corp.com", source="httpx", metadata={"host": "sub4.corp.com"}))

        # Endpoints for Host 0 and Host 1
        store.add(Evidence(category="endpoint", value="http://sub0.corp.com/api/v1", source="katana", metadata={"host": "sub0.corp.com"}))
        store.add(Evidence(category="endpoint", value="http://sub0.corp.com/login", source="katana", metadata={"host": "sub0.corp.com"}))
        store.add(Evidence(category="endpoint", value="https://sub1.corp.com:8443/docs", source="katana", metadata={"host": "sub1.corp.com"}))

        # Vulns for Host 0, Host 2, Host 3
        store.add(Evidence(category="vulnerability", value="xss-0", source="nuclei", metadata={"host": "http://sub0.corp.com"}))
        store.add(Evidence(category="vulnerability", value="sqli-2", source="nuclei", metadata={"host": "sub2.corp.com"}))
        store.add(Evidence(category="vulnerability", value="rce-3", source="nuclei", metadata={"host": "https://sub3.corp.com"}))

        graph = builder.build_from_evidence(store, target="corp.com")

        # Verify asset counts
        counts = graph.get_asset_counts()
        assert counts["target"] == 1
        assert counts["subdomain"] == 5
        assert counts["live_host"] == 5
        assert counts["endpoint"] == 3
        assert counts["technology"] == 2
        assert counts["vulnerability"] == 3

        # Verify get_hosts_without_endpoints:
        # Should be Host 2, Host 3, Host 4
        no_eps = graph.get_hosts_without_endpoints()
        no_eps_vals = {n.value for n in no_eps}
        assert no_eps_vals == {"sub2.corp.com", "https://sub3.corp.com", "https://sub4.corp.com"}

        # Verify get_hosts_without_vulnerabilities:
        # Should be Host 1, Host 4
        no_vulns = graph.get_hosts_without_vulnerabilities()
        no_vulns_vals = {n.value for n in no_vulns}
        assert no_vulns_vals == {"https://sub1.corp.com:8443", "https://sub4.corp.com"}

    def test_e2e_mission_delta_workflow(self):
        """
        Simulate Cycle 1 vs Cycle 2 of an E2E mission workflow.
        """
        # Cycle 1: Baseline mission
        m1 = Mission(target="corp.com")
        m1.subdomains = ["a.corp.com", "b.corp.com"]
        m1.live_hosts = [
            {"url": "https://a.corp.com", "host": "a.corp.com", "status": 200, "technologies": ["react"]},
            {"url": "https://b.corp.com", "host": "b.corp.com", "status": 200, "technologies": ["express"]}
        ]
        m1.endpoints = ["https://a.corp.com/index.html"]
        m1.vulnerabilities = []

        # Cycle 2: Subdomain b removed, c added. Host a status changed to 503 and added a vulnerability.
        m2 = Mission(target="corp.com")
        m2.subdomains = ["a.corp.com", "c.corp.com"]
        m2.live_hosts = [
            {"url": "https://a.corp.com", "host": "a.corp.com", "status": 503, "technologies": ["react", "vue"]},
            {"url": "https://c.corp.com", "host": "c.corp.com", "status": 200, "technologies": ["flask"]}
        ]
        m2.endpoints = ["https://a.corp.com/index.html", "https://c.corp.com/api"]
        m2.vulnerabilities = [{"template_id": "cve-2024-9999", "host": "https://a.corp.com", "severity": "critical"}]

        diff = AttackSurfaceDiffEngine.diff_missions(m1, m2)

        assert diff.new_subdomains == ["c.corp.com"]
        assert diff.removed_subdomains == ["b.corp.com"]
        assert diff.new_live_hosts == ["https://c.corp.com"]
        assert diff.removed_live_hosts == ["https://b.corp.com"]
        assert diff.new_endpoints == ["https://c.corp.com/api"]
        assert diff.removed_endpoints == []
        assert "flask" in diff.new_technologies
        assert "express" in diff.removed_technologies
        assert len(diff.new_vulnerabilities) == 1

        # Check host a drift
        assert len(diff.changed_hosts) == 1
        hc = diff.changed_hosts[0]
        assert hc.host == "https://a.corp.com"
        assert hc.status_changed is True
        assert hc.old_status == 200
        assert hc.new_status == 503
        assert hc.added_technologies == ["vue"]
        assert hc.added_vulnerabilities == ["cve-2024-9999"]
