"""
Unit tests for KnowledgeGraph query methods and GapAnalyzer graph integration (R2).
"""
import pytest
from argus.graph import KnowledgeGraph, Node, Edge, AttackSurfaceGraphBuilder
from argus.evidence.store import EvidenceStore
from argus.evidence.model import Evidence
from argus.runtime.mission import Mission
from argus.planning.gap_analysis import GapAnalyzer
from argus.planning.models import TaskCategory


class TestGraphQueries:
    """Test suite for KnowledgeGraph query interface."""

    def test_get_hosts_without_endpoints(self):
        graph = KnowledgeGraph()
        # 3 live hosts
        h1 = Node(id="live_host:http://host1.com", type="live_host", value="http://host1.com")
        h2 = Node(id="live_host:http://host2.com", type="live_host", value="http://host2.com")
        h3 = Node(id="live_host:http://host3.com", type="live_host", value="http://host3.com")
        ep1 = Node(id="endpoint:http://host1.com/api", type="endpoint", value="http://host1.com/api")

        graph.add(h1)
        graph.add(h2)
        graph.add(h3)
        graph.add(ep1)

        # Connect h1 -> ep1
        graph.connect("live_host:http://host1.com", "endpoint:http://host1.com/api", "HAS_ENDPOINT")

        uncovered = graph.get_hosts_without_endpoints()
        uncovered_ids = {n.id for n in uncovered}
        assert uncovered_ids == {"live_host:http://host2.com", "live_host:http://host3.com"}

    def test_get_hosts_without_vulnerabilities(self):
        graph = KnowledgeGraph()
        h1 = Node(id="live_host:http://host1.com", type="live_host", value="http://host1.com")
        h2 = Node(id="live_host:http://host2.com", type="live_host", value="http://host2.com")
        v1 = Node(id="vulnerability:cve-1", type="vulnerability", value="cve-1")

        graph.add(h1)
        graph.add(h2)
        graph.add(v1)

        graph.connect("live_host:http://host1.com", "vulnerability:cve-1", "HAS_VULNERABILITY")

        unscanned = graph.get_hosts_without_vulnerabilities()
        assert len(unscanned) == 1
        assert unscanned[0].id == "live_host:http://host2.com"

    def test_get_asset_counts(self):
        graph = KnowledgeGraph()
        graph.add(Node(id="target:example.com", type="target", value="example.com"))
        graph.add(Node(id="subdomain:a.example.com", type="subdomain", value="a.example.com"))
        graph.add(Node(id="subdomain:b.example.com", type="subdomain", value="b.example.com"))
        graph.add(Node(id="live_host:http://a.example.com", type="live_host", value="http://a.example.com"))
        graph.add(Node(id="endpoint:http://a.example.com/login", type="endpoint", value="http://a.example.com/login"))
        graph.add(Node(id="technology:nginx", type="technology", value="nginx"))
        graph.add(Node(id="vulnerability:CVE-2023-0001", type="vulnerability", value="CVE-2023-0001"))

        counts = graph.get_asset_counts()
        assert counts["target"] == 1
        assert counts["subdomain"] == 2
        assert counts["live_host"] == 1
        assert counts["endpoint"] == 1
        assert counts["technology"] == 1
        assert counts["vulnerability"] == 1

    def test_gap_analyzer_identifies_uncrawled_hosts_via_graph(self):
        """GapAnalyzer targets uncovered hosts from graph in related_assets."""
        mission = Mission(target="example.com")
        # Build graph with 2 hosts, 1 crawled
        store = EvidenceStore()
        store.add(Evidence(category="subdomain", value="api.example.com", source="subfinder"))
        store.add(Evidence(category="subdomain", value="admin.example.com", source="subfinder"))
        store.add(Evidence(category="live_host", value="http://api.example.com", source="httpx", metadata={"url": "http://api.example.com", "host": "api.example.com"}))
        store.add(Evidence(category="live_host", value="http://admin.example.com", source="httpx", metadata={"url": "http://admin.example.com", "host": "admin.example.com"}))
        store.add(Evidence(category="endpoint", value="http://api.example.com/v1", source="katana", metadata={"url": "http://api.example.com/v1", "host": "api.example.com"}))

        AttackSurfaceGraphBuilder().build_from_evidence(store, target="example.com", graph=mission.attack_surface_graph)

        gaps = GapAnalyzer(mission).analyze()
        ep_gap = next((g for g in gaps if g.area == "Endpoints"), None)
        assert ep_gap is not None
        assert "http://admin.example.com" in ep_gap.related_assets
        assert "http://api.example.com" not in ep_gap.related_assets

    def test_gap_analyzer_fully_covered_graph_produces_no_recon_gaps(self):
        """When all live hosts in graph have endpoints and vulnerabilities, no recon gaps remain."""
        mission = Mission(target="example.com")
        store = EvidenceStore()
        store.add(Evidence(category="subdomain", value="api.example.com", source="subfinder"))
        store.add(Evidence(category="live_host", value="http://api.example.com", source="httpx", metadata={"url": "http://api.example.com", "host": "api.example.com"}))
        store.add(Evidence(category="endpoint", value="http://api.example.com/v1", source="katana", metadata={"url": "http://api.example.com/v1", "host": "api.example.com"}))
        store.add(Evidence(category="vulnerability", value="CVE-2023-XXXX", source="nuclei", metadata={"template_id": "CVE-2023-XXXX", "host": "http://api.example.com"}))

        mission.evidence = store
        mission.technologies = ["nginx"]
        AttackSurfaceGraphBuilder().build(mission)

        gaps = GapAnalyzer(mission).analyze()
        recon_areas = {"Subdomains", "Live Hosts", "Endpoints", "Vulnerability Scanning"}
        discovered_areas = {g.area for g in gaps}
        assert not (recon_areas & discovered_areas)
