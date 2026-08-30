"""
Unit tests for AttackSurfaceDiffEngine, AttackSurfaceDiff, and HostChange (R3).
"""
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


class TestAttackSurfaceDiff:
    """Test suite for AttackSurfaceDiffEngine."""

    def test_r3_subdomain_delta(self):
        """Comparing [a.example.com, b.example.com] vs [b.example.com, c.example.com]."""
        m1 = Mission(target="example.com")
        m1.subdomains = ["a.example.com", "b.example.com"]

        m2 = Mission(target="example.com")
        m2.subdomains = ["b.example.com", "c.example.com"]

        diff = AttackSurfaceDiffEngine.diff_missions(m1, m2)
        assert isinstance(diff, AttackSurfaceDiff)
        assert diff.new_subdomains == ["c.example.com"]
        assert diff.removed_subdomains == ["a.example.com"]
        assert diff.has_changes is True

    def test_r3_additions_and_removals_across_all_asset_types(self):
        """Verify delta calculation for subdomains, live hosts, endpoints, tech, vulns."""
        g1 = KnowledgeGraph()
        g1.add(Node(id="target:example.com", type="target", value="example.com"))
        g1.add(Node(id="subdomain:sub1.example.com", type="subdomain", value="sub1.example.com"))
        g1.add(Node(id="live_host:http://sub1.example.com", type="live_host", value="http://sub1.example.com", metadata={"status": 200, "server": "nginx"}))
        g1.add(Node(id="endpoint:http://sub1.example.com/old", type="endpoint", value="http://sub1.example.com/old"))
        g1.add(Node(id="technology:apache", type="technology", value="apache"))
        g1.add(Node(id="vulnerability:cve-old", type="vulnerability", value="cve-old", metadata={"template_id": "cve-old", "severity": "low"}))

        g2 = KnowledgeGraph()
        g2.add(Node(id="target:example.com", type="target", value="example.com"))
        g2.add(Node(id="subdomain:sub2.example.com", type="subdomain", value="sub2.example.com"))
        g2.add(Node(id="live_host:http://sub2.example.com", type="live_host", value="http://sub2.example.com", metadata={"status": 200, "server": "caddy"}))
        g2.add(Node(id="endpoint:http://sub2.example.com/new", type="endpoint", value="http://sub2.example.com/new"))
        g2.add(Node(id="technology:nginx", type="technology", value="nginx"))
        g2.add(Node(id="vulnerability:cve-new", type="vulnerability", value="cve-new", metadata={"template_id": "cve-new", "severity": "critical"}))

        diff = AttackSurfaceDiffEngine.diff_graphs(g1, g2)

        assert diff.new_subdomains == ["sub2.example.com"]
        assert diff.removed_subdomains == ["sub1.example.com"]
        assert diff.new_live_hosts == ["http://sub2.example.com"]
        assert diff.removed_live_hosts == ["http://sub1.example.com"]
        assert diff.new_endpoints == ["http://sub2.example.com/new"]
        assert diff.removed_endpoints == ["http://sub1.example.com/old"]
        assert diff.new_technologies == ["nginx"]
        assert diff.removed_technologies == ["apache"]
        assert len(diff.new_vulnerabilities) == 1
        assert diff.new_vulnerabilities[0]["template_id"] == "cve-new"
        assert len(diff.removed_vulnerabilities) == 1
        assert diff.removed_vulnerabilities[0]["template_id"] == "cve-old"

    def test_r3_in_place_host_changes(self):
        """Verify drift detection on identical host (status change, server change, added tech/eps)."""
        g1 = KnowledgeGraph()
        h1 = Node(id="live_host:http://api.example.com", type="live_host", value="http://api.example.com", metadata={"status": 200, "server": "nginx"})
        t1 = Node(id="technology:react", type="technology", value="react")
        ep1 = Node(id="endpoint:http://api.example.com/v1", type="endpoint", value="http://api.example.com/v1")
        g1.add(h1)
        g1.add(t1)
        g1.add(ep1)
        g1.connect(h1.id, t1.id, "RUNS_TECHNOLOGY")
        g1.connect(h1.id, ep1.id, "HAS_ENDPOINT")

        g2 = KnowledgeGraph()
        h2 = Node(id="live_host:http://api.example.com", type="live_host", value="http://api.example.com", metadata={"status": 500, "server": "gunicorn"})
        t2 = Node(id="technology:vue", type="technology", value="vue")
        ep2 = Node(id="endpoint:http://api.example.com/v2", type="endpoint", value="http://api.example.com/v2")
        v2 = Node(id="vulnerability:cve-x", type="vulnerability", value="cve-x")
        g2.add(h2)
        g2.add(t2)
        g2.add(ep2)
        g2.add(v2)
        g2.connect(h2.id, t2.id, "RUNS_TECHNOLOGY")
        g2.connect(h2.id, ep2.id, "HAS_ENDPOINT")
        g2.connect(h2.id, v2.id, "HAS_VULNERABILITY")

        diff = AttackSurfaceDiffEngine.diff_graphs(g1, g2)
        assert len(diff.changed_hosts) == 1
        ch = diff.changed_hosts[0]

        assert ch.host == "http://api.example.com"
        assert ch.status_changed is True
        assert ch.old_status == 200
        assert ch.new_status == 500
        assert ch.server_changed is True
        assert ch.old_server == "nginx"
        assert ch.new_server == "gunicorn"
        assert ch.added_technologies == ["vue"]
        assert ch.removed_technologies == ["react"]
        assert ch.added_endpoints == ["http://api.example.com/v2"]
        assert ch.removed_endpoints == ["http://api.example.com/v1"]
        assert ch.added_vulnerabilities == ["cve-x"]
        assert ch.has_changes is True

    def test_r3_diff_evidence_stores(self):
        """Verify diffing two EvidenceStores directly."""
        s1 = EvidenceStore()
        s1.add(Evidence(category="subdomain", value="dev.example.com", source="subfinder"))

        s2 = EvidenceStore()
        s2.add(Evidence(category="subdomain", value="dev.example.com", source="subfinder"))
        s2.add(Evidence(category="subdomain", value="prod.example.com", source="subfinder"))

        diff = AttackSurfaceDiffEngine.diff_evidence(s1, s2, base_target="example.com", current_target="example.com")
        assert diff.new_subdomains == ["prod.example.com"]
        assert diff.removed_subdomains == []

    def test_r3_diff_polymorphic_entrypoint(self):
        """Verify AttackSurfaceDiffEngine.diff handles Missions, Graphs, or EvidenceStores."""
        g1 = KnowledgeGraph()
        g1.add(Node(id="subdomain:a.com", type="subdomain", value="a.com"))
        g2 = KnowledgeGraph()
        g2.add(Node(id="subdomain:b.com", type="subdomain", value="b.com"))

        diff1 = AttackSurfaceDiffEngine.diff(g1, g2)
        assert diff1.new_subdomains == ["b.com"]

        m1 = Mission(target="a.com")
        m2 = Mission(target="b.com")
        diff2 = AttackSurfaceDiffEngine.diff(m1, m2)
        assert isinstance(diff2, AttackSurfaceDiff)

    def test_r3_summary_and_total_changes(self):
        """Verify total_changes and summary dictionary output."""
        m1 = Mission(target="example.com")
        m1.subdomains = ["sub1.example.com"]

        m2 = Mission(target="example.com")
        m2.subdomains = ["sub1.example.com", "sub2.example.com"]
        m2.technologies = ["django"]

        diff = AttackSurfaceDiffEngine.diff_missions(m1, m2)
        assert diff.total_changes() == 2  # 1 new sub + 1 new tech
        summary = diff.summary()
        assert summary["new_subdomains"] == 1
        assert summary["new_technologies"] == 1
        assert summary["total_changes"] == 2

    def test_r3_identical_missions_yield_no_changes(self):
        """Diffing two identical missions produces has_changes == False and total_changes == 0."""
        m1 = Mission(target="example.com")
        m1.subdomains = ["api.example.com"]
        m1.live_hosts = [{"url": "http://api.example.com", "status": 200}]

        m2 = Mission(target="example.com")
        m2.subdomains = ["api.example.com"]
        m2.live_hosts = [{"url": "http://api.example.com", "status": 200}]

        diff = AttackSurfaceDiffEngine.diff_missions(m1, m2)
        assert diff.has_changes is False
        assert diff.total_changes() == 0
        assert diff.changed_hosts == []
