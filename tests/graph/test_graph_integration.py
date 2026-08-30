"""
Integration tests for Graph lifecycle and delta detection across mission iterations (R4).
"""
import pytest
from argus.runtime.mission import Mission, MissionState
from argus.evidence.store import EvidenceStore
from argus.evidence.model import Evidence
from argus.graph import (
    AttackSurfaceGraphBuilder,
    AttackSurfaceDiffEngine,
    KnowledgeGraph,
)
from argus.planning.gap_analysis import GapAnalyzer


class TestGraphIntegration:
    """Integration test suite connecting graph builder, queries, and diffing."""

    def test_full_mission_graph_lifecycle(self):
        """
        Verify complete cycle:
        1. Mission initializes with empty KnowledgeGraph
        2. Evidence is collected from recon
        3. AttackSurfaceGraphBuilder constructs relational graph
        4. GapAnalyzer queries graph to generate targeted coverage tasks
        5. Graph is updated with second stage recon
        6. GapAnalyzer reflects complete coverage
        """
        mission = Mission(target="acme.corp")
        assert mission.attack_surface_graph is not None
        assert mission.graph is mission.attack_surface_graph
        assert mission.attack_surface_graph.node_count() == 0

        # Phase 1: Subdomain and Live Host Discovery
        mission.evidence.add(Evidence(category="subdomain", value="api.acme.corp", source="subfinder"))
        mission.evidence.add(Evidence(
            category="live_host",
            value="https://api.acme.corp",
            source="httpx",
            metadata={"url": "https://api.acme.corp", "host": "api.acme.corp", "status": 200, "technologies": ["express"]}
        ))

        builder = AttackSurfaceGraphBuilder()
        builder.build(mission)

        # target(1) + sub(1) + host(1) + tech(1) = 4 nodes
        assert mission.attack_surface_graph.node_count() == 4

        # GapAnalyzer should identify missing endpoints and missing vuln scans
        analyzer = GapAnalyzer(mission)
        gaps = analyzer.analyze()
        areas = {g.area for g in gaps}
        assert "Endpoints" in areas
        assert "Vulnerability Scanning" in areas

        ep_gap = next(g for g in gaps if g.area == "Endpoints")
        assert "https://api.acme.corp" in ep_gap.related_assets

        # Phase 2: Crawling & Vuln Scan evidence added
        mission.evidence.add(Evidence(
            category="endpoint",
            value="https://api.acme.corp/v1/users",
            source="katana",
            metadata={"url": "https://api.acme.corp/v1/users", "host": "api.acme.corp"}
        ))
        mission.evidence.add(Evidence(
            category="vulnerability",
            value="CVE-2024-5555",
            source="nuclei",
            severity="critical",
            metadata={"template_id": "CVE-2024-5555", "host": "https://api.acme.corp"}
        ))

        # Re-build graph idempotently
        builder.build(mission)

        # target(1) + sub(1) + host(1) + tech(1) + ep(1) + vuln(1) = 6 nodes
        assert mission.attack_surface_graph.node_count() == 6
        assert len(mission.attack_surface_graph.get_hosts_without_endpoints()) == 0
        assert len(mission.attack_surface_graph.get_hosts_without_vulnerabilities()) == 0

        # Now recon gaps should be resolved
        mission.technologies = ["express"]
        fresh_gaps = GapAnalyzer(mission).analyze()
        recon_areas = {"Subdomains", "Live Hosts", "Endpoints", "Vulnerability Scanning"}
        assert not (recon_areas & {g.area for g in fresh_gaps})

    def test_multi_cycle_mission_delta_tracking(self):
        """
        Verify diffing two consecutive scan cycles:
        Cycle 1: base attack surface
        Cycle 2: new subdomain, upgraded web server, patched vuln, new endpoint
        """
        # Cycle 1
        m1 = Mission(target="target.org")
        m1.evidence.add(Evidence(category="subdomain", value="web.target.org", source="subfinder"))
        m1.evidence.add(Evidence(
            category="live_host",
            value="http://web.target.org",
            source="httpx",
            metadata={"url": "http://web.target.org", "host": "web.target.org", "server": "apache/2.4.49", "status": 200}
        ))
        m1.evidence.add(Evidence(
            category="vulnerability",
            value="CVE-2021-41773",
            source="nuclei",
            metadata={"template_id": "CVE-2021-41773", "host": "http://web.target.org"}
        ))
        AttackSurfaceGraphBuilder().build(m1)

        # Cycle 2
        m2 = Mission(target="target.org")
        m2.evidence.add(Evidence(category="subdomain", value="web.target.org", source="subfinder"))
        m2.evidence.add(Evidence(category="subdomain", value="portal.target.org", source="subfinder"))
        m2.evidence.add(Evidence(
            category="live_host",
            value="http://web.target.org",
            source="httpx",
            metadata={"url": "http://web.target.org", "host": "web.target.org", "server": "apache/2.4.51", "status": 200}
        ))
        m2.evidence.add(Evidence(
            category="endpoint",
            value="http://web.target.org/dashboard",
            source="katana",
            metadata={"url": "http://web.target.org/dashboard", "host": "web.target.org"}
        ))
        AttackSurfaceGraphBuilder().build(m2)

        # Compute diff
        diff = AttackSurfaceDiffEngine.diff_missions(m1, m2)

        assert diff.new_subdomains == ["portal.target.org"]
        assert diff.removed_subdomains == []
        assert diff.new_endpoints == ["http://web.target.org/dashboard"]
        assert len(diff.removed_vulnerabilities) == 1
        assert diff.removed_vulnerabilities[0]["template_id"] == "CVE-2021-41773"

        # Changed host inspection
        assert len(diff.changed_hosts) == 1
        ch = diff.changed_hosts[0]
        assert ch.host == "http://web.target.org"
        assert ch.server_changed is True
        assert ch.old_server == "apache/2.4.49"
        assert ch.new_server == "apache/2.4.51"
        assert ch.status_changed is False
        assert "http://web.target.org/dashboard" in ch.added_endpoints
        assert "CVE-2021-41773" in ch.removed_vulnerabilities
