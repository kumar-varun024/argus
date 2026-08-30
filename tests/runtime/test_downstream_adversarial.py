"""
Adversarial Verification Suite for Downstream System Integration and Data Integrity.
Tested components:
1. EvidenceStore (5 recon categories: subdomain, live_host, technology, endpoint, vulnerability)
2. Downstream Consumers: GapAnalyzer, ResearchPlanner, TechnologyCollector, KatanaCollector, HttpxCollector, GraphQLDiscovery
3. Mission Data Schemas: subdomains (list[str]), live_hosts (list[dict]), technologies (list[str]), endpoints (list[dict]), vulnerabilities (list[dict])
4. Multi-stage Pipeline Integration & Checkpoint Serialization
"""
import pytest
from unittest.mock import patch, MagicMock

from argus.evidence.store import EvidenceStore
from argus.evidence.model import Evidence, ProvenanceData
from argus.runtime.mission import Mission, MissionState
from argus.runtime.models import ToolExecutionStatus
from argus.planning.gap_analysis import GapAnalyzer
from argus.planning.research_planner import ResearchPlanner
from argus.planning.models import TaskCategory
from argus.collectors.technology import TechnologyCollector
from argus.collectors.katana import KatanaCollector
from argus.collectors.httpx import HttpxCollector
from argus.plugins.graphql.discovery import GraphQLDiscovery
from argus.plugins.graphql.models import GraphQLEndpoint
from argus.runtime.parser import ReconParser


# =====================================================================
# 1. EvidenceStore: All 5 Recon Categories & Storage/Retrieval Stress
# =====================================================================

class TestEvidenceStoreFiveCategories:
    """Rigorous tests for EvidenceStore across all 5 recon categories."""

    def test_store_and_retrieve_all_five_categories(self):
        store = EvidenceStore()
        assert len(store) == 0
        assert store.count() == 0

        # 1. Subdomain Evidence
        sub_ev = Evidence(
            category="subdomain",
            value="api.target.com",
            source="subfinder",
            description="Discovered subdomain api.target.com",
            metadata={"source": "subfinder", "hostname": "api.target.com"}
        )
        store.add(sub_ev)

        # 2. Live Host Evidence
        host_ev = Evidence(
            category="live_host",
            value="https://api.target.com",
            source="httpx",
            description="Discovered live host https://api.target.com",
            metadata={
                "url": "https://api.target.com",
                "scheme": "https",
                "host": "api.target.com",
                "port": 443,
                "status": 200,
                "title": "API Gateway",
                "server": "nginx/1.22",
                "technologies": ["Nginx", "FastAPI"]
            }
        )
        store.add(host_ev)

        # 3. Technology Evidence
        tech_ev1 = Evidence(
            category="technology",
            value="FastAPI",
            source="httpx",
            description="Detected technology FastAPI on https://api.target.com",
            metadata={"name": "FastAPI", "host": "api.target.com", "url": "https://api.target.com", "source": "httpx"}
        )
        tech_ev2 = Evidence(
            category="technology",
            value="Nginx",
            source="httpx",
            description="Detected technology Nginx on https://api.target.com",
            metadata={"name": "Nginx", "host": "api.target.com", "url": "https://api.target.com", "source": "httpx"}
        )
        store.add(tech_ev1)
        store.add(tech_ev2)

        # 4. Endpoint Evidence
        ep_ev = Evidence(
            category="endpoint",
            value="https://api.target.com/v1/auth/login",
            source="katana",
            description="Discovered endpoint https://api.target.com/v1/auth/login",
            metadata={
                "url": "https://api.target.com/v1/auth/login",
                "path": "/v1/auth/login",
                "host": "api.target.com",
                "method": "POST",
                "params": {"redirect": ["/dashboard"]}
            }
        )
        store.add(ep_ev)

        # 5. Vulnerability Evidence
        vuln_ev = Evidence(
            category="vulnerability",
            value="CVE-2023-9999",
            source="nuclei",
            severity="high",
            description="Authentication bypass in API Gateway",
            metadata={
                "template_id": "CVE-2023-9999",
                "name": "Auth Bypass",
                "severity": "high",
                "host": "https://api.target.com",
                "matched_at": "https://api.target.com/v1/auth/login",
                "description": "Authentication bypass in API Gateway",
                "tags": ["cve", "auth-bypass", "rce"],
                "extracted_results": ["token_override=true"]
            }
        )
        store.add(vuln_ev)

        # Asserts on counts & collections
        assert len(store) == 6
        assert store.count() == 6
        all_items = store.all()
        assert len(all_items) == 6

        # Category Filter Tests
        sub_items = store.filter("subdomain")
        assert len(sub_items) == 1
        assert sub_items[0].metadata["hostname"] == "api.target.com"
        assert sub_items[0].source == "subfinder"

        host_items = store.filter("live_host")
        assert len(host_items) == 1
        assert host_items[0].metadata["status"] == 200
        assert host_items[0].metadata["technologies"] == ["Nginx", "FastAPI"]

        tech_items = store.filter("technology")
        assert len(tech_items) == 2
        tech_names = {t.metadata["name"] for t in tech_items}
        assert tech_names == {"FastAPI", "Nginx"}

        ep_items = store.filter("endpoint")
        assert len(ep_items) == 1
        assert ep_items[0].metadata["path"] == "/v1/auth/login"
        assert ep_items[0].metadata["method"] == "POST"

        vuln_items = store.filter("vulnerability")
        assert len(vuln_items) == 1
        assert vuln_items[0].severity == "high"
        assert vuln_items[0].metadata["template_id"] == "CVE-2023-9999"

        # Non-existent category
        assert store.filter("nonexistent") == []

        # Iteration test
        iter_categories = [item.category for item in store]
        assert iter_categories == ["subdomain", "live_host", "technology", "technology", "endpoint", "vulnerability"]

        # Clear test
        store.clear()
        assert len(store) == 0
        assert store.all() == []

    def test_evidence_store_high_volume_stress(self):
        store = EvidenceStore()
        categories = ["subdomain", "live_host", "technology", "endpoint", "vulnerability"]
        
        for i in range(1000):
            cat = categories[i % len(categories)]
            store.add(Evidence(
                category=cat,
                value=f"item_{i}",
                source="stress_test",
                metadata={"index": i, "category": cat}
            ))

        assert len(store) == 1000
        for cat in categories:
            filtered = store.filter(cat)
            assert len(filtered) == 200
            assert all(item.category == cat for item in filtered)


# =====================================================================
# 2. Downstream Consumers: GapAnalyzer Adversarial Tests
# =====================================================================

class TestGapAnalyzerDownstream:
    """Stress tests GapAnalyzer against all combinations of recon states."""

    def test_gap_analyzer_lifecycle_progression(self):
        mission = Mission(target="example.com")
        analyzer = GapAnalyzer(mission)

        # Stage 0: Brand new mission (no subdomains, no hosts, no endpoints, no vulns)
        gaps = analyzer.analyze()
        gap_areas = {g.area for g in gaps}
        assert "Subdomains" in gap_areas
        assert "Live Hosts" not in gap_areas
        assert "Endpoints" not in gap_areas
        assert "Technologies" in gap_areas

        # Stage 1: Subdomains discovered (list of strings)
        mission.subdomains = ["api.example.com", "portal.example.com"]
        gaps = analyzer.analyze()
        gap_areas = {g.area for g in gaps}
        assert "Subdomains" not in gap_areas
        assert "Live Hosts" in gap_areas
        assert "Endpoints" not in gap_areas

        # Stage 2: Live hosts discovered (list of dicts)
        mission.live_hosts = [
            {"url": "https://api.example.com", "host": "api.example.com", "status": 200, "technologies": ["GraphQL", "React"]},
            {"url": "https://portal.example.com", "host": "portal.example.com", "status": 200, "technologies": ["Nginx"]}
        ]
        mission.technologies = ["GraphQL", "React", "Nginx"]
        gaps = analyzer.analyze()
        gap_areas = {g.area for g in gaps}
        assert "Live Hosts" not in gap_areas
        assert "Endpoints" in gap_areas
        assert "Vulnerability Scanning" in gap_areas
        assert "GraphQL Schema" in gap_areas  # from GraphQL technology
        assert "JavaScript Analysis" in gap_areas  # from React technology

        # Stage 3: Endpoints crawled (list of dicts)
        mission.endpoints = [
            {"url": "https://api.example.com/graphql", "path": "/graphql", "host": "api.example.com", "method": "POST"},
            {"url": "https://portal.example.com/login", "path": "/login", "host": "portal.example.com", "method": "GET"}
        ]
        gaps = analyzer.analyze()
        gap_areas = {g.area for g in gaps}
        assert "Endpoints" not in gap_areas
        assert "Vulnerability Scanning" in gap_areas

        # Stage 4: Vulnerabilities scanned (list of dicts)
        mission.vulnerabilities = [
            {"template_id": "cve-2023-1234", "name": "Test Bug", "severity": "medium", "host": "https://api.example.com"}
        ]
        gaps = analyzer.analyze()
        gap_areas = {g.area for g in gaps}
        assert "Vulnerability Scanning" not in gap_areas

    def test_gap_analyzer_hostile_inputs(self):
        """Pass malformed and unconventional data to ensure no crash."""
        mission = Mission(target="edgecase.com")
        analyzer = GapAnalyzer(mission)

        # Hostile technologies: None, nested dicts, ints, empty strings
        mission.technologies = [None, "", {"name": "react"}, {"tech": "graphql"}, 12345, {}]
        # Hostile live_hosts: dicts missing 'url', non-dict items, None
        mission.live_hosts = [{"host": "no-url.com"}, {"url": "http://ok.com"}, None, "string_host"]
        # Hostile endpoints: bare strings, empty dicts, dicts with None
        mission.endpoints = ["/raw/string", {}, {"url": None}, {"url": "https://ok.com/api"}]
        # Hostile vulnerabilities: dict with no fields, None
        mission.vulnerabilities = [{}, None]

        # Should execute safely without raising exceptions
        gaps = analyzer.analyze()
        assert isinstance(gaps, list)


# =====================================================================
# 3. Downstream Consumers: ResearchPlanner Adversarial Tests
# =====================================================================

class TestResearchPlannerDownstream:
    """Tests ResearchPlanner handling of Sprint 1 structured recon data."""

    def test_research_planner_recon_task_chain(self):
        mission = Mission(target="adversarial.example.com")
        planner = ResearchPlanner(mission)

        # Initial plan -> produces subdomain task
        tasks = planner.plan()
        titles = [t.title for t in tasks]
        assert "Discover Subdomains" in titles
        assert mission.research_tasks == tasks

        # Advance state to subdomains
        mission.subdomains = ["app.adversarial.example.com"]
        tasks = planner.plan()
        titles = [t.title for t in tasks]
        assert "Fingerprint Live Hosts" in titles

        # Advance state to live hosts (structured dicts)
        mission.live_hosts = [{"url": "https://app.adversarial.example.com", "host": "app.adversarial.example.com", "status": 200, "technologies": ["Nginx"]}]
        mission.technologies = ["Nginx"]
        tasks = planner.plan()
        titles = [t.title for t in tasks]
        assert "Discover API Endpoints" in titles or "Scan Live Hosts" in titles

    def test_research_planner_knowledge_hints_with_evidence(self):
        mission = Mission(target="knowledge.example.com")
        mission.evidence = EvidenceStore()
        mission.evidence.add(Evidence(category="technology", value="Spring Boot", source="httpx"))
        mission.evidence.add(Evidence(category="vulnerability", value="CWE-89 SQL Injection", source="nuclei"))
        mission.technologies = ["Spring Boot"]

        planner = ResearchPlanner(mission)
        tasks = planner.plan()
        assert isinstance(tasks, list)
        assert len(tasks) > 0


# =====================================================================
# 4. Downstream Consumers: Collectors (Technology, Katana, Httpx)
# =====================================================================

class TestCollectorsDownstream:
    """Tests collectors integrating with structured mission state."""

    def test_technology_collector_with_structured_live_hosts(self):
        collector = TechnologyCollector()
        mission = Mission(target="tech.example.com")
        mission.evidence = EvidenceStore()

        # Structured dicts in live_hosts
        mission.live_hosts = [
            {"url": "https://api.tech.com", "technologies": ["Nginx", "FastAPI", "PostgreSQL"]},
            {"url": "https://app.tech.com", "technologies": ["Nginx", "React", "Node.js"]},
            {"url": "https://empty.tech.com", "technologies": []},
            {"url": "https://notech.tech.com"} # no technologies key
        ]

        collector.collect(mission)

        # Verify technologies in evidence
        tech_evs = mission.evidence.filter("technology")
        tech_values = {e.value for e in tech_evs}
        assert tech_values == {"Nginx", "FastAPI", "PostgreSQL", "React", "Node.js"}
        assert len(tech_evs) == 5  # Deduplicated across hosts

    @patch("argus.runtime.local.LocalRuntime.run_command")
    def test_katana_collector_with_structured_hosts(self, mock_run):
        mock_run.return_value = {
            "stdout": "https://api.katana.com/v1/users\nhttps://api.katana.com/v1/orders",
            "stderr": ""
        }
        collector = KatanaCollector()
        mission = Mission(target="katana.example.com")
        mission.live_hosts = [{"url": "https://api.katana.com"}]

        collector.collect(mission)

        assert len(mission.endpoints) == 2
        for ep in mission.endpoints:
            assert isinstance(ep, dict)
            assert "url" in ep
            assert "path" in ep
            assert "host" in ep
            assert ep["host"] == "https://api.katana.com"

    @patch("argus.runtime.local.LocalRuntime.run_command")
    def test_httpx_collector_with_string_subdomains(self, mock_run):
        mock_run.return_value = {
            "stdout": '{"url":"https://api.httpx.com","status_code":200,"webserver":"nginx","tech":["Nginx"]}',
            "stderr": ""
        }
        collector = HttpxCollector()
        mission = Mission(target="httpx.example.com")
        mission.subdomains = ["api.httpx.com", "auth.httpx.com"]

        collector.collect(mission)

        assert len(mission.live_hosts) == 1
        host = mission.live_hosts[0]
        assert isinstance(host, dict)
        assert host["url"] == "https://api.httpx.com"
        assert host["status"] == 200
        assert host["technologies"] == ["Nginx"]


# =====================================================================
# 5. Downstream Consumers: GraphQLDiscovery
# =====================================================================

class TestGraphQLDiscoveryDownstream:
    """Tests GraphQLDiscovery integration with structured mission endpoints and evidence."""

    def test_graphql_discovery_from_structured_endpoints(self):
        discovery = GraphQLDiscovery()
        mission = Mission(target="gql.example.com")
        mission.evidence = EvidenceStore()

        # Structured dict endpoints
        mission.endpoints = [
            {"url": "https://gql.example.com/graphql", "path": "/graphql", "method": "POST"},
            {"url": "https://gql.example.com/api/v1/users", "path": "/api/v1/users", "method": "GET"},
            {"url": "https://gql.example.com/api/graphql", "path": "/api/graphql", "method": "POST"},
            {"url": "https://gql.example.com/login", "path": "/login", "method": "GET"},
        ]

        discovered = discovery.discover(mission)
        assert len(discovered) == 2
        urls = {d.url for d in discovered}
        assert urls == {"https://gql.example.com/graphql", "https://gql.example.com/api/graphql"}
        for d in discovered:
            assert isinstance(d, GraphQLEndpoint)
            assert d.supports_post is True

    def test_graphql_discovery_from_evidence_store(self):
        discovery = GraphQLDiscovery()
        mission = Mission(target="gql-ev.example.com")
        mission.evidence = EvidenceStore()

        mission.evidence.add(Evidence(
            category="HTTP Response",
            value="application/graphql; charset=utf-8",
            source="https://gql-ev.example.com/query"
        ))
        mission.evidence.add(Evidence(
            category="javascript",
            value="Apollo Client detected with graphql endpoints",
            source="https://gql-ev.example.com/app.js"
        ))

        discovered = discovery.discover(mission)
        assert len(discovered) >= 1
        urls = {d.url for d in discovered}
        assert "https://gql-ev.example.com/query" in urls


# =====================================================================
# 6. Mission Dataclass Schema Integrity
# =====================================================================

class TestMissionDataStructuresSchema:
    """Verifies that all 5 recon collections on Mission conform to expected schemas."""

    def test_mission_recon_fields_contract(self):
        m = Mission(target="schema.example.com")

        # 1. subdomains: list[str]
        m.subdomains = ["sub1.example.com", "sub2.example.com"]
        assert all(isinstance(s, str) for s in m.subdomains)

        # 2. live_hosts: list[dict]
        m.live_hosts = [{"url": "https://sub1.example.com", "status": 200, "technologies": ["Nginx"]}]
        assert all(isinstance(h, dict) for h in m.live_hosts)

        # 3. technologies: list[str]
        m.technologies = ["Nginx", "React", "PostgreSQL"]
        assert all(isinstance(t, str) for t in m.technologies)

        # 4. endpoints: list[dict]
        m.endpoints = [{"url": "https://sub1.example.com/api", "path": "/api", "method": "GET"}]
        assert all(isinstance(ep, dict) for ep in m.endpoints)

        # 5. vulnerabilities: list[dict]
        m.vulnerabilities = [{"template_id": "cve-2024-1", "severity": "high", "name": "Bug"}]
        assert all(isinstance(v, dict) for v in m.vulnerabilities)

        # 6. evidence: EvidenceStore
        assert isinstance(m.evidence, EvidenceStore)


# =====================================================================
# 7. End-to-End Pipeline & Multi-Stage State Transitions
# =====================================================================

class TestFullReconPipelineIntegration:
    """Simulates the entire multi-stage recon lifecycle end-to-end."""

    @patch("argus.runtime.sandbox.Sandbox.execute_command")
    def test_full_recon_pipeline_e2e_state_and_consumers(self, mock_exec):
        from argus.runtime.executor import ExternalToolExecutor
        from argus.runtime.models import Tool, ToolExecutionContext
        from argus.planning.models import ResearchTask

        mission = Mission(target="pipeline.example.com")
        executor = ExternalToolExecutor()

        def make_context(tool_id):
            task = ResearchTask(
                title=f"Task {tool_id}",
                description=f"Run {tool_id}",
                goal="test",
                category=TaskCategory.TECHNOLOGY_DISCOVERY,
                metadata={"tool_id": tool_id}
            )
            return ToolExecutionContext(mission=mission, task=task)

        # Stage 1: Subfinder
        mock_exec.return_value = {
            "stdout": "api.pipeline.example.com\nauth.pipeline.example.com\nportal.pipeline.example.com",
            "stderr": ""
        }
        tool_sub = Tool(id="subfinder", name="Subfinder", command="subfinder", supported_tasks=[TaskCategory.TECHNOLOGY_DISCOVERY])
        res1 = executor.execute(tool_sub, make_context("subfinder"))
        assert res1.status == ToolExecutionStatus.SUCCEEDED

        # Verification Stage 1
        assert mission.subdomains == ["api.pipeline.example.com", "auth.pipeline.example.com", "portal.pipeline.example.com"]
        assert len(mission.evidence.filter("subdomain")) == 3
        
        # Downstream check: GapAnalyzer
        gaps1 = GapAnalyzer(mission).analyze()
        gap_areas1 = {g.area for g in gaps1}
        assert "Subdomains" not in gap_areas1
        assert "Live Hosts" in gap_areas1

        # Stage 2: HTTPX
        mock_exec.return_value = {
            "stdout": (
                '{"url":"https://api.pipeline.example.com","host":"api.pipeline.example.com","status_code":200,"webserver":"nginx","tech":["Nginx","GraphQL","FastAPI"]}\n'
                '{"url":"https://auth.pipeline.example.com","host":"auth.pipeline.example.com","status_code":200,"webserver":"apache","tech":["Apache","Node.js"]}\n'
                '{"url":"https://portal.pipeline.example.com","host":"portal.pipeline.example.com","status_code":403,"webserver":"cloudflare","tech":["Cloudflare","React"]}'
            ),
            "stderr": ""
        }
        tool_httpx = Tool(id="httpx", name="HTTPX", command="httpx", supported_tasks=[TaskCategory.TECHNOLOGY_DISCOVERY])
        res2 = executor.execute(tool_httpx, make_context("httpx"))
        assert res2.status == ToolExecutionStatus.SUCCEEDED

        # Verification Stage 2
        assert len(mission.live_hosts) == 3
        assert all(isinstance(h, dict) for h in mission.live_hosts)
        assert set(mission.technologies) == {"Nginx", "GraphQL", "FastAPI", "Apache", "Node.js", "Cloudflare", "React"}
        assert len(mission.evidence.filter("live_host")) == 3
        assert len(mission.evidence.filter("technology")) == 7

        # Downstream check: GapAnalyzer & TechnologyCollector
        gaps2 = GapAnalyzer(mission).analyze()
        gap_areas2 = {g.area for g in gaps2}
        assert "Live Hosts" not in gap_areas2
        assert "Endpoints" in gap_areas2
        assert "Vulnerability Scanning" in gap_areas2
        assert "GraphQL Schema" in gap_areas2
        assert "JavaScript Analysis" in gap_areas2

        # Stage 3: Katana
        mock_exec.return_value = {
            "stdout": (
                '{"url":"https://api.pipeline.example.com/graphql","path":"/graphql","host":"api.pipeline.example.com","method":"POST"}\n'
                '{"url":"https://api.pipeline.example.com/v1/users","path":"/v1/users","host":"api.pipeline.example.com","method":"GET"}\n'
                '{"url":"https://portal.pipeline.example.com/app.js","path":"/app.js","host":"portal.pipeline.example.com","method":"GET"}'
            ),
            "stderr": ""
        }
        tool_katana = Tool(id="katana_crawler", name="Katana", command="katana", supported_tasks=[TaskCategory.API_DISCOVERY])
        res3 = executor.execute(tool_katana, make_context("katana_crawler"))
        assert res3.status == ToolExecutionStatus.SUCCEEDED

        # Verification Stage 3
        assert len(mission.endpoints) == 3
        assert all(isinstance(ep, dict) for ep in mission.endpoints)
        assert len(mission.evidence.filter("endpoint")) == 3

        # Downstream check: GraphQLDiscovery
        gql_endpoints = GraphQLDiscovery().discover(mission)
        assert len(gql_endpoints) == 1
        assert gql_endpoints[0].url == "https://api.pipeline.example.com/graphql"

        # Stage 4: Nuclei
        mock_exec.return_value = {
            "stdout": (
                '{"template-id":"graphql-introspection","info":{"name":"GraphQL Introspection Enabled","severity":"medium","description":"GraphQL introspection is enabled"},"host":"https://api.pipeline.example.com","matched-at":"https://api.pipeline.example.com/graphql","tags":["graphql","info"]}\n'
                '{"template-id":"cve-2024-1111","info":{"name":"Critical RCE","severity":"critical","description":"Remote code execution via prototype pollution"},"host":"https://portal.pipeline.example.com","matched-at":"https://portal.pipeline.example.com/app.js","tags":["cve","rce","critical"]}'
            ),
            "stderr": ""
        }
        tool_nuclei = Tool(id="nuclei", name="Nuclei", command="nuclei", supported_tasks=[TaskCategory.EVIDENCE_CORRELATION])
        res4 = executor.execute(tool_nuclei, make_context("nuclei"))
        assert res4.status == ToolExecutionStatus.SUCCEEDED

        # Verification Stage 4
        assert len(mission.vulnerabilities) == 2
        assert all(isinstance(v, dict) for v in mission.vulnerabilities)
        vuln_evs = mission.evidence.filter("vulnerability")
        assert len(vuln_evs) == 2
        severities = {v.severity for v in vuln_evs}
        assert severities == {"medium", "critical"}

        # Final Downstream check: GapAnalyzer
        gaps4 = GapAnalyzer(mission).analyze()
        gap_areas4 = {g.area for g in gaps4}
        assert "Vulnerability Scanning" not in gap_areas4
        assert "Subdomains" not in gap_areas4
        assert "Live Hosts" not in gap_areas4
        assert "Endpoints" not in gap_areas4

        # Final Planner Check
        tasks = ResearchPlanner(mission).plan()
        assert isinstance(tasks, list)


# =====================================================================
# 8. Checkpointer & Serialization Integration
# =====================================================================

class TestMissionCheckpointerIntegration:
    """Verifies that Mission state with all 5 recon lists survives checkpointing and state changes."""

    def test_checkpointing_with_full_recon_state(self, tmp_path):
        from argus.runtime.checkpoint import MissionCheckpointer, CheckpointAction
        
        checkpointer = MissionCheckpointer(storage_dir=str(tmp_path))
        mission = Mission(target="checkpoint.example.com")
        mission.subdomains = ["a.checkpoint.com", "b.checkpoint.com"]
        mission.live_hosts = [{"url": "https://a.checkpoint.com", "status": 200, "technologies": ["Nginx"]}]
        mission.technologies = ["Nginx"]
        mission.endpoints = [{"url": "https://a.checkpoint.com/api", "path": "/api", "method": "GET"}]
        mission.vulnerabilities = [{"template_id": "cve-1234", "severity": "low", "name": "Info Leak"}]
        
        ev = Evidence(category="vulnerability", value="Info Leak", severity="low", metadata={"template_id": "cve-1234"})
        mission.evidence.add(ev)

        # Save checkpoint to disk
        checkpointer.checkpoint(mission)

        # Recover from disk
        recovered = checkpointer.recover(mission.id)
        assert recovered.id == mission.id
        assert recovered.subdomains == ["a.checkpoint.com", "b.checkpoint.com"]
        assert len(recovered.live_hosts) == 1
        assert recovered.live_hosts[0]["url"] == "https://a.checkpoint.com"
        assert recovered.technologies == ["Nginx"]
        assert len(recovered.endpoints) == 1
        assert recovered.endpoints[0]["url"] == "https://a.checkpoint.com/api"
        assert len(recovered.vulnerabilities) == 1
        assert recovered.vulnerabilities[0]["template_id"] == "cve-1234"
        assert len(recovered.evidence) == 1
        assert recovered.evidence.filter("vulnerability")[0].metadata["template_id"] == "cve-1234"

        # Checkpoint evaluation with hooks
        checkpointer.register_hook("test_hook", lambda m, c: CheckpointAction.APPROVE)
        action = checkpointer.evaluate_checkpoint("test_hook", mission)
        assert action == CheckpointAction.APPROVE
