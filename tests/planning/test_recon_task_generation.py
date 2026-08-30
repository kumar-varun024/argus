"""
Unit and integration tests for concrete recon task generation and state-aware gap analysis.
"""
import pytest
from argus.runtime.mission import Mission
from argus.runtime.registry import registry
from argus.runtime.dispatcher import ToolDispatcher
from argus.runtime.executor import TaskScheduler
from argus.runtime.models import TaskState
from argus.planning.models import ResearchTask, TaskCategory, CoverageGap
from argus.planning.gap_analysis import GapAnalyzer
from argus.planning.task_generator import TaskGenerator
from argus.evidence.model import Evidence


class TestExplicitDispatcherRouting:
    """Verify ToolDispatcher resolves tasks using metadata.tool_id."""

    def test_acceptance_criteria_dispatcher_routing(self):
        tests = [
            ("Subfinder", "subfinder", TaskCategory.TECHNOLOGY_DISCOVERY),
            ("HTTPX", "httpx", TaskCategory.TECHNOLOGY_DISCOVERY),
            ("Katana", "katana_crawler", TaskCategory.API_DISCOVERY),
            ("Nuclei", "nuclei", TaskCategory.EVIDENCE_CORRELATION),
            ("GraphQL", "graphql_specialist", TaskCategory.GRAPHQL_ANALYSIS),
        ]

        dispatcher = ToolDispatcher(registry)

        for title, expected_tool_id, category in tests:
            task = ResearchTask(
                title=title,
                description="Explicit dispatcher routing test",
                goal="Verify tool selection",
                category=category,
                metadata={"tool_id": expected_tool_id},
            )

            tool = dispatcher.resolve_tool(task)
            assert tool is not None, f"Tool '{expected_tool_id}' not resolved"
            assert tool.id == expected_tool_id, f"Expected tool ID '{expected_tool_id}', got '{tool.id}'"


class TestReconStateGapAnalyzer:
    """Verify GapAnalyzer distinguishes distinct recon states."""

    def test_state_1_no_subdomains(self):
        mission = Mission(target="example.com")
        mission.subdomains = []
        mission.live_hosts = []
        mission.endpoints = []

        gaps = GapAnalyzer(mission).analyze()
        areas = [g.area for g in gaps]
        assert "Subdomains" in areas

        sub_gap = next(g for g in gaps if g.area == "Subdomains")
        assert sub_gap.category == TaskCategory.TECHNOLOGY_DISCOVERY
        assert sub_gap.severity >= 0.9
        assert "example.com" in sub_gap.related_assets

    def test_state_2_subdomains_present_no_live_hosts(self):
        mission = Mission(target="example.com")
        mission.subdomains = ["api.example.com", "admin.example.com"]
        mission.live_hosts = []
        mission.endpoints = []

        gaps = GapAnalyzer(mission).analyze()
        areas = [g.area for g in gaps]
        assert "Live Hosts" in areas
        assert "Subdomains" not in areas

        lh_gap = next(g for g in gaps if g.area == "Live Hosts")
        assert lh_gap.category == TaskCategory.TECHNOLOGY_DISCOVERY
        assert "api.example.com" in lh_gap.related_assets

    def test_state_3_and_4_live_hosts_present_no_endpoints_no_vuln_scan(self):
        mission = Mission(target="example.com")
        mission.subdomains = ["api.example.com"]
        mission.live_hosts = [{"url": "https://api.example.com"}]
        mission.technologies = ["nginx"]
        mission.endpoints = []

        gaps = GapAnalyzer(mission).analyze()
        areas = [g.area for g in gaps]
        assert "Endpoints" in areas
        assert "Vulnerability Scanning" in areas
        assert "Subdomains" not in areas
        assert "Live Hosts" not in areas

        ep_gap = next(g for g in gaps if g.area == "Endpoints")
        assert ep_gap.category == TaskCategory.API_DISCOVERY

        vuln_gap = next(g for g in gaps if g.area == "Vulnerability Scanning")
        assert vuln_gap.category == TaskCategory.EVIDENCE_CORRELATION

    def test_recon_completed_no_recon_gaps(self):
        mission = Mission(target="example.com")
        mission.subdomains = ["api.example.com"]
        mission.live_hosts = [{"url": "https://api.example.com"}]
        mission.endpoints = [{"url": "/api/users", "method": "GET"}]
        mission.technologies = ["nginx"]
        mission.vulnerabilities = [{"name": "CVE-2023-1234", "severity": "medium"}]

        gaps = GapAnalyzer(mission).analyze()
        areas = [g.area for g in gaps]
        assert "Subdomains" not in areas
        assert "Live Hosts" not in areas
        assert "Endpoints" not in areas
        assert "Vulnerability Scanning" not in areas

    def test_recon_state_detected_from_evidence_store(self):
        mission = Mission(target="example.com")
        mission.evidence.add(Evidence(category="subdomain", value="app.example.com", source="subfinder"))

        gaps = GapAnalyzer(mission).analyze()
        areas = [g.area for g in gaps]
        assert "Live Hosts" in areas
        assert "Subdomains" not in areas

    def test_vuln_scan_detected_from_evidence_store(self):
        mission = Mission(target="example.com")
        mission.subdomains = ["api.example.com"]
        mission.live_hosts = [{"url": "https://api.example.com"}]
        mission.endpoints = [{"url": "/api/v1", "method": "GET"}]
        mission.evidence.add(Evidence(category="vulnerability", value="CVE-2023-0001", source="nuclei"))

        gaps = GapAnalyzer(mission).analyze()
        areas = [g.area for g in gaps]
        assert "Vulnerability Scanning" not in areas

    def test_preseeded_live_hosts_without_subdomains_emits_endpoints_and_vuln_scan(self):
        """When live hosts exist (e.g. IP target or pre-seeded), skip subdomain enum and check endpoints/vuln scan."""
        mission = Mission(target="192.168.1.100")
        mission.subdomains = []
        mission.live_hosts = [{"url": "http://192.168.1.100"}]
        mission.endpoints = []

        gaps = GapAnalyzer(mission).analyze()
        areas = [g.area for g in gaps]
        assert "Subdomains" not in areas
        assert "Live Hosts" not in areas
        assert "Endpoints" in areas
        assert "Vulnerability Scanning" in areas

    def test_vuln_scan_detected_from_execution_history_and_task_states(self):
        """Verify vulnerability scan gap is suppressed when recorded in execution history or completed tasks."""
        mission = Mission(target="example.com")
        mission.subdomains = ["api.example.com"]
        mission.live_hosts = [{"url": "https://api.example.com"}]
        mission.endpoints = [{"url": "/api/v1", "method": "GET"}]
        mission.execution_history = [{"tool_id": "nuclei", "task_title": "Scan Live Hosts"}]

        gaps = GapAnalyzer(mission).analyze()
        areas = [g.area for g in gaps]
        assert "Vulnerability Scanning" not in areas


class TestConcreteReconTaskGeneration:
    """Verify TaskGenerator produces concrete, dependency-aware recon tasks with tool_id metadata."""

    def test_generate_recon_tasks_metadata_and_dependencies(self):
        mission = Mission(target="target.example.com")
        generator = TaskGenerator(mission)
        tasks = generator.generate_recon_tasks()

        assert len(tasks) == 5

        # Task 1: Subfinder
        t_sub = tasks[0]
        assert t_sub.title == "Discover Subdomains"
        assert t_sub.category == TaskCategory.TECHNOLOGY_DISCOVERY
        assert t_sub.metadata.get("tool_id") == "subfinder"
        assert t_sub.dependencies == []
        assert "ReconAgent" not in t_sub.required_specialists
        assert t_sub.required_specialists == []
        assert "subdomains" in t_sub.expected_outputs

        # Task 2: HTTPX
        t_http = tasks[1]
        assert t_http.title == "Fingerprint Live Hosts"
        assert t_http.category == TaskCategory.TECHNOLOGY_DISCOVERY
        assert t_http.metadata.get("tool_id") == "httpx"
        assert t_http.dependencies == ["Discover Subdomains"]
        assert "ReconAgent" not in t_http.required_specialists
        assert t_http.required_specialists == []
        assert "live_hosts" in t_http.expected_outputs

        # Task 3: Katana Crawler
        t_kat = tasks[2]
        assert t_kat.title == "Discover API Endpoints"
        assert t_kat.category == TaskCategory.API_DISCOVERY
        assert t_kat.metadata.get("tool_id") == "katana_crawler"
        assert t_kat.dependencies == ["Fingerprint Live Hosts"]
        assert "ReconAgent" not in t_kat.required_specialists
        assert t_kat.required_specialists == []
        assert "endpoints" in t_kat.expected_outputs

        # Task 4: Nuclei
        t_nuc = tasks[3]
        assert t_nuc.title == "Scan Live Hosts"
        assert t_nuc.category == TaskCategory.EVIDENCE_CORRELATION
        assert t_nuc.metadata.get("tool_id") == "nuclei"
        assert t_nuc.dependencies == ["Fingerprint Live Hosts"]
        assert "ReconAgent" not in t_nuc.required_specialists
        assert t_nuc.required_specialists == []
        assert "vulnerabilities" in t_nuc.expected_outputs

        # Task 5: Information Disclosure
        t_info = tasks[4]
        assert t_info.title == "Probe Information Disclosure"
        assert t_info.category == TaskCategory.EVIDENCE_CORRELATION
        assert t_info.metadata.get("tool_id") == "info_disclosure"
        assert t_info.dependencies == ["Fingerprint Live Hosts"]
        assert "ReconAgent" not in t_info.required_specialists
        assert t_info.required_specialists == []
        assert "vulnerabilities" in t_info.expected_outputs
        assert t_info.priority == 0.82


    def test_no_task_references_recon_agent(self):
        mission = Mission(target="example.com")
        generator = TaskGenerator(mission)
        recon_tasks = generator.generate_recon_tasks()

        for t in recon_tasks:
            assert "ReconAgent" not in t.required_specialists
            assert all(spec in registry.tools for spec in t.required_specialists)

    def test_from_gaps_subdomain_gap(self):
        mission = Mission(target="example.com")
        gap = CoverageGap(area="Subdomains", description="No subdomains", category=TaskCategory.TECHNOLOGY_DISCOVERY)
        tasks = TaskGenerator(mission).from_gaps([gap])

        assert len(tasks) == 1
        assert tasks[0].title == "Discover Subdomains"
        assert tasks[0].metadata.get("tool_id") == "subfinder"
        assert tasks[0].dependencies == []

    def test_from_gaps_live_hosts_gap(self):
        mission = Mission(target="example.com")
        gap = CoverageGap(area="Live Hosts", description="No live hosts", category=TaskCategory.TECHNOLOGY_DISCOVERY)
        tasks = TaskGenerator(mission).from_gaps([gap])

        assert len(tasks) == 1
        assert tasks[0].title == "Fingerprint Live Hosts"
        assert tasks[0].metadata.get("tool_id") == "httpx"
        assert tasks[0].dependencies == ["Discover Subdomains"]

    def test_from_gaps_endpoints_gap(self):
        mission = Mission(target="example.com")
        gap = CoverageGap(area="Endpoints", description="No endpoints crawled", category=TaskCategory.API_DISCOVERY)
        tasks = TaskGenerator(mission).from_gaps([gap])

        assert len(tasks) == 1
        assert tasks[0].title == "Discover API Endpoints"
        assert tasks[0].metadata.get("tool_id") == "katana_crawler"
        assert tasks[0].dependencies == ["Fingerprint Live Hosts"]

    def test_from_gaps_vulnerability_gap(self):
        mission = Mission(target="example.com")
        gap = CoverageGap(area="Vulnerability Scanning", description="No vuln scan", category=TaskCategory.EVIDENCE_CORRELATION)
        tasks = TaskGenerator(mission).from_gaps([gap])

        assert len(tasks) == 1
        assert tasks[0].title == "Scan Live Hosts"
        assert tasks[0].metadata.get("tool_id") == "nuclei"
        assert tasks[0].dependencies == ["Fingerprint Live Hosts"]

    def test_all_specialist_tasks_have_valid_registry_tools(self):
        mission = Mission(target="example.com")
        generator = TaskGenerator(mission)

        # Create gaps for all specialist categories
        gaps = [
            CoverageGap(area="GraphQL Schema", description="GraphQL", category=TaskCategory.GRAPHQL_ANALYSIS),
            CoverageGap(area="Authentication Workflows", description="Auth", category=TaskCategory.AUTHENTICATION_ANALYSIS),
            CoverageGap(area="Authorization", description="Authz", category=TaskCategory.AUTHORIZATION_ANALYSIS),
            CoverageGap(area="Business Logic", description="BL", category=TaskCategory.BUSINESS_LOGIC_ANALYSIS),
            CoverageGap(area="JavaScript Analysis", description="JS", category=TaskCategory.JAVASCRIPT_ANALYSIS),
            CoverageGap(area="API Endpoints", description="API analysis", category=TaskCategory.API_DISCOVERY),
        ]
        # Make sure mission has endpoints so API Endpoints maps to specialist
        mission.endpoints = [{"url": "/api/v1/users"}]

        tasks = generator.from_gaps(gaps)
        dispatcher = ToolDispatcher(registry)

        for task in tasks:
            assert "ReconAgent" not in task.required_specialists
            tool = dispatcher.resolve_tool(task)
            assert tool is not None, f"Could not resolve tool for task: {task.title}"


class TestReconTaskExecutionOrder:
    """Verify TaskScheduler respects the dependency chain of generated recon tasks."""

    def test_recon_tasks_execute_in_correct_order(self):
        mission = Mission(target="example.com")
        generator = TaskGenerator(mission)
        recon_tasks = generator.generate_recon_tasks()

        scheduler = TaskScheduler(mission, max_workers=4)
        scheduler.schedule_tasks(recon_tasks)

        # Batch 1: Only Discover Subdomains (subfinder) is READY
        batch1 = scheduler.get_executable_batch()
        assert len(batch1) == 1
        assert batch1[0].task_title == "Discover Subdomains"

        # Complete Subfinder
        scheduler.report_success(batch1[0].task_id)

        # Batch 2: Fingerprint Live Hosts (httpx) is now READY
        batch2 = scheduler.get_executable_batch()
        assert len(batch2) == 1
        assert batch2[0].task_title == "Fingerprint Live Hosts"

        # Complete HTTPX
        scheduler.report_success(batch2[0].task_id)

        # Batch 3: Discover API Endpoints (katana), Scan Live Hosts (nuclei), and Probe Information Disclosure (info_disclosure) are now READY
        batch3 = scheduler.get_executable_batch()
        assert len(batch3) == 3
        titles = {t.task_title for t in batch3}
        assert titles == {"Discover API Endpoints", "Scan Live Hosts", "Probe Information Disclosure"}

        # Complete all
        for t in batch3:
            scheduler.report_success(t.task_id)

        assert scheduler.queue_manager.is_complete()

    def test_unblocked_execution_for_preseeded_assets(self):
        """When pre-seeded live hosts exist, generated Katana and Nuclei tasks execute immediately."""
        mission = Mission(target="example.com")
        mission.subdomains = ["api.example.com"]
        mission.live_hosts = [{"url": "https://api.example.com"}]
        mission.technologies = ["nginx"]

        gaps = GapAnalyzer(mission).analyze()
        tasks = TaskGenerator(mission).from_gaps(gaps)

        # Filter to recon tasks
        recon_tasks = [t for t in tasks if t.title in ("Discover API Endpoints", "Scan Live Hosts", "Probe Information Disclosure")]
        assert len(recon_tasks) == 3

        scheduler = TaskScheduler(mission, max_workers=4)
        scheduler.schedule_tasks(recon_tasks)

        batch = scheduler.get_executable_batch()
        assert len(batch) == 3
        titles = {t.task_title for t in batch}
        assert titles == {"Discover API Endpoints", "Scan Live Hosts", "Probe Information Disclosure"}

        for t in batch:
            scheduler.report_success(t.task_id)

        assert scheduler.queue_manager.is_complete()


class TestEdgeCasesAndDefensiveBehavior:
    """Verify robust handling of edge cases, null attributes, and defensive boundaries."""

    def test_none_attributes_on_mission_do_not_crash_gap_analyzer_or_task_generator(self):
        mission = Mission(target="example.com")
        mission.subdomains = None
        mission.live_hosts = None
        mission.endpoints = None
        mission.technologies = None
        mission.vulnerabilities = None
        mission.workflows = None
        mission.business_logic = None
        mission.authentication_workflows = None
        mission.authorization_investigations = None
        mission.research_tasks = None
        mission.execution_history = None
        mission.task_states = None

        analyzer = GapAnalyzer(mission)
        gaps = analyzer.analyze()
        assert len(gaps) > 0

        generator = TaskGenerator(mission)
        recon_tasks = generator.generate_recon_tasks()
        assert len(recon_tasks) == 5

        tasks_from_gaps = generator.from_gaps(gaps)
        assert len(tasks_from_gaps) > 0

    def test_non_dict_metadata_in_dispatcher(self):
        dispatcher = ToolDispatcher(registry)
        
        class MockTask:
            title = "Discover Subdomains"
            category = TaskCategory.TECHNOLOGY_DISCOVERY
            metadata = "invalid_string_metadata"  # not a dict
            required_specialists = []

        tool = dispatcher.resolve_tool(MockTask())
        assert tool is not None
        assert tool.id in ("subfinder", "httpx")

    def test_empty_description_in_coverage_gap(self):
        mission = Mission(target="example.com")
        gap = CoverageGap(area="API Endpoints", description="", category=TaskCategory.API_DISCOVERY)
        tasks = TaskGenerator(mission).from_gaps([gap])
        assert len(tasks) == 1
        assert tasks[0].title == "Discover API Endpoints"

    def test_string_and_dict_host_assets(self):
        mission = Mission(target="example.com")
        mission.live_hosts = ["https://host1.example.com", {"url": "https://host2.example.com"}]
        mission.endpoints = []

        gaps = GapAnalyzer(mission).analyze()
        tasks = TaskGenerator(mission).from_gaps(gaps)

        katana_task = next(t for t in tasks if t.title == "Discover API Endpoints")
        assert "https://host1.example.com" in katana_task.required_inputs
        assert "https://host2.example.com" in katana_task.required_inputs

    def test_set_attributes_do_not_crash_gap_analyzer_or_task_generator(self):
        mission = Mission(target="example.com")
        mission.subdomains = {"api.example.com", "admin.example.com"}
        mission.live_hosts = {"https://api.example.com"}
        mission.endpoints = {"/api/v1/users"}
        mission.technologies = {"nginx", "react"}

        analyzer = GapAnalyzer(mission)
        gaps = analyzer.analyze()
        assert isinstance(gaps, list)

        generator = TaskGenerator(mission)
        recon_tasks = generator.generate_recon_tasks()
        assert len(recon_tasks) == 5


        tasks_from_gaps = generator.from_gaps(gaps)
        assert isinstance(tasks_from_gaps, list)

    def test_non_string_and_dict_technologies_do_not_crash_gap_analyzer(self):
        mission = Mission(target="example.com")
        mission.technologies = ["React", 123, None, {"name": "GraphQL", "version": "16.0"}]

        analyzer = GapAnalyzer(mission)
        gaps = analyzer.analyze()
        areas = [g.area for g in gaps]
        assert "GraphQL Schema" in areas
        assert "JavaScript Analysis" in areas

    def test_vuln_scan_detected_from_tool_runs(self):
        mission = Mission(target="example.com")
        mission.subdomains = ["api.example.com"]
        mission.live_hosts = ["https://api.example.com"]
        mission.endpoints = ["/api/v1"]
        mission.tool_runs = {
            "task-123": {
                "tool_id": "nuclei",
                "status": "succeeded"
            }
        }

        gaps = GapAnalyzer(mission).analyze()
        areas = [g.area for g in gaps]
        assert "Vulnerability Scanning" not in areas

    def test_none_or_empty_gap_area_safely_handled(self):
        mission = Mission(target="example.com")
        gap1 = CoverageGap(area="", description="Test gap with empty area", category=TaskCategory.COVERAGE_IMPROVEMENT)
        tasks1 = TaskGenerator(mission).from_gaps([gap1])
        assert len(tasks1) == 1
        assert tasks1[0].title == "Improve Coverage"

        class MockGap:
            area = None
            description = "Mock gap"
            severity = 0.5
            category = TaskCategory.COVERAGE_IMPROVEMENT
            related_assets = []

        tasks2 = TaskGenerator(mission).from_gaps([MockGap()])
        assert len(tasks2) == 1
        assert tasks2[0].title == "Improve Coverage"



