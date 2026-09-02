"""
Adversarial & Empirical Stress Test Suite for CORS & Security Headers
Pipeline, Attack Surface Graph, CVSS v3.1, and DAG Wiring.
"""

import time
import pytest
from argus.graph import KnowledgeGraph, Node, Edge, AttackSurfaceGraphBuilder
from argus.evidence.store import EvidenceStore
from argus.evidence.model import Evidence
from argus.runtime.mission import Mission
from argus.runtime.registry import ToolRegistry, registry
from argus.runtime.plugins import PluginExecutorAdapter
from argus.planning.task_generator import TaskGenerator, _RECON_TEMPLATES
from argus.planning.models import ResearchTask, CoverageGap, TaskCategory
from argus.planning.gap_analysis import GapAnalyzer
from argus.reporting.cvss import CVSSCalculator, cvss_roundup
from argus.reporting.models import ReportSeverity, CVSSData, CWEInfo
from argus.collectors.cors_security import (
    CORSSecurityCollector,
    CORSProbe,
    CORSProbeResponse,
    CORSVulnerabilityType,
    CORSMutationStrategy,
)


class TestAttackSurfaceGraphScaleAndDeduplication:
    """Stress-tests AttackSurfaceGraphBuilder and KnowledgeGraph deduplication under high volume."""

    def test_massive_evidence_deduplication(self):
        """Verify that 10,000 duplicate/overlapping CORS and Security Header evidence items
        are ingested in sub-second time with 100% accurate edge deduplication.
        """
        builder = AttackSurfaceGraphBuilder()
        store = EvidenceStore()

        # Generate 10 hosts, 50 endpoints, and 10,000 total evidence items with heavy duplication
        num_hosts = 10
        endpoints_per_host = 5
        probes_per_endpoint = 200 # 10 * 5 * 200 = 10,000 evidence items

        for h in range(num_hosts):
            host = f"host{h}.target.com"
            host_url = f"https://{host}"
            store.add(Evidence(
                category="live_host",
                value=host_url,
                source="httpx",
                metadata={"url": host_url, "host": host, "status": 200}
            ))

            for ep in range(endpoints_per_host):
                ep_url = f"{host_url}/api/v1/resource_{ep}"
                store.add(Evidence(
                    category="endpoint",
                    value=ep_url,
                    source="katana",
                    metadata={"url": ep_url, "host": host}
                ))

                for p in range(probes_per_endpoint):
                    # Rotate between 4 vulnerability types
                    vuln_idx = p % 4
                    if vuln_idx == 0:
                        cat = "cors"
                        tmpl = "cors-origin-reflection"
                        title = "CORS Arbitrary Origin Reflection"
                        sev = "high"
                    elif vuln_idx == 1:
                        cat = "cors_security"
                        tmpl = "cors-null-origin"
                        title = "CORS Null Origin Allowed with Credentials"
                        sev = "high"
                    elif vuln_idx == 2:
                        cat = "security_headers"
                        tmpl = "csp-missing"
                        title = "Missing Content-Security-Policy"
                        sev = "medium"
                    else:
                        cat = "http_security_headers"
                        tmpl = "hsts-missing"
                        title = "Missing Strict-Transport-Security"
                        sev = "low"

                    store.add(Evidence(
                        category=cat,
                        value=ep_url,
                        source="cors_security",
                        severity=sev,
                        title=title,
                        metadata={
                            "url": ep_url,
                            "host": host_url,
                            "template_id": tmpl,
                            "vulnerability_type": tmpl,
                            "severity": sev,
                            "parameter": "Origin",
                        }
                    ))

        t0 = time.perf_counter()
        graph = builder.build_from_evidence(store, target="target.com")
        duration = time.perf_counter() - t0

        # Performance Assertion: 10,000+ items must process in under 1.5 seconds
        assert duration < 1.5, f"Graph build took {duration:.3f}s, expected < 1.5s"

        # Structural Assertions:
        # Nodes:
        # 1 Target
        # 10 Live Hosts
        # 10 Subdomains (created for live hosts)
        # 50 Endpoints
        # 50 endpoints * 4 distinct vulns = 200 Vulnerability nodes
        # Total expected nodes = 1 + 10 + 10 + 50 + 200 = 271 nodes
        assert graph.node_count() == 271

        # Check edge deduplication:
        # Target -> Subdomains: 10
        # Subdomain -> Live Host: 10
        # Live Host -> Endpoint: 50
        # Live Host -> Vulnerability: 200
        # Endpoint -> Vulnerability: 200
        # Total expected edges = 10 + 10 + 50 + 200 + 200 = 470 edges
        assert graph.edge_count() == 470

        # Verify no duplicate edges exist in graph.edges
        edge_tuples = [(e.source, e.target, e.type) for e in graph.edges]
        assert len(edge_tuples) == len(set(edge_tuples)), "Duplicate edges detected in graph.edges!"
        assert len(graph._edge_keys) == len(graph.edges)

        # Verify HAS_VULNERABILITY edges count
        vuln_edges = [e for e in graph.edges if e.type == "HAS_VULNERABILITY"]
        assert len(vuln_edges) == 400 # 200 from live_host, 200 from endpoint

        # Verify HAS_ENDPOINT edges count
        ep_edges = [e for e in graph.edges if e.type == "HAS_ENDPOINT"]
        assert len(ep_edges) == 50

    def test_adversarial_malformed_evidence(self):
        """Stress-test builder against None, empty strings, missing keys, and exotic categories."""
        builder = AttackSurfaceGraphBuilder()
        store = EvidenceStore()

        # 1. Evidence with completely empty metadata and missing URL
        store.add(Evidence(category="cors", value="cors-finding-no-url", source="cors_security"))

        # 2. Evidence with metadata but None values
        store.add(Evidence(
            category="cors_security",
            value="",
            source="cors_security",
            metadata={"url": None, "host": None, "template_id": None, "parameter": None}
        ))

        # 3. Evidence with weird unicode, control characters, and malformed URLs
        store.add(Evidence(
            category="security_headers",
            value="https://test.com/path\x00\x1f?q=ümlaut",
            source="cors_security",
            metadata={"url": "https://test.com/path\x00\x1f?q=ümlaut", "template_id": "bad-url-finding"}
        ))

        # 4. Evidence with all supported CORS/Header category variations
        categories = [
            "cors",
            "cors_security",
            "cors_security",
            "cors_misconfiguration",
            "security_headers",
            "http_security_headers",
            "http_headers",
            "security_header",
        ]
        for idx, cat in enumerate(categories):
            store.add(Evidence(
                category=cat,
                value=f"https://cat-test.com/ep_{idx}",
                source="cors_security",
                metadata={"url": f"https://cat-test.com/ep_{idx}", "template_id": f"tmpl_{cat}"}
            ))

        # Must not raise any exceptions
        graph = builder.build_from_evidence(store, target="target.com")
        assert graph.node_count() > 0
        assert graph.edge_count() > 0

    def test_unlinked_endpoints_and_synthetic_host_creation(self):
        """Verify that when CORS findings arrive for an endpoint whose live host wasn't explicitly
        in the evidence store, a synthetic live_host node is created and connected.
        """
        builder = AttackSurfaceGraphBuilder()
        store = EvidenceStore()

        store.add(Evidence(
            category="cors",
            value="https://orphaned.example.com/api/v1/auth",
            source="cors_security",
            metadata={
                "url": "https://orphaned.example.com/api/v1/auth",
                "template_id": "cors-origin-reflection",
                "vulnerability_type": "origin_reflection",
            }
        ))

        graph = builder.build_from_evidence(store, target="example.com")
        assert graph.get("endpoint:https://orphaned.example.com/api/v1/auth") is not None
        assert graph.get("live_host:https://orphaned.example.com") is not None
        assert graph.get("vulnerability:cors-origin-reflection:https://orphaned.example.com/api/v1/auth") is not None

        # Verify edge connections: live_host -> endpoint, live_host -> vuln, endpoint -> vuln
        lh_node = graph.get("live_host:https://orphaned.example.com")
        ep_node = graph.get("endpoint:https://orphaned.example.com/api/v1/auth")
        vuln_node = graph.get("vulnerability:cors-origin-reflection:https://orphaned.example.com/api/v1/auth")

        lh_edges = {e.target: e.type for e in graph.edges_from(lh_node)}
        assert lh_edges.get(ep_node.id) == "HAS_ENDPOINT"
        assert lh_edges.get(vuln_node.id) == "HAS_VULNERABILITY"

        ep_edges = {e.target: e.type for e in graph.edges_from(ep_node)}
        assert ep_edges.get(vuln_node.id) == "HAS_VULNERABILITY"


class TestCVSSCalculationsAndCWEMappings:
    """Rigorous verification of CVSS v3.1 scoring formulas and CWE mappings."""

    def test_cwe_mappings_for_all_required_cwe_classes(self):
        """Verify CWE mappings for CWE-942, CWE-693, CWE-1021, CWE-525, and CWE-319."""
        # CWE-942 (CORS)
        for cat in [
            "cors", "cors_security", "cors_security", "cors_misconfiguration",
            "origin_reflection", "null_origin_allowed", "wildcard_with_credentials",
            "subdomain_trust_abuse", "preflight_bypass", "origin_parser_differential",
            "cwe_942", "cwe-942",
        ]:
            info = CVSSCalculator.get_cwe_for_category(cat)
            assert info is not None, f"Failed for {cat}"
            assert info.id == "CWE-942", f"Expected CWE-942 for {cat}, got {info.id}"
            assert "Cross-domain" in info.name or "Cross-origin" in info.name

        # CWE-693 (Security Headers & Protections)
        for cat in [
            "security_headers", "http_security_headers", "security_header", "http_headers",
            "csp", "csp_missing", "csp_weak_directive", "x_content_type_options",
            "x_content_type_options_missing", "nosniff", "referrer_policy",
            "referrer_policy_weak", "permissions_policy", "permissions_policy_weak",
            "x_xss_protection", "x_xss_protection_disabled", "cwe_693", "cwe-693",
        ]:
            info = CVSSCalculator.get_cwe_for_category(cat)
            assert info is not None, f"Failed for {cat}"
            assert info.id == "CWE-693", f"Expected CWE-693 for {cat}, got {info.id}"
            assert "Protection Mechanism Failure" in info.name

        # CWE-1021 (Clickjacking & X-Frame-Options)
        for cat in [
            "x_frame_options", "x_frame_options_missing", "x_frame_options_misconfigured",
            "clickjacking", "xfo", "cwe_1021", "cwe-1021",
        ]:
            info = CVSSCalculator.get_cwe_for_category(cat)
            assert info is not None, f"Failed for {cat}"
            assert info.id == "CWE-1021", f"Expected CWE-1021 for {cat}, got {info.id}"
            assert "Improper Restriction of Rendered UI Layers or Frames" in info.name

        # CWE-525 (Cache-Control on Sensitive Data)
        for cat in [
            "cache_control_sensitive_leak", "cache_control_sensitive", "cwe_525", "cwe-525",
        ]:
            info = CVSSCalculator.get_cwe_for_category(cat)
            assert info is not None, f"Failed for {cat}"
            assert info.id == "CWE-525", f"Expected CWE-525 for {cat}, got {info.id}"
            assert "Use of Web Browser Cache Containing Sensitive Information" in info.name

        # CWE-319 (Cleartext Transmission / HSTS)
        for cat in ["hsts", "hsts_missing", "hsts_weak_directive"]:
            info = CVSSCalculator.get_cwe_for_category(cat)
            assert info is not None, f"Failed for {cat}"
            assert info.id == "CWE-319", f"Expected CWE-319 for {cat}, got {info.id}"

    def test_cvss_roundup_edge_cases(self):
        """Test the official FIRST CVSS v3.1 roundup function."""
        assert cvss_roundup(0.0) == 0.0
        assert cvss_roundup(4.0) == 4.0
        assert cvss_roundup(4.0001) == 4.1
        assert cvss_roundup(4.02) == 4.1
        assert cvss_roundup(4.09) == 4.1
        assert cvss_roundup(4.10) == 4.1
        assert cvss_roundup(4.1001) == 4.2
        assert cvss_roundup(9.8) == 9.8
        assert cvss_roundup(10.0) == 10.0

    def test_cvss_vector_calculations_against_first_standards(self):
        """Verify CVSS v3.1 vector calculations for exact scores."""
        # 1. High CORS Vector (Origin reflection with credentials)
        # AV:N / AC:L / PR:N / UI:R / S:U / C:H / I:H / A:N -> 8.1 High
        cors_vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N"
        score = CVSSCalculator.calculate_base_score(cors_vec)
        assert score == 8.1
        assert CVSSCalculator.score_to_severity(score) == ReportSeverity.HIGH

        # 2. Medium Security Header Vector (Missing CSP / XFO)
        # AV:N / AC:L / PR:N / UI:N / S:U / C:L / I:N / A:N -> 5.3 Medium
        sh_vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
        score_sh = CVSSCalculator.calculate_base_score(sh_vec)
        assert score_sh == 5.3
        assert CVSSCalculator.score_to_severity(score_sh) == ReportSeverity.MEDIUM

        # 3. Low Security Header Vector (Missing Permissions-Policy / Server banner)
        # AV:N / AC:L / PR:H / UI:N / S:U / C:L / I:N / A:N -> 2.7 Low
        low_vec = "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:N"
        score_low = CVSSCalculator.calculate_base_score(low_vec)
        assert score_low == 2.7
        assert CVSSCalculator.score_to_severity(score_low) == ReportSeverity.LOW

        # 4. Critical Scope Unchanged Vector (RCE / Critical Smuggling)
        # AV:N / AC:L / PR:N / UI:N / S:U / C:H / I:H / A:H -> 9.8 Critical
        crit_vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        score_crit = CVSSCalculator.calculate_base_score(crit_vec)
        assert score_crit == 9.8
        assert CVSSCalculator.score_to_severity(score_crit) == ReportSeverity.CRITICAL

        # 5. Critical Scope Changed Vector (SSRF with Cloud Metadata Takeover)
        # AV:N / AC:L / PR:N / UI:N / S:C / C:H / I:H / A:N -> 10.0 Critical
        crit_c_vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N"
        score_crit_c = CVSSCalculator.calculate_base_score(crit_c_vec)
        assert score_crit_c == 10.0
        assert CVSSCalculator.score_to_severity(score_crit_c) == ReportSeverity.CRITICAL

        # 6. Zero Vector
        zero_vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
        score_zero = CVSSCalculator.calculate_base_score(zero_vec)
        assert score_zero == 0.0
        assert CVSSCalculator.score_to_severity(score_zero) == ReportSeverity.INFO

    def test_approximate_cvss_derivation_for_cors_and_headers(self):
        """Verify get_approximate_cvss heuristics produce valid vectors and matching scores."""
        # High CORS finding
        cvss_cors = CVSSCalculator.get_approximate_cvss("cors", severity="high")
        assert cvss_cors.score == 8.1
        assert cvss_cors.severity_rating == "High"
        assert "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N" in cvss_cors.vector

        # Medium Security Headers
        cvss_sh = CVSSCalculator.get_approximate_cvss("security_headers", severity="medium")
        assert cvss_sh.score == 5.3
        assert cvss_sh.severity_rating == "Medium"
        assert "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" in cvss_sh.vector

        # Low Security Headers
        cvss_low = CVSSCalculator.get_approximate_cvss("security_headers", severity="low")
        assert cvss_low.score == 2.7
        assert cvss_low.severity_rating == "Low"
        assert "AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:N" in cvss_low.vector


class TestToolRegistryAndPluginAdapter:
    """Stress-test ToolRegistry and PluginExecutorAdapter wiring for cors_headers."""

    def test_tool_registry_aliases_and_capability_resolution(self):
        """Verify all aliases and capabilities map to cors_headers."""
        aliases = [
            "cors",
            "cors_security",
            "cors_security",
            "cors_collector",
            "cors_headers_collector",
            "cors_misconfiguration",
            "cors_misconfiguration_collector",
            "security_headers",
            "http_headers",
            "header_audit",
            "header_auditor",
            "security_header_collector",
            "http_security_headers",
            "csp",
            "hsts",
            "clickjacking",
            "x_frame_options",
            "cors_detector",
        ]

        for alias in aliases:
            tool = registry.get(alias)
            assert tool is not None, f"Alias {alias} returned None"
            assert tool.id == "cors_security", f"Alias {alias} resolved to {tool.id}"

        # Find compatible tools by supported tasks
        for task_name in ["CORS Security Testing", "HTTP Header Audit", "Security Header Validation", "Vulnerability Scanning"]:
            tools = registry.find_compatible_tools(task_name)
            assert any(t.id == "cors_security" for t in tools), f"Failed to find cors_headers for task {task_name}"

    def test_plugin_executor_adapter_instantiation(self):
        """Verify specialist fallback adapter instantiates CORSSecurityCollector."""
        adapter = PluginExecutorAdapter()
        for pid in [
            "cors", "cors_security", "security_headers", "cors_security",
            "cors_misconfiguration", "security_header", "http_header",
            "header_audit", "csp", "hsts", "xfo"
        ]:
            collector = adapter._instantiate_specialist_fallback(pid)
            assert collector is not None, f"Failed to instantiate fallback for {pid}"
            assert isinstance(collector, CORSSecurityCollector)


class TestTaskGeneratorDAGWiringAndAcyclicity:
    """Empirical verification of DAG generation, dependencies, and acyclicity."""

    def test_task_generator_gap_to_cors_headers_wiring(self):
        """Verify TaskGenerator correctly links cors_headers from gap to Discover API Endpoints."""
        mission = Mission(target="example.com")
        mission.endpoints = ["https://example.com/api/users", "https://example.com/api/checkout"]
        mission.live_hosts = ["https://example.com"]

        generator = TaskGenerator(mission)
        gap = CoverageGap(
            area="cors",
            description="Audit CORS policies on discovered endpoints",
            category=TaskCategory.EVIDENCE_CORRELATION,
            severity=0.85,
            related_assets=["https://example.com/api/users"],
        )

        tasks = generator.from_gaps([gap])
        assert len(tasks) == 1
        cors_task = tasks[0]
        assert cors_task.title == "Validate CORS Configuration & HTTP Security Headers"
        assert "Discover API Endpoints" in cors_task.dependencies
        assert "https://example.com/api/users" in cors_task.required_inputs
        assert "vulnerabilities" in cors_task.expected_outputs

    def test_dag_acyclicity_full_suite(self):
        """Verify entire DAG graph is strictly acyclic (DAG)."""
        mission = Mission(target="example.com")
        mission.endpoints = ["https://example.com/api/users"]
        mission.live_hosts = ["https://example.com"]

        generator = TaskGenerator(mission)
        recon_tasks = generator.generate_recon_tasks()

        # Simulate gaps across all areas
        all_gaps = [
            CoverageGap(area="subdomains", description="subdomains gap", category=TaskCategory.TECHNOLOGY_DISCOVERY, severity=0.8),
            CoverageGap(area="live hosts", description="live hosts gap", category=TaskCategory.TECHNOLOGY_DISCOVERY, severity=0.8),
            CoverageGap(area="endpoints", description="endpoints gap", category=TaskCategory.API_DISCOVERY, severity=0.8),
            CoverageGap(area="vulnerabilities", description="vulnerabilities gap", category=TaskCategory.EVIDENCE_CORRELATION, severity=0.8),
            CoverageGap(area="information disclosure", description="info disclosure gap", category=TaskCategory.EVIDENCE_CORRELATION, severity=0.8),
            CoverageGap(area="cors", description="CORS gap", category=TaskCategory.EVIDENCE_CORRELATION, severity=0.8),
            CoverageGap(area="security headers", description="Headers gap", category=TaskCategory.EVIDENCE_CORRELATION, severity=0.8),
            CoverageGap(area="cache security", description="Cache gap", category=TaskCategory.EVIDENCE_CORRELATION, severity=0.8),
            CoverageGap(area="ssti", description="SSTI gap", category=TaskCategory.EVIDENCE_CORRELATION, severity=0.8),
            CoverageGap(area="sql injection", description="SQLi gap", category=TaskCategory.EVIDENCE_CORRELATION, severity=0.8),
            CoverageGap(area="xss", description="XSS gap", category=TaskCategory.EVIDENCE_CORRELATION, severity=0.8),
            CoverageGap(area="request smuggling", description="Smuggling gap", category=TaskCategory.EVIDENCE_CORRELATION, severity=0.8),
            CoverageGap(area="race conditions", description="Race condition gap", category=TaskCategory.EVIDENCE_CORRELATION, severity=0.8),
            CoverageGap(area="business logic", description="Business logic gap", category=TaskCategory.BUSINESS_LOGIC_ANALYSIS, severity=0.8),
        ]

        gap_tasks = generator.from_gaps(all_gaps)
        all_tasks = recon_tasks + gap_tasks

        # Build adjacency list: title -> dependencies
        graph = {}
        for t in all_tasks:
            graph[t.title] = t.dependencies

        # Cycle detection via DFS
        visited = {} # 0: unvisited, 1: visiting, 2: visited

        def dfs(node: str) -> bool:
            visited[node] = 1 # visiting
            for dep in graph.get(node, []):
                if dep not in visited:
                    continue # dependency might be external or not in task set
                if visited[dep] == 1:
                    return False # cycle detected!
                if visited[dep] == 0:
                    if not dfs(dep):
                        return False
            visited[node] = 2 # visited
            return True

        for t_title in graph:
            visited[t_title] = 0

        for t_title in graph:
            if visited[t_title] == 0:
                assert dfs(t_title), f"Cycle detected in task DAG involving task: {t_title}"

    def test_gap_analyzer_triggering_cors_headers(self):
        """Verify that security gaps regarding CORS / headers resolve to cors_headers template."""
        mission = Mission(target="example.com")
        generator = TaskGenerator(mission)

        gap_descriptions = [
            "Missing CORS validation on sensitive endpoints",
            "Cross-origin resource sharing policy too permissive",
            "Arbitrary origin reflection detected in headers",
            "Null origin allowed on authenticated endpoint",
            "Missing security header: Content-Security-Policy",
            "HSTS is not configured with includeSubDomains",
            "Clickjacking vulnerability due to missing X-Frame-Options",
            "X-Content-Type-Options nosniff missing",
            "Referrer-policy is overly permissive",
            "Permissions-policy camera and microphone unconstrained",
        ]

        for desc in gap_descriptions:
            gap = CoverageGap(
                area="cors",
                description=desc,
                category=TaskCategory.EVIDENCE_CORRELATION,
                severity=0.8,
                related_assets=["https://example.com/api"],
            )
            tmpl = generator._resolve_template_for_gap(gap)
            assert tmpl is not None, f"Failed to resolve template for gap: {desc}"
            assert tmpl.get("metadata", {}).get("tool_id") == "cors_security", f"Expected cors_headers tool_id for gap '{desc}', got {tmpl.get('metadata', {}).get('tool_id')}"


class TestAttackSurfaceGraphQueriesAndNavigation:
    """Empirical verification of graph queries and topology navigation with CORS findings."""

    def test_graph_navigation_and_asset_counts(self):
        """Verify graph query methods correctly navigate CORS and Security Header relationships."""
        builder = AttackSurfaceGraphBuilder()
        store = EvidenceStore()

        # Host 1 with endpoints and CORS vulnerability
        store.add(Evidence(category="subdomain", value="app.example.com", source="subfinder"))
        store.add(Evidence(
            category="live_host",
            value="https://app.example.com",
            source="httpx",
            metadata={"url": "https://app.example.com", "host": "app.example.com"}
        ))
        store.add(Evidence(
            category="endpoint",
            value="https://app.example.com/api/user",
            source="katana",
            metadata={"url": "https://app.example.com/api/user", "host": "app.example.com"}
        ))
        store.add(Evidence(
            category="cors",
            value="https://app.example.com/api/user",
            source="cors_security",
            severity="high",
            metadata={
                "url": "https://app.example.com/api/user",
                "host": "https://app.example.com",
                "template_id": "cors-origin-reflection",
                "vulnerability_type": "origin_reflection",
                "parameter": "Origin",
            }
        ))

        # Host 2 with endpoint but NO vulnerability
        store.add(Evidence(category="subdomain", value="clean.example.com", source="subfinder"))
        store.add(Evidence(
            category="live_host",
            value="https://clean.example.com",
            source="httpx",
            metadata={"url": "https://clean.example.com", "host": "clean.example.com"}
        ))
        store.add(Evidence(
            category="endpoint",
            value="https://clean.example.com/health",
            source="katana",
            metadata={"url": "https://clean.example.com/health", "host": "clean.example.com"}
        ))

        graph = builder.build_from_evidence(store, target="example.com")

        # 1. Asset Counts
        counts = graph.get_asset_counts()
        assert counts["target"] == 1
        assert counts["subdomain"] == 2
        assert counts["live_host"] == 2
        assert counts["endpoint"] == 2
        assert counts["vulnerability"] == 1

        # 2. get_hosts_without_vulnerabilities
        clean_hosts = graph.get_hosts_without_vulnerabilities()
        clean_ids = [h.id for h in clean_hosts]
        assert "live_host:https://clean.example.com" in clean_ids
        assert "live_host:https://app.example.com" not in clean_ids

        # 3. get_hosts_without_endpoints
        assert len(graph.get_hosts_without_endpoints()) == 0

        # 4. get_host_for_node navigation
        vuln_node = graph.get("vulnerability:cors-origin-reflection:https://app.example.com/api/user:Origin")
        assert vuln_node is not None
        resolved_host = graph.get_host_for_node(vuln_node)
        assert resolved_host is not None
        assert resolved_host.id == "live_host:https://app.example.com"

        # 5. neighbors query
        ep_node = graph.get("endpoint:https://app.example.com/api/user")
        ep_neighbors = graph.neighbors(ep_node)
        neighbor_ids = {n.id for n in ep_neighbors}
        assert "live_host:https://app.example.com" in neighbor_ids
        assert vuln_node.id in neighbor_ids


class TestScanEngineCORSExecution:
    """Empirical verification of ScanEngine end-to-end execution with CORS module."""

    def test_scan_engine_simulated_cors_collector_execution(self, tmp_path):
        from argus.scanning.dag import ScanDAG, ScanTask
        from argus.scanning.engine import ScanEngine
        from argus.runtime.mission import Mission, MissionState

        # Build custom DAG with subfinder -> httpx -> katana -> cors_headers
        tasks = [
            ScanTask(key="subfinder", title="Discover Subdomains", tool_id="subfinder", dependencies=[]),
            ScanTask(key="httpx", title="Fingerprint Live Hosts", tool_id="httpx", dependencies=["Discover Subdomains"]),
            ScanTask(key="katana_crawler", title="Discover API Endpoints", tool_id="katana_crawler", dependencies=["Fingerprint Live Hosts"]),
            ScanTask(key="cors_security", title="Validate CORS Configuration & HTTP Security Headers", tool_id="cors_security", dependencies=["Discover API Endpoints"]),
        ]
        dag = ScanDAG(tasks=tasks)

        class MockProberCollector:
            def collect(self, mission: Mission):
                # Simulate discovery of 1 CORS finding and 1 Header finding
                ev1 = Evidence(
                    category="cors",
                    value="https://target.com/api/profile",
                    source="cors_security",
                    severity="high",
                    title="CORS Arbitrary Origin Reflection",
                    metadata={
                        "url": "https://target.com/api/profile",
                        "host": "https://target.com",
                        "template_id": "cors-origin-reflection",
                        "vulnerability_type": "origin_reflection",
                        "severity": "high",
                    }
                )
                ev2 = Evidence(
                    category="security_headers",
                    value="https://target.com/api/profile",
                    source="cors_security",
                    severity="medium",
                    title="Missing Content-Security-Policy",
                    metadata={
                        "url": "https://target.com/api/profile",
                        "host": "https://target.com",
                        "template_id": "csp-missing",
                        "vulnerability_type": "csp_missing",
                        "severity": "medium",
                    }
                )
                mission.evidence.add(ev1)
                mission.evidence.add(ev2)
                return [ev1, ev2]

        def factory(task):
            if task.key == "subfinder":
                class SubCollector:
                    def collect(self, m):
                        m.subdomains.append("target.com")
                        ev = Evidence(category="subdomain", value="target.com", source="subfinder")
                        m.evidence.add(ev)
                        return [ev]
                return SubCollector()
            elif task.key == "httpx":
                class HttpCollector:
                    def collect(self, m):
                        m.live_hosts.append({"url": "https://target.com", "host": "target.com"})
                        ev = Evidence(category="live_host", value="https://target.com", source="httpx", metadata={"url": "https://target.com", "host": "target.com"})
                        m.evidence.add(ev)
                        return [ev]
                return HttpCollector()
            elif task.key == "katana_crawler":
                class KatCollector:
                    def collect(self, m):
                        m.endpoints.append({"url": "https://target.com/api/profile", "host": "target.com"})
                        ev = Evidence(category="endpoint", value="https://target.com/api/profile", source="katana", metadata={"url": "https://target.com/api/profile", "host": "target.com"})
                        m.evidence.add(ev)
                        return [ev]
                return KatCollector()
            elif task.key == "cors_security":
                return MockProberCollector()
            return None

        engine = ScanEngine(dag=dag, output_dir=str(tmp_path), collector_factory=factory)
        mission = Mission(target="target.com")

        res = engine.run(mission)

        assert res.status == "COMPLETED"
        assert res.collectors_run == 4
        assert res.collectors_failed == 0
        assert res.total_evidence == 5 # 1 sub, 1 host, 1 ep, 2 cors/header vulns

        # Verify attack surface graph in mission was built and populated
        graph = mission.attack_surface_graph
        assert graph is not None
        assert graph.node_count() > 0

        # Verify HAS_VULNERABILITY edges exist
        vuln_edges = [e for e in graph.edges if e.type == "HAS_VULNERABILITY"]
        assert len(vuln_edges) >= 2

        # Verify HAS_ENDPOINT edges exist
        ep_edges = [e for e in graph.edges if e.type == "HAS_ENDPOINT"]
        assert len(ep_edges) >= 1
