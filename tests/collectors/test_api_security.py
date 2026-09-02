"""
Unit and Integration Test Suite for API Security Testing Module.

Covers:
- Models, Enums, Aliases, and Result structures
- APISecurityPayloadGenerator (6 detection modes, 5 mutation strategies, benign baselines)
- APISecurityProber (HTTP dispatch, burst execution, differential identity probing)
- APISecurityAnalyzer (sensitive fields, error disclosure, rate limit headers, false positive filtering, severity/CWE calibration)
- APISecurityCollector lifecycle and Quadruple State Publishing
- ToolRegistry and alias resolution
- PluginExecutorAdapter fallback instantiation
- TaskGenerator DAG task generation, gap resolution, and input binding
- AttackSurfaceGraphBuilder Section 27 graph expansion
- CVSS and CWE database mappings
- ControlledMission wrapper compatibility
"""
import copy
import urllib.parse
from typing import Any, Dict, List, Optional
import pytest

from argus.collectors.api_security import (
    APISecurityCollector,
    APISecurityTestingCollector,
    RESTSecurityCollector,
    APIVulnerabilityCollector,
    BOLACollector,
    IDORCollector,
    MassAssignmentCollector,
    RateLimitCollector,
    ExcessiveDataExposureCollector,
    MethodTamperingCollector,
    APISecurityPayloadGenerator,
    APISecurityProber,
    APISecurityAnalyzer,
    APIProbe,
    APIProbeResponse,
    APISecurityResult,
    APISecuritySeverity,
    APISeverity,
    APIVulnerabilityType,
    APISecurityTechnique,
    APIMutationStrategy,
    APISecurityMutationStrategy,
)
from argus.evidence.model import Evidence
from argus.graph.graph import KnowledgeGraph
from argus.graph.attack_surface import AttackSurfaceGraphBuilder
from argus.http.client import HttpResponse
from argus.runtime.mission import Mission
from argus.plugins.interfaces import ControlledMission
from argus.runtime.registry import registry
from argus.runtime.plugins import PluginExecutorAdapter
from argus.planning.task_generator import TaskGenerator, CoverageGap, TaskCategory
from argus.reporting.cvss import CVSSCalculator, ReportSeverity


class MockAPIHttpClient:
    """Mock HTTP client simulating REST API endpoints and burst responses."""

    def __init__(self, response_fn=None):
        self.response_fn = response_fn
        self.requests_log: List[Dict[str, Any]] = []

    def request(self, *args, **kwargs) -> HttpResponse:
        mission = kwargs.pop("mission", None)
        method = kwargs.pop("method", "GET")
        url = kwargs.pop("url", "")
        if args:
            if len(args) == 1:
                url = args[0]
            elif len(args) == 2:
                method, url = args[0], args[1]
            elif len(args) >= 3:
                mission, method, url = args[0], args[1], args[2]
        self.requests_log.append({"mission": mission, "method": method, "url": url, "kwargs": kwargs})
        if self.response_fn:
            return self.response_fn(method, url, **kwargs)
        return HttpResponse(
            success=True,
            status_code=200,
            headers={"content-type": "application/json"},
            body='{"status": "success", "result": "ok"}',
            raw_body='{"status": "success", "result": "ok"}',
            url=url,
        )

    def get(self, *args, **kwargs) -> HttpResponse:
        if args and len(args) >= 2:
            return self.request(args[0], "GET", args[1], **kwargs)
        elif args and len(args) == 1:
            return self.request(None, "GET", args[0], **kwargs)
        return self.request(method="GET", **kwargs)

    def post(self, *args, **kwargs) -> HttpResponse:
        if args and len(args) >= 2:
            return self.request(args[0], "POST", args[1], **kwargs)
        elif args and len(args) == 1:
            return self.request(None, "POST", args[0], **kwargs)
        return self.request(method="POST", **kwargs)


# =============================================================================
# 1. Models & Enums Tests
# =============================================================================

def test_api_security_severity_enums_and_aliases():
    assert APISecuritySeverity.CRITICAL.value == "critical"
    assert APISecuritySeverity.HIGH.value == "high"
    assert APISecuritySeverity.MEDIUM.value == "medium"
    assert APISecuritySeverity.LOW.value == "low"
    assert APISecuritySeverity.INFO.value == "info"
    assert APISeverity == APISecuritySeverity
    assert APISecuritySeverity.CRIT == APISecuritySeverity.CRITICAL


def test_api_vulnerability_type_enums_and_aliases():
    assert APIVulnerabilityType.PARAMETER_TAMPERING.value == "parameter_tampering"
    assert APIVulnerabilityType.MASS_ASSIGNMENT.value == "mass_assignment"
    assert APIVulnerabilityType.RATE_LIMITING_BYPASS.value == "rate_limiting_bypass"
    assert APIVulnerabilityType.BOLA_IDOR.value == "bola_idor"
    assert APIVulnerabilityType.EXCESSIVE_DATA_EXPOSURE.value == "excessive_data_exposure"
    assert APIVulnerabilityType.METHOD_TAMPERING.value == "method_tampering"
    assert APIVulnerabilityType.ERROR_INFO_DISCLOSURE.value == "error_info_disclosure"

    assert APISecurityTechnique == APIVulnerabilityType
    assert APIVulnerabilityType.BOLA == APIVulnerabilityType.BOLA_IDOR
    assert APIVulnerabilityType.IDOR == APIVulnerabilityType.BOLA_IDOR
    assert APIVulnerabilityType.RATE_LIMIT == APIVulnerabilityType.RATE_LIMITING_BYPASS
    assert APIVulnerabilityType.DATA_EXPOSURE == APIVulnerabilityType.EXCESSIVE_DATA_EXPOSURE


def test_api_mutation_strategy_enums():
    assert APIMutationStrategy.CONTENT_TYPE_SWITCHING.value == "content_type_switching"
    assert APIMutationStrategy.PARAMETER_POLLUTION.value == "parameter_pollution"
    assert APIMutationStrategy.HEADER_AUTH_BYPASS.value == "header_auth_bypass"
    assert APIMutationStrategy.VERSION_DOWNGRADE.value == "version_downgrade"
    assert APIMutationStrategy.ENCODING_VARIATIONS.value == "encoding_variations"
    assert APIMutationStrategy.STANDARD.value == "standard"
    assert APISecurityMutationStrategy == APIMutationStrategy


def test_api_probe_and_response_dataclasses():
    probe = APIProbe(
        probe_id="p1",
        target_url="https://api.example.com/items",
        method="POST",
        vulnerability_type=APIVulnerabilityType.PARAMETER_TAMPERING,
        tested_parameter="price",
        original_value=100.0,
        tampered_value=0.01,
    )
    assert probe.probe_id == "p1"
    assert probe.method == "POST"
    assert probe.tested_parameter == "price"

    resp = APIProbeResponse(
        probe=probe,
        status_code=200,
        headers={"content-type": "application/json"},
        body='{"item_id": 1, "price": 0.01}',
        json_body={"item_id": 1, "price": 0.01},
    )
    assert resp.status_code == 200
    assert resp.json_body["price"] == 0.01


# =============================================================================
# 2. Payload Generator Tests
# =============================================================================

def test_payload_generator_modes_and_mutations():
    gen = APISecurityPayloadGenerator()
    url = "https://api.example.com/v2/users/42"

    # Test all 6 mode generators
    pt_probes = gen.generate_parameter_tampering_probes(url)
    assert len(pt_probes) >= 4
    assert any(p.tested_parameter == "price" for p in pt_probes)
    assert any(p.tested_parameter == "quantity" for p in pt_probes)

    ma_probes = gen.generate_mass_assignment_probes(url)
    assert len(ma_probes) >= 5
    assert any(p.tested_parameter == "isAdmin" for p in ma_probes)
    assert any(p.tested_parameter == "role" for p in ma_probes)

    rl_probes = gen.generate_rate_limiting_probes(url)
    assert len(rl_probes) >= 2
    assert any(p.burst_count >= 10 for p in rl_probes)

    bola_probes = gen.generate_bola_idor_probes(url)
    assert len(bola_probes) >= 2
    assert any(p.tested_parameter in ("path_id", "id", "user_id") for p in bola_probes)

    ede_probes = gen.generate_excessive_data_exposure_probes(url)
    assert len(ede_probes) >= 2

    mt_probes = gen.generate_method_tampering_probes(url)
    assert len(mt_probes) >= 5
    assert any(p.method == "PUT" for p in mt_probes)
    assert any(p.method == "DELETE" for p in mt_probes)

    # Test benign baselines
    baselines = gen.generate_benign_baseline_probes(url)
    assert len(baselines) >= 2
    assert all(p.is_benign for p in baselines)


def test_payload_generator_mutation_strategies():
    gen = APISecurityPayloadGenerator()
    base_probe = APIProbe(
        probe_id="test_probe",
        target_url="https://api.example.com/v2/checkout",
        method="POST",
        headers={"Content-Type": "application/json"},
        json_data={"price": 0.01, "role": "admin"},
        params={"id": "100"},
        tested_parameter="role",
    )

    # 1. Content-Type Switching
    mut_ct = gen.apply_mutation(base_probe, APIMutationStrategy.CONTENT_TYPE_SWITCHING)
    assert mut_ct.strategy == APIMutationStrategy.CONTENT_TYPE_SWITCHING
    assert mut_ct.headers["Content-Type"] == "application/x-www-form-urlencoded"
    assert "role=admin" in mut_ct.data

    # 2. Parameter Pollution
    mut_pp = gen.apply_mutation(base_probe, APIMutationStrategy.PARAMETER_POLLUTION)
    assert mut_pp.strategy == APIMutationStrategy.PARAMETER_POLLUTION
    assert isinstance(mut_pp.json_data["role"], list)

    # 3. Header-Based Auth Bypass
    mut_hdr = gen.apply_mutation(base_probe, APIMutationStrategy.HEADER_AUTH_BYPASS)
    assert mut_hdr.strategy == APIMutationStrategy.HEADER_AUTH_BYPASS
    assert mut_hdr.headers["X-Forwarded-For"] == "127.0.0.1"
    assert mut_hdr.headers["X-Original-URL"] == "/v2/checkout"

    # 4. Version Downgrade
    mut_ver = gen.apply_mutation(base_probe, APIMutationStrategy.VERSION_DOWNGRADE)
    assert mut_ver.strategy == APIMutationStrategy.VERSION_DOWNGRADE
    assert "/v1/checkout" in mut_ver.target_url
    assert "X-API-Version" in mut_ver.headers

    # 5. Encoding Variations
    mut_enc = gen.apply_mutation(base_probe, APIMutationStrategy.ENCODING_VARIATIONS)
    assert mut_enc.strategy == APIMutationStrategy.ENCODING_VARIATIONS
    assert "\\u" in mut_enc.json_data["role"]


def test_payload_generator_generate_all_probes():
    gen = APISecurityPayloadGenerator()
    all_probes = gen.generate_all_probes("https://api.example.com/v2/orders/101")
    assert len(all_probes) >= 25
    types = {p.vulnerability_type for p in all_probes}
    assert APIVulnerabilityType.PARAMETER_TAMPERING in types
    assert APIVulnerabilityType.MASS_ASSIGNMENT in types
    assert APIVulnerabilityType.RATE_LIMITING_BYPASS in types
    assert APIVulnerabilityType.BOLA_IDOR in types
    assert APIVulnerabilityType.EXCESSIVE_DATA_EXPOSURE in types
    assert APIVulnerabilityType.METHOD_TAMPERING in types


# =============================================================================
# 3. Prober & Analyzer Tests
# =============================================================================

def test_api_security_prober_execution():
    mock_http = MockAPIHttpClient(
        response_fn=lambda method, url, **kwargs: HttpResponse(
            success=True,
            status_code=200,
            headers={"content-type": "application/json"},
            body='{"user_id": 42, "role": "admin", "isAdmin": true}',
            url=url,
        )
    )
    prober = APISecurityProber(client=mock_http)
    probe = APIProbe(
        probe_id="p1",
        target_url="https://api.example.com/users/42",
        method="POST",
        json_data={"role": "admin"},
        tested_parameter="role",
    )
    resp = prober.execute_probe(None, "https://api.example.com/users/42", probe)
    assert resp.status_code == 200
    assert resp.json_body["role"] == "admin"
    assert resp.json_body["isAdmin"] is True


def test_api_security_prober_burst_sequence():
    call_count = [0]
    def burst_fn(method, url, **kwargs):
        call_count[0] += 1
        return HttpResponse(
            success=True,
            status_code=200,
            headers={"x-ratelimit-limit": "100", "x-ratelimit-remaining": "90"},
            body='{"status": "ok"}',
            url=url,
        )

    mock_http = MockAPIHttpClient(response_fn=burst_fn)
    prober = APISecurityProber(client=mock_http)
    probe = APIProbe(
        probe_id="burst_probe",
        target_url="https://api.example.com/api/v1/resource",
        method="GET",
        vulnerability_type=APIVulnerabilityType.RATE_LIMITING_BYPASS,
        burst_count=10,
    )
    resp = prober.execute_probe(None, "https://api.example.com/api/v1/resource", probe)
    assert len(resp.burst_responses) == 10
    assert resp.status_code == 200
    assert "x-ratelimit-limit" in resp.rate_limit_headers


def test_analyzer_parameter_tampering_evaluation():
    analyzer = APISecurityAnalyzer()
    probe = APIProbe(
        probe_id="pt_probe",
        target_url="https://api.example.com/order",
        method="POST",
        vulnerability_type=APIVulnerabilityType.PARAMETER_TAMPERING,
        tested_parameter="price",
        tampered_value=0.01,
    )
    resp = APIProbeResponse(
        probe=probe,
        status_code=200,
        headers={"content-type": "application/json"},
        body='{"order_id": 999, "price": 0.01, "status": "confirmed"}',
        json_body={"order_id": 999, "price": 0.01, "status": "confirmed"},
    )
    result = analyzer.evaluate_probe(probe, resp, "https://api.example.com/order")
    assert result is not None
    assert result.is_valid_finding is True
    assert result.severity == APISecuritySeverity.HIGH.value
    assert result.cwe_id == "CWE-602"
    assert result.cvss_score == 8.5


def test_analyzer_mass_assignment_evaluation():
    analyzer = APISecurityAnalyzer()
    probe = APIProbe(
        probe_id="ma_probe",
        target_url="https://api.example.com/users",
        method="POST",
        vulnerability_type=APIVulnerabilityType.MASS_ASSIGNMENT,
        tested_parameter="isAdmin",
        tampered_value=True,
    )
    resp = APIProbeResponse(
        probe=probe,
        status_code=201,
        headers={"content-type": "application/json"},
        body='{"id": 5, "username": "alice", "isAdmin": true}',
        json_body={"id": 5, "username": "alice", "isAdmin": True},
    )
    result = analyzer.evaluate_probe(probe, resp, "https://api.example.com/users")
    assert result is not None
    assert result.is_valid_finding is True
    assert result.severity == APISecuritySeverity.HIGH.value
    assert result.cwe_id == "CWE-915"
    assert result.cvss_score == 8.1


def test_analyzer_rate_limiting_bypass_evaluation():
    analyzer = APISecurityAnalyzer()
    probe = APIProbe(
        probe_id="rl_probe",
        target_url="https://api.example.com/login",
        method="POST",
        vulnerability_type=APIVulnerabilityType.RATE_LIMITING_BYPASS,
        burst_count=15,
        tested_parameter="rate_limiting",
    )
    resp = APIProbeResponse(
        probe=probe,
        status_code=200,
        headers={},
        body='{"status": "ok"}',
        burst_responses=[{"status_code": 200}] * 15,
    )
    result = analyzer.evaluate_probe(probe, resp, "https://api.example.com/login")
    assert result is not None
    assert result.is_valid_finding is True
    assert result.severity == APISecuritySeverity.MEDIUM.value
    assert result.cwe_id == "CWE-770"
    assert result.cvss_score == 5.3


def test_analyzer_bola_idor_evaluation():
    analyzer = APISecurityAnalyzer()
    probe = APIProbe(
        probe_id="bola_probe",
        target_url="https://api.example.com/accounts/999",
        method="GET",
        vulnerability_type=APIVulnerabilityType.BOLA_IDOR,
        tested_parameter="path_id",
        tampered_value="999",
    )
    resp = APIProbeResponse(
        probe=probe,
        status_code=200,
        headers={"content-type": "application/json"},
        body='{"account_id": 999, "owner": "Victim User", "balance": 50000}',
        json_body={"account_id": 999, "owner": "Victim User", "balance": 50000},
    )
    result = analyzer.evaluate_probe(probe, resp, "https://api.example.com/accounts/999")
    assert result is not None
    assert result.is_valid_finding is True
    assert result.severity == APISecuritySeverity.HIGH.value
    assert result.cwe_id == "CWE-639"
    assert result.cvss_score == 8.5


def test_analyzer_excessive_data_exposure_evaluation():
    analyzer = APISecurityAnalyzer()
    probe = APIProbe(
        probe_id="ede_probe",
        target_url="https://api.example.com/profile",
        method="GET",
        vulnerability_type=APIVulnerabilityType.EXCESSIVE_DATA_EXPOSURE,
        tested_parameter="response_body",
    )
    resp = APIProbeResponse(
        probe=probe,
        status_code=200,
        headers={"content-type": "application/json"},
        body='{"user_id": 1, "username": "alice", "password_hash": "$2a$12$e8wD/3dJkl...", "ssn": "123-45-6789"}',
    )
    result = analyzer.evaluate_probe(probe, resp, "https://api.example.com/profile")
    assert result is not None
    assert result.is_valid_finding is True
    assert result.severity == APISecuritySeverity.MEDIUM.value
    assert result.cwe_id == "CWE-200"
    assert result.cvss_score == 5.3
    assert "password_hash" in result.metadata["sensitive_fields"]


def test_analyzer_method_tampering_evaluation():
    analyzer = APISecurityAnalyzer()
    probe = APIProbe(
        probe_id="mt_probe",
        target_url="https://api.example.com/resource",
        method="DELETE",
        vulnerability_type=APIVulnerabilityType.METHOD_TAMPERING,
        tested_parameter="http_method",
        tampered_value="DELETE",
    )
    resp = APIProbeResponse(
        probe=probe,
        status_code=200,
        headers={"content-type": "application/json"},
        body='{"deleted": true}',
    )
    result = analyzer.evaluate_probe(probe, resp, "https://api.example.com/resource")
    assert result is not None
    assert result.is_valid_finding is True
    assert result.severity == APISecuritySeverity.HIGH.value
    assert result.cwe_id == "CWE-650"
    assert result.cvss_score == 7.5


# =============================================================================
# 4. Collector & Quadruple State Publishing Tests
# =============================================================================

def test_collector_quadruple_state_publishing():
    mission = Mission(target="example.com")
    mission.endpoints = [{"url": "https://example.com/api/v1/orders"}]
    mission.attack_surface_graph = KnowledgeGraph()
    controlled = ControlledMission(mission)

    # Setup mock client that returns vulnerable price tampering response
    mock_http = MockAPIHttpClient(
        response_fn=lambda method, url, **kwargs: HttpResponse(
            success=True,
            status_code=200,
            headers={"content-type": "application/json"},
            body='{"order_id": 1, "price": -50.0, "status": "processed"}',
            raw_body='{"order_id": 1, "price": -50.0, "status": "processed"}',
            url=url,
        )
    )

    collector = APISecurityCollector(http_client=mock_http, max_probes_per_endpoint=5)
    evidence_items = collector.collect(controlled)

    assert len(evidence_items) > 0
    first_ev = evidence_items[0]
    assert first_ev.category == "api_security"
    assert first_ev.status == "CONFIRMED"

    # 1. raw_mission.evidence
    ev_items = mission.evidence.all() if hasattr(mission.evidence, "all") else list(mission.evidence)
    assert len(ev_items) > 0
    # 2. raw_mission.vulnerabilities
    assert len(mission.vulnerabilities) > 0
    assert mission.vulnerabilities[0]["cwe_id"] in ("CWE-602", "CWE-915", "CWE-639", "CWE-770", "CWE-200", "CWE-650")
    # 3. attack_surface_graph
    assert len(mission.attack_surface_graph.nodes) >= 3
    vuln_nodes = [n for n in mission.attack_surface_graph.nodes.values() if n.type == "vulnerability"]
    assert len(vuln_nodes) > 0
    vuln_edges = [e for e in mission.attack_surface_graph.edges if getattr(e, "type", getattr(e, "edge_type", "")) == "HAS_VULNERABILITY"]
    assert len(vuln_edges) > 0


def test_collector_aliases():
    assert APISecurityTestingCollector == APISecurityCollector
    assert RESTSecurityCollector == APISecurityCollector
    assert APIVulnerabilityCollector == APISecurityCollector
    assert BOLACollector == APISecurityCollector
    assert IDORCollector == APISecurityCollector
    assert MassAssignmentCollector == APISecurityCollector
    assert RateLimitCollector == APISecurityCollector
    assert ExcessiveDataExposureCollector == APISecurityCollector
    assert MethodTamperingCollector == APISecurityCollector


# =============================================================================
# 5. Pipeline & Integration Tests
# =============================================================================

def test_registry_tool_and_alias_resolution():
    tool = registry.get("api_security")
    assert tool is not None
    assert tool.id == "api_security"
    assert tool.capability == "api_security_detector"
    assert "api_security_detector" in tool.capabilities

    # Test alias lookups
    for alias in (
        "api_security",
        "api-security",
        "api_security_specialist",
        "api_security_collector",
        "api_security_detector",
        "api_security_testing",
        "rest_api_security",
        "rest_security",
        "grpc_security",
        "bola",
        "idor_detector",
        "excessive_data_exposure",
        "rate_limit_bypass",
        "rate_limiting",
        "rate_limiting_bypass",
        "method_tampering",
    ):
        resolved = registry.get(alias)
        assert resolved is not None
        assert resolved.id == "api_security"


def test_plugin_executor_adapter_fallback():
    adapter = PluginExecutorAdapter()
    for pid in ("api_security", "api_security_collector", "rest_api_security", "bola", "rate_limit_bypass"):
        inst = adapter._instantiate_specialist_fallback(pid)
        assert isinstance(inst, APISecurityCollector)


def test_task_generator_recon_template_and_gap_resolution():
    mission = Mission(target="api.target.com")
    mission.endpoints = [{"url": "https://api.target.com/api/v1/users"}]
    tg = TaskGenerator(mission=mission)

    # Gap resolution via area_lower
    gap = CoverageGap(
        area="api security",
        description="Verify REST API endpoints for BOLA and mass assignment",
        category=TaskCategory.EVIDENCE_CORRELATION,
        severity=0.85,
    )
    template = tg._resolve_template_for_gap(gap)
    assert template["metadata"]["tool_id"] == "api_security"
    assert template["dependencies"] == ["Discover API Endpoints"]

    # Tasks generation from gaps
    tasks = tg.from_gaps([gap])
    assert len(tasks) == 1
    task = tasks[0]
    assert task.title == "Validate REST & gRPC API Security"
    assert "https://api.target.com/api/v1/users" in task.required_inputs


def test_attack_surface_graph_builder_section_27():
    graph = KnowledgeGraph()
    builder = AttackSurfaceGraphBuilder()

    ev = Evidence(
        category="api_security",
        value="api_security:api-bola-user_id:https://api.example.com/users/42:user_id",
        source="api_security",
        title="API Security Vulnerability: BOLA/IDOR on https://api.example.com/users/42",
        severity="high",
        metadata={
            "url": "https://api.example.com/users/42",
            "host": "https://api.example.com",
            "template_id": "api-bola-user_id",
            "technique": "bola_idor",
            "parameter": "user_id",
            "cwe_id": "CWE-639",
            "cvss_score": 8.5,
        },
    )

    built_graph = builder.build_from_evidence(evidence=[ev], target="api.example.com", graph=graph)
    assert "endpoint:https://api.example.com/users/42" in built_graph.nodes
    assert "live_host:https://api.example.com" in built_graph.nodes

    # Check edges
    has_vuln_edges = [
        e for e in built_graph.edges
        if getattr(e, "edge_type", getattr(e, "type", "")) == "HAS_VULNERABILITY"
    ]
    assert len(has_vuln_edges) >= 2


def test_cvss_and_cwe_database_mappings():
    assert CVSSCalculator.get_cwe_for_category("bola").id == "CWE-639"
    assert CVSSCalculator.get_cwe_for_category("idor").id == "CWE-639"
    assert CVSSCalculator.get_cwe_for_category("bola_idor").id == "CWE-639"
    assert CVSSCalculator.get_cwe_for_category("mass_assignment").id == "CWE-915"
    assert CVSSCalculator.get_cwe_for_category("rate_limiting").id == "CWE-770"
    assert CVSSCalculator.get_cwe_for_category("rate_limiting_bypass").id == "CWE-770"
    assert CVSSCalculator.get_cwe_for_category("parameter_tampering").id == "CWE-602"
    assert CVSSCalculator.get_cwe_for_category("excessive_data_exposure").id == "CWE-200"
    assert CVSSCalculator.get_cwe_for_category("method_tampering").id == "CWE-650"

    # Test CVSS score calibration
    vec_high = CVSSCalculator._get_preset_vector("api_security", ReportSeverity.HIGH)
    score_high = CVSSCalculator.calculate_base_score(vec_high)
    assert 7.0 <= score_high <= 8.9

    vec_med = CVSSCalculator._get_preset_vector("rate_limiting", ReportSeverity.MEDIUM)
    score_med = CVSSCalculator.calculate_base_score(vec_med)
    assert 4.0 <= score_med <= 6.9
