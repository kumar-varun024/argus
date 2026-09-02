import pytest
import urllib.parse
from unittest.mock import Mock, patch
from dataclasses import dataclass
from typing import Dict, Optional

from argus.collectors.cors_security import (
    CORSSecurityCollector,
    CORSPayloadGenerator,
    CORSSecurityAnalyzer,
    CORSProbe,
    CORSProbeResponse,
    CORSVulnerabilityType,
    CORSMutationStrategy,
    HeaderVulnerabilityType
)

class MockMission:
    def __init__(self, endpoints=None):
        self.inputs = {"endpoints": endpoints or []}
        self.evidence = []
        self.vulnerabilities = []
        self.attack_surface_graph = Mock()
        self.attack_surface_graph.nodes = {}
        self.attack_surface_graph.add = Mock()
        self.attack_surface_graph.connect = Mock()

    def publish_finding(self, evidence_id, ev):
        pass

@pytest.fixture
def generator():
    return CORSPayloadGenerator()

@pytest.fixture
def analyzer():
    return CORSSecurityAnalyzer()

@pytest.fixture
def collector():
    return CORSSecurityCollector()

# Generator Tests (7)
def test_payload_generator_origin_reflection_probes(generator):
    probes = generator.generate_origin_reflection_probes("https://example.com/api")
    assert len(probes) >= 5
    assert all(p.vulnerability_type == CORSVulnerabilityType.ORIGIN_REFLECTION for p in probes)

def test_payload_generator_null_origin_probes(generator):
    probes = generator.generate_null_origin_probes("https://example.com/api")
    assert len(probes) == 1
    assert probes[0].origin_value == "null"
    assert probes[0].headers["Origin"] == "null"

def test_payload_generator_wildcard_credential_probes(generator):
    probes = generator.generate_wildcard_credential_probes("https://example.com/api")
    assert len(probes) == 1
    assert probes[0].origin_value == "*"
    assert probes[0].headers["Origin"] == "*"

def test_payload_generator_subdomain_trust_probes(generator):
    probes = generator.generate_subdomain_trust_probes("https://example.com/api")
    assert len(probes) == 1
    assert probes[0].vulnerability_type == CORSVulnerabilityType.SUBDOMAIN_TRUST_ABUSE
    assert "attacker.example.com" in probes[0].origin_value

def test_payload_generator_preflight_probes(generator):
    probes = generator.generate_preflight_probes("https://example.com/api")
    assert len(probes) >= 1
    assert probes[0].method == "OPTIONS"

def test_payload_generator_parser_differential_probes(generator):
    probes = generator.generate_parser_differential_probes("https://example.com/api")
    assert len(probes) >= 3
    origins = [p.origin_value for p in probes]
    assert "https://example.com.evil.com" in origins
    assert "https://evil.com.example.com" in origins

def test_payload_generator_mutation_strategies(generator):
    probe = CORSProbe(
        target_url="https://example.com/api",
        vulnerability_type=CORSVulnerabilityType.ORIGIN_REFLECTION,
        strategy=CORSMutationStrategy.ORIGIN_CASING,
        origin_value="https://evil.com"
    )
    mutated = generator.apply_mutation(probe, CORSMutationStrategy.ORIGIN_CASING)
    assert mutated.origin_value == "HTTPS://EVIL.COM"
    
    mutated = generator.apply_mutation(probe, CORSMutationStrategy.PROTOCOL_SMUGGLING)
    assert mutated.origin_value == "http://evil.com"

# Analyzer Tests (CORS)
def test_analyzer_origin_reflection_detection(analyzer):
    probe = CORSProbe("https://example.com/api", CORSVulnerabilityType.ORIGIN_REFLECTION, CORSMutationStrategy.ORIGIN_CASING, "https://evil.com")
    resp = CORSProbeResponse(probe, 200, {}, "", 0.1, acao_value="https://evil.com", acac_value="true")
    res = analyzer.analyze_origin_reflection(resp, probe)
    assert res is not None
    assert res.severity == "HIGH"

def test_analyzer_null_origin_detection(analyzer):
    probe = CORSProbe("https://example.com/api", CORSVulnerabilityType.NULL_ORIGIN, CORSMutationStrategy.ORIGIN_CASING, "null")
    resp = CORSProbeResponse(probe, 200, {}, "", 0.1, acao_value="null", acac_value="true")
    res = analyzer.analyze_null_origin(resp, probe)
    assert res is not None
    assert res.severity == "HIGH"
    
    resp.acac_value = None
    res2 = analyzer.analyze_null_origin(resp, probe)
    assert res2 is not None
    assert res2.severity == "MEDIUM"

def test_analyzer_wildcard_credentials_detection(analyzer):
    probe = CORSProbe("https://example.com/api", CORSVulnerabilityType.WILDCARD_CREDENTIALS, CORSMutationStrategy.ORIGIN_CASING, "*")
    resp = CORSProbeResponse(probe, 200, {}, "", 0.1, acao_value="*", acac_value="true")
    res = analyzer.analyze_wildcard_credentials(resp, probe)
    assert res is not None
    assert res.severity == "CRITICAL"

def test_analyzer_subdomain_trust_detection(analyzer):
    probe = CORSProbe("https://example.com/api", CORSVulnerabilityType.SUBDOMAIN_TRUST_ABUSE, CORSMutationStrategy.SUBDOMAIN_INJECTION, "https://attacker.example.com")
    resp = CORSProbeResponse(probe, 200, {}, "", 0.1, acao_value="https://attacker.example.com", acac_value="false")
    res = analyzer.analyze_subdomain_trust(resp, probe)
    assert res is not None
    assert res.severity == "MEDIUM"

# Analyzer Tests (Headers)
def test_analyzer_header_audit_missing_csp(analyzer):
    res = analyzer.audit_security_headers({}, "https://example.com")
    csp_findings = [f for f in res if f.vulnerability_type == HeaderVulnerabilityType.MISSING_CSP]
    assert len(csp_findings) == 1
    assert csp_findings[0].severity == "MEDIUM"

def test_analyzer_header_audit_weak_hsts(analyzer):
    headers = {"Strict-Transport-Security": "max-age=1000"}
    res = analyzer.audit_security_headers(headers, "https://example.com")
    hsts_findings = [f for f in res if f.vulnerability_type == HeaderVulnerabilityType.WEAK_HSTS]
    assert len(hsts_findings) == 1
    assert hsts_findings[0].severity == "LOW"

def test_analyzer_header_audit_strong_hsts_no_finding(analyzer):
    headers = {"Strict-Transport-Security": "max-age=31536000; includeSubDomains"}
    res = analyzer.audit_security_headers(headers, "https://example.com")
    hsts_findings = [f for f in res if "hsts" in f.vulnerability_type.value]
    assert len(hsts_findings) == 0

def test_analyzer_header_audit_all_headers_independent(analyzer):
    res = analyzer.audit_security_headers({}, "https://example.com")
    assert len(res) >= 3 # missing csp, hsts, xfo, etc.

# Collector lifecycle test
def test_collector_lifecycle_quadruple_publishing():
    collector = CORSSecurityCollector()
    mission = MockMission(["https://example.com/api"])
    
    with patch.object(collector.http, "request") as mock_req:
        class FakeResp:
            def __init__(self, headers):
                self.status_code = 200
                self.headers = headers
                self.text = ""
        mock_req.return_value = FakeResp({
            "Access-Control-Allow-Origin": "https://evil.com",
            "Access-Control-Allow-Credentials": "true"
        })
        
        collector.collect(mission)
        
        assert len(mission.evidence) > 0
        assert len(mission.vulnerabilities) > 0
        assert mission.attack_surface_graph.add.called
        assert mission.attack_surface_graph.connect.called

# Engine / Registry integration tests
def test_tool_registry_and_aliases():
    from argus.runtime.registry import registry
    tool = registry.get("cors_security")
    assert tool is not None
    assert tool.id == "cors_security"
    assert "header_security" in tool.capabilities or "header_audit" in tool.capabilities

def test_plugin_executor_adapter_fallback():
    from argus.runtime.plugins import PluginExecutorAdapter
    adapter = PluginExecutorAdapter()
    col = adapter._instantiate_specialist_fallback("cors_security")
    assert type(col).__name__ == "CORSSecurityCollector"
    col = adapter._instantiate_specialist_fallback("header_security")
    assert type(col).__name__ == "CORSSecurityCollector"

def test_task_generator_dag_scheduling():
    from argus.planning.task_generator import TaskGenerator
    from argus.planning.models import TaskCategory, CoverageGap
    gen = TaskGenerator(Mock())
    gap = CoverageGap(category=TaskCategory.EVIDENCE_CORRELATION, area="cors", description="Missing CORS validation")
    template = gen._resolve_template_for_gap(gap)
    assert template["metadata"]["tool_id"] == "cors_security"

def test_cvss_cwe_mappings():
    from argus.reporting.cvss import CVSSCalculator
    cwe_info = CVSSCalculator.get_cwe_for_category("cors_security")
    assert cwe_info.id == "CWE-942"
    cwe_info = CVSSCalculator.get_cwe_for_category("header_security")
    assert cwe_info.id == "CWE-693"
