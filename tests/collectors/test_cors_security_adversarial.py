import pytest
from unittest.mock import Mock, patch

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

@pytest.fixture
def analyzer():
    return CORSSecurityAnalyzer()

def test_same_origin_cors_no_finding(analyzer):
    probe = CORSProbe("https://example.com/api", CORSVulnerabilityType.ORIGIN_REFLECTION, CORSMutationStrategy.ORIGIN_CASING, "https://example.com")
    resp = CORSProbeResponse(probe, 200, {}, "", 0.1, acao_value="https://example.com", acac_value="true")
    res = analyzer.analyze_origin_reflection(resp, probe)
    assert res is None

def test_wildcard_without_credentials_public_api_no_finding(analyzer):
    probe = CORSProbe("https://example.com/api", CORSVulnerabilityType.WILDCARD_CREDENTIALS, CORSMutationStrategy.ORIGIN_CASING, "*")
    resp = CORSProbeResponse(probe, 200, {}, "", 0.1, acao_value="*", acac_value="false")
    res = analyzer.analyze_wildcard_credentials(resp, probe)
    assert res is None

def test_strong_hsts_no_finding(analyzer):
    headers = {"Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload"}
    res = analyzer.audit_security_headers(headers, "https://example.com")
    hsts_findings = [f for f in res if "hsts" in f.vulnerability_type.value]
    assert len(hsts_findings) == 0

def test_all_headers_present_and_strong_no_finding(analyzer):
    headers = {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff"
    }
    res = analyzer.audit_security_headers(headers, "https://example.com")
    assert len(res) == 0

def test_waf_block_429_no_finding():
    collector = CORSSecurityCollector()
    collector._discover_candidate_endpoints = Mock(return_value=["https://example.com/api"])
    
    with patch.object(collector.http, "request") as mock_req:
        class FakeResp:
            def __init__(self):
                self.status_code = 429
                self.headers = {}
                self.text = "Too Many Requests"
        mock_req.return_value = FakeResp()
        
        mission = Mock()
        mission._raw_mission = mission
        evs = collector.collect(mission)
        
        # We might have header findings from the first GET, but if the first GET returns 429, we should check if it handles it.
        # Actually our mock returns 429 for all requests. The header audit does not explicitly skip 429, but CORS does.
        # Let's ensure CORS didn't produce findings.
        assert len([e for e in evs if e.metadata.get("vulnerability_type") == "origin_reflection"]) == 0

def test_server_error_500_no_finding():
    collector = CORSSecurityCollector()
    collector._discover_candidate_endpoints = Mock(return_value=["https://example.com/api"])
    
    with patch.object(collector.http, "request") as mock_req:
        class FakeResp:
            def __init__(self):
                self.status_code = 500
                self.headers = {}
                self.text = "Internal Server Error"
        mock_req.return_value = FakeResp()
        
        mission = Mock()
        mission._raw_mission = mission
        evs = collector.collect(mission)
        assert len([e for e in evs if e.metadata.get("vulnerability_type") == "origin_reflection"]) == 0

def test_network_timeout_no_crash():
    collector = CORSSecurityCollector()
    collector._discover_candidate_endpoints = Mock(return_value=["https://example.com/api"])
    
    with patch.object(collector.http, "request", side_effect=TimeoutError("Timeout")):
        mission = Mock()
        mission._raw_mission = mission
        evs = collector.collect(mission)
        assert len(evs) == 0

def test_empty_response_headers_no_crash(analyzer):
    res = analyzer.audit_security_headers({}, "https://example.com")
    assert len(res) > 0 # Will just report missing headers

def test_malformed_hsts_header_graceful(analyzer):
    headers = {"Strict-Transport-Security": "max-age=abc"}
    res = analyzer.audit_security_headers(headers, "https://example.com")
    hsts_findings = [f for f in res if f.vulnerability_type == HeaderVulnerabilityType.WEAK_HSTS]
    assert len(hsts_findings) == 1
    assert "malformed" in hsts_findings[0].recommendation.lower()

def test_cors_on_non_cors_endpoint_no_finding(analyzer):
    probe = CORSProbe("https://example.com/api", CORSVulnerabilityType.ORIGIN_REFLECTION, CORSMutationStrategy.ORIGIN_CASING, "https://evil.com")
    resp = CORSProbeResponse(probe, 200, {}, "", 0.1, acao_value=None, acac_value=None)
    res = analyzer.analyze_origin_reflection(resp, probe)
    assert res is None
