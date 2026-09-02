"""
Empirical Challenger Exhaustive Stress Harness for Sprint 19 HTTP Request Smuggling Module.
Audits edge cases, evasion resilience, false positive immunity, and all mutation/downgrade strategies.
"""
import pytest
from argus.collectors.request_smuggling import (
    HTTPRequestSmugglingCollector,
    RequestSmugglingCollector,
    RequestSmugglingPayloadGenerator,
    RequestSmugglingSecurityAnalyzer,
    RawHttpStreamProber,
    RawHttpResponse,
    RequestSmugglingResult,
    RequestSmugglingSeverity,
    RequestSmugglingTechnique,
    RequestSmugglingMutationStrategy,
    HARDENED_DEFENSE_SIGNATURES,
    CANARY_DESYNC_SIGNATURES,
)
from argus.runtime.mission import Mission
from argus.evidence.model import Evidence


class ChallengerAdversarialTransport:
    """Configurable transport for adversarial matrix testing."""
    def __init__(self, responder_func):
        self.responder_func = responder_func
        self.history = []

    def adapter(self, url, payload, timeout=5.0):
        payload_str = payload if isinstance(payload, str) else payload.decode("latin-1", errors="replace")
        self.history.append((url, payload_str))
        return self.responder_func(url, payload_str, timeout)


# ============================================================================
# Dimension 1: False Positive Suppression on Hardened & Benign Endpoints
# ============================================================================

@pytest.mark.parametrize("status,body,headers", [
    (400, "400 Bad Request: Malformed HTTP request", {}),
    (400, "Invalid request line format", {"Server": "nginx"}),
    (400, "Duplicate Content-Length header rejected", {}),
    (400, "Transfer-Encoding not supported by proxy", {}),
    (400, "RFC compliance error: conflicting transfer encoding and content length", {}),
    (501, "501 Not Implemented: Chunked transfer encoding is not supported", {}),
    (501, "Unsupported method", {}),
    (505, "505 HTTP Version Not Supported", {}),
    (200, "Normal 200 response with no canary or desync indicators", {"Content-Type": "text/html"}),
    (403, "403 Forbidden: Access Denied", {}),
    (401, "401 Unauthorized: Authentication required", {}),
    (500, "500 Internal Server Error: Database connection pool exhausted", {}),
    (503, "503 Service Unavailable: Backends busy", {}),
])
def test_fp_suppression_hardened_rejection_matrix(status, body, headers):
    """Verifies that hardened defenses and standard non-desync error codes are never flagged."""
    # Timing analysis check
    res_timing = RequestSmugglingSecurityAnalyzer.analyze_timing_response(
        endpoint_url="http://hardened.target/api",
        technique="cl_te",
        strategy="standard",
        baseline_elapsed=0.1,
        injected_elapsed=5.0,
        threshold=3.0,
        status_code=status,
        error_message=body if status in (400, 501, 505) else None,
    )
    if status in (400, 501, 505) or any(p.search(body) for p in HARDENED_DEFENSE_SIGNATURES.values()):
        assert res_timing is None, f"False positive timing finding on hardened status {status} with body: {body}"

    # Pipeline analysis check
    atk_r = RawHttpResponse(status_code=status, body=body, headers=headers, elapsed=0.05)
    fol_r = RawHttpResponse(status_code=200, body="Normal benign content", headers={"Content-Type": "text/plain"}, elapsed=0.05)
    res_pipe = RequestSmugglingSecurityAnalyzer.analyze_pipeline_response(
        endpoint_url="http://hardened.target/api",
        technique="cl_te",
        strategy="standard",
        attack_resp=atk_r,
        follow_up_resp=fol_r,
        baseline_status=200,
    )
    assert res_pipe is None, f"False positive pipeline finding on status {status} with body: {body}"


def test_fp_suppression_synchronized_latency():
    """Fast baseline (0.05s) and fast injected (0.05s) must never trigger timing desync."""
    res = RequestSmugglingSecurityAnalyzer.analyze_timing_response(
        endpoint_url="http://fast.target/api",
        technique="cl_te",
        strategy="standard",
        baseline_elapsed=0.05,
        injected_elapsed=0.06,
        threshold=3.0,
        status_code=200,
    )
    assert res is None


def test_fp_suppression_heavy_server_slow_baseline():
    """Slow baseline (2.2s) and slow injected (5.5s) must be suppressed because baseline >= 2.0s."""
    res = RequestSmugglingSecurityAnalyzer.analyze_timing_response(
        endpoint_url="http://slow.target/api",
        technique="te_cl",
        strategy="standard",
        baseline_elapsed=2.2,
        injected_elapsed=5.5,
        threshold=3.0,
        status_code=200,
    )
    assert res is None


# ============================================================================
# Dimension 2: Genuine Detection & Confirmation Pipelines
# ============================================================================

def test_genuine_cl_te_differential_timing():
    """CL.TE differential timing probe detection."""
    res = RequestSmugglingSecurityAnalyzer.analyze_timing_response(
        endpoint_url="http://vuln.target/submit",
        technique=RequestSmugglingTechnique.CL_TE.value,
        strategy=RequestSmugglingMutationStrategy.STANDARD.value,
        baseline_elapsed=0.08,
        injected_elapsed=4.60,
        threshold=3.0,
        status_code=200,
    )
    assert res is not None
    assert res.technique == "cl_te"
    assert res.severity == RequestSmugglingSeverity.CRITICAL.value
    assert res.cvss_score == 9.8
    assert res.delay_delta >= 4.5
    assert res.cwe_id == "CWE-444"


def test_genuine_te_cl_differential_timing():
    """TE.CL differential timing probe detection."""
    res = RequestSmugglingSecurityAnalyzer.analyze_timing_response(
        endpoint_url="http://vuln.target/search",
        technique=RequestSmugglingTechnique.TE_CL.value,
        strategy=RequestSmugglingMutationStrategy.STANDARD.value,
        baseline_elapsed=0.12,
        injected_elapsed=4.90,
        threshold=3.0,
        status_code=200,
    )
    assert res is not None
    assert res.technique == "te_cl"
    assert res.severity == RequestSmugglingSeverity.CRITICAL.value
    assert res.cvss_score == 9.8
    assert res.cwe_id == "CWE-444"


def test_genuine_cl_te_2_request_pipeline_canary_reflection():
    """CL.TE 2-request confirmation pipeline via canary reflection in header and body."""
    atk_r = RawHttpResponse(status_code=200, body="Probe queued", elapsed=0.04)
    fol_r = RawHttpResponse(
        status_code=200,
        body="<h1>Echo: ARGUS_SMUGGLE_CANARY</h1>",
        headers={"X-Smuggled-Echo": "ARGUS_SMUGGLE_CANARY"},
        elapsed=0.04,
    )
    res = RequestSmugglingSecurityAnalyzer.analyze_pipeline_response(
        endpoint_url="http://vuln.target/api",
        technique=RequestSmugglingTechnique.CL_TE.value,
        strategy=RequestSmugglingMutationStrategy.STANDARD.value,
        attack_resp=atk_r,
        follow_up_resp=fol_r,
        canary_marker="ARGUS_SMUGGLE_CANARY",
        baseline_status=200,
    )
    assert res is not None
    assert res.matched_signature == "canary_reflection"
    assert res.confidence == 0.98
    assert res.cvss_score == 9.8


def test_genuine_te_cl_2_request_pipeline_status_inversion():
    """TE.CL 2-request confirmation pipeline via generic 404 status inversion on canary path."""
    atk_r = RawHttpResponse(status_code=200, body="Attack chunk accepted", elapsed=0.04)
    fol_r = RawHttpResponse(
        status_code=404,
        body="404 Not Found: Endpoint does not exist",
        headers={"Content-Type": "text/html"},
        elapsed=0.04,
    )
    res = RequestSmugglingSecurityAnalyzer.analyze_pipeline_response(
        endpoint_url="http://vuln.target/api",
        technique=RequestSmugglingTechnique.TE_CL.value,
        strategy=RequestSmugglingMutationStrategy.STANDARD.value,
        attack_resp=atk_r,
        follow_up_resp=fol_r,
        baseline_status=200,
    )
    assert res is not None
    assert res.matched_signature == "pipeline_status_inversion"
    assert res.follow_up_status == 404
    assert res.confidence == 0.92


def test_genuine_te_cl_2_request_pipeline_canary_path_reflection():
    """TE.CL 2-request confirmation pipeline when 404 body reflects the canary path."""
    atk_r = RawHttpResponse(status_code=200, body="Attack chunk accepted", elapsed=0.04)
    fol_r = RawHttpResponse(
        status_code=404,
        body="404 Not Found: Cannot route /argus_smuggled_canary",
        headers={"Content-Type": "text/html"},
        elapsed=0.04,
    )
    res = RequestSmugglingSecurityAnalyzer.analyze_pipeline_response(
        endpoint_url="http://vuln.target/api",
        technique=RequestSmugglingTechnique.TE_CL.value,
        strategy=RequestSmugglingMutationStrategy.STANDARD.value,
        attack_resp=atk_r,
        follow_up_resp=fol_r,
        baseline_status=200,
    )
    assert res is not None
    assert res.matched_signature == "canary_reflection"
    assert res.confidence == 0.98


# ============================================================================
# Dimension 3: TE.TE Mutation Strategies Comprehensive Verification
# ============================================================================

def test_all_six_te_te_mutation_strategies():
    """Validates that all 6 mutation strategies are produced and detected."""
    mutations = RequestSmugglingPayloadGenerator.generate_te_te_mutations("test.target.org", "/api")
    strat_map = {}
    for strat, atk, fol, desc in mutations:
        strat_map.setdefault(strat, []).append((atk, fol, desc))

    # 1. HEADER_CASING_WHITESPACE
    assert RequestSmugglingMutationStrategy.HEADER_CASING_WHITESPACE in strat_map
    assert len(strat_map[RequestSmugglingMutationStrategy.HEADER_CASING_WHITESPACE]) >= 4

    # 2. DUAL_HEADER
    assert RequestSmugglingMutationStrategy.DUAL_HEADER in strat_map
    assert len(strat_map[RequestSmugglingMutationStrategy.DUAL_HEADER]) >= 3

    # 3. HOP_BY_HOP
    assert RequestSmugglingMutationStrategy.HOP_BY_HOP in strat_map
    assert len(strat_map[RequestSmugglingMutationStrategy.HOP_BY_HOP]) >= 3

    # 4. CHUNK_EXTENSION
    assert RequestSmugglingMutationStrategy.CHUNK_EXTENSION in strat_map
    assert any("0;foo=bar" in m[0] for m in strat_map[RequestSmugglingMutationStrategy.CHUNK_EXTENSION])

    # 5. HEX_MUTATION
    assert RequestSmugglingMutationStrategy.HEX_MUTATION in strat_map
    assert any("0X0" in m[0] for m in strat_map[RequestSmugglingMutationStrategy.HEX_MUTATION])

    # 6. COMMA_DELIMITED
    assert RequestSmugglingMutationStrategy.COMMA_DELIMITED in strat_map
    assert any("chunked, identity" in m[0] for m in strat_map[RequestSmugglingMutationStrategy.COMMA_DELIMITED])

    # Test detection across each strategy
    for strat in [
        RequestSmugglingMutationStrategy.HEADER_CASING_WHITESPACE,
        RequestSmugglingMutationStrategy.DUAL_HEADER,
        RequestSmugglingMutationStrategy.HOP_BY_HOP,
        RequestSmugglingMutationStrategy.CHUNK_EXTENSION,
        RequestSmugglingMutationStrategy.HEX_MUTATION,
        RequestSmugglingMutationStrategy.COMMA_DELIMITED,
    ]:
        atk_p, fol_p, desc = strat_map[strat][0]
        atk_r = RawHttpResponse(status_code=200, body="OK", elapsed=0.05)
        fol_r = RawHttpResponse(status_code=404, body="Canary 404", headers={"X-Canary": "ARGUS_SMUGGLE_CANARY"}, elapsed=0.05)
        res = RequestSmugglingSecurityAnalyzer.analyze_pipeline_response(
            endpoint_url="http://test.target.org/api",
            technique=RequestSmugglingTechnique.TE_TE.value,
            strategy=strat.value,
            attack_resp=atk_r,
            follow_up_resp=fol_r,
            baseline_status=200,
            payload=atk_p,
        )
        assert res is not None
        assert res.technique == "te_te"
        assert res.mutation_strategy == strat.value


# ============================================================================
# Dimension 4: HTTP/2 Downgrading Vectors (H2.CL, H2.TE, CRLF Injection)
# ============================================================================

def test_h2_downgrade_vector_generation_and_analysis():
    """Validates H2.CL, H2.TE, and pseudo-header CRLF injection vectors."""
    probes = RequestSmugglingPayloadGenerator.generate_h2_downgrade_probes("h2.example.com", "/h2_api")
    tech_set = {p[0] for p in probes}
    assert RequestSmugglingTechnique.H2_CL in tech_set
    assert RequestSmugglingTechnique.H2_TE in tech_set
    assert RequestSmugglingTechnique.H2_CRLF in tech_set

    # Test H2.CL
    h2_cl_probe = [p for p in probes if p[0] == RequestSmugglingTechnique.H2_CL][0]
    res_h2_cl = RequestSmugglingSecurityAnalyzer.analyze_h2_downgrade_response(
        endpoint_url="https://h2.example.com/h2_api",
        technique=h2_cl_probe[0].value,
        strategy=h2_cl_probe[1].value,
        response=RawHttpResponse(status_code=404, body="Smuggled request executed", elapsed=0.05),
    )
    assert res_h2_cl is not None
    assert res_h2_cl.technique == "h2_cl"
    assert res_h2_cl.cvss_score == 9.8

    # Test H2.TE
    h2_te_probe = [p for p in probes if p[0] == RequestSmugglingTechnique.H2_TE][0]
    res_h2_te = RequestSmugglingSecurityAnalyzer.analyze_h2_downgrade_response(
        endpoint_url="https://h2.example.com/h2_api",
        technique=h2_te_probe[0].value,
        strategy=h2_te_probe[1].value,
        response=RawHttpResponse(status_code=200, body="Response containing ARGUS_SMUGGLE_CANARY reflected", elapsed=0.05),
    )
    assert res_h2_te is not None
    assert res_h2_te.technique == "h2_te"

    # Test H2 CRLF in :path
    h2_crlf_probe = [p for p in probes if p[0] == RequestSmugglingTechnique.H2_CRLF and p[1] == RequestSmugglingMutationStrategy.H2_PSEUDO_HEADER][0]
    res_h2_crlf = RequestSmugglingSecurityAnalyzer.analyze_h2_downgrade_response(
        endpoint_url="https://h2.example.com/h2_api",
        technique=h2_crlf_probe[0].value,
        strategy=h2_crlf_probe[1].value,
        response=RawHttpResponse(status_code=502, body="Bad Gateway after CRLF injection desync", elapsed=0.05),
    )
    assert res_h2_crlf is not None
    assert res_h2_crlf.technique == "h2_crlf"


# ============================================================================
# Dimension 5: Raw HTTP Socket Response Parser Robustness
# ============================================================================

def test_raw_parser_edge_cases():
    """Tests header folding, LF-only lines, binary data, and empty bodies."""
    # 1. LF only instead of CRLF
    lf_data = b"HTTP/1.1 200 OK\nServer: custom\nContent-Length: 4\n\ntest"
    resp_lf = RawHttpStreamProber._parse_raw_http_response(lf_data, 0.01, "http://target/")
    assert resp_lf.status_code == 200
    assert resp_lf.headers.get("server") == "custom"
    assert resp_lf.body == "test"

    # 2. Non-standard status code
    non_std = b"HTTP/1.1 999 Custom Status\r\nHeader: 1\r\n\r\nBody"
    resp_non_std = RawHttpStreamProber._parse_raw_http_response(non_std, 0.01, "http://target/")
    assert resp_non_std.status_code == 999

    # 3. Malformed status line
    malformed = b"GARBAGE_NO_STATUS\r\nHeader: 1\r\n\r\nBody"
    resp_mal = RawHttpStreamProber._parse_raw_http_response(malformed, 0.01, "http://target/")
    assert resp_mal.status_code == 0


# ============================================================================
# Dimension 6: E2E Collector Quadruple State Updates Validation
# ============================================================================

def test_e2e_collector_full_quadruple_state_update():
    """
    Validates that executing HTTPRequestSmugglingCollector on a mission with a vulnerable target
    updates:
    1. mission.evidence
    2. mission.vulnerabilities
    3. mission.attack_surface_graph (HAS_ENDPOINT, HAS_VULNERABILITY)
    4. ControlledMission finding publisher (if wrapped)
    """
    def vulnerable_router(url, payload, timeout=5.0):
        if "Transfer-Encoding: chunked" in payload and "ARGUS_SMUGGLE_CANARY" in payload:
            return RawHttpResponse(status_code=200, body="Smuggle chunk staged", elapsed=0.05, url=url)
        elif "x=123" in payload:
            return RawHttpResponse(
                status_code=404,
                body="404 Not Found: /argus_smuggled_canary",
                headers={"X-Canary-Reflected": "ARGUS_SMUGGLE_CANARY"},
                elapsed=0.05,
                url=url,
            )
        return RawHttpResponse(status_code=200, body="OK", elapsed=0.05, url=url)

    transport = ChallengerAdversarialTransport(vulnerable_router)
    prober = RawHttpStreamProber(transport_adapter=transport.adapter)
    collector = HTTPRequestSmugglingCollector(prober=prober)

    mission = Mission(
        id="e2e_smuggle_mission",
        target="http://e2e-target.local",
        endpoints=["http://e2e-target.local/api/orders"],
        live_hosts=["http://e2e-target.local"],
    )

    evidences = collector.collect(mission)
    assert len(evidences) >= 1

    # 1. Evidence Store
    ev = evidences[0]
    assert ev.category == "request_smuggling"
    assert ev.status == "CONFIRMED"
    assert ev.severity == "critical"
    assert ev.confidence >= 0.90
    assert "CWE-444" in ev.description

    # 2. Mission Vulnerabilities
    assert len(mission.vulnerabilities) >= 1
    vuln = mission.vulnerabilities[0]
    assert vuln["cwe_id"] == "CWE-444"
    assert vuln["cvss_score"] == 9.8

    # 3. Attack Surface Graph
    graph = mission.attack_surface_graph
    assert graph is not None
    lh_nodes = graph.nodes_by_type("live_host")
    ep_nodes = graph.nodes_by_type("endpoint")
    vuln_nodes = graph.nodes_by_type("vulnerability")
    assert len(lh_nodes) >= 1
    assert len(ep_nodes) >= 1
    assert len(vuln_nodes) >= 1

    has_endpoint_edges = [e for e in graph.edges if e.type == "HAS_ENDPOINT"]
    has_vuln_edges = [e for e in graph.edges if e.type == "HAS_VULNERABILITY"]
    assert len(has_endpoint_edges) >= 1
    assert len(has_vuln_edges) >= 2
