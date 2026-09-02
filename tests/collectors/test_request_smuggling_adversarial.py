"""
Adversarial, Evasion, and Edge-Case Tests for HTTP Request Smuggling Detection Module:
- High-jitter latency resilience (preventing false positives when network is slow)
- Chunk extensions, malformed chunks, and non-hex length handling
- Header folding and CRLF injection obfuscations
- Conflicting and duplicate Content-Length headers
- Hop-by-hop Connection stripping variations
- HTTP/2 pseudo-header and custom header CRLF injections
- Status inversion with canary path/marker reflections
- Hardened server RFC compliance suppression
- Socket connection reset and timeout error handling
- ControlledMission wrapper publish_finding integration
- Malformed URLs, IPv6 addresses, and non-standard ports
"""
from __future__ import annotations

import urllib.parse
from typing import Any, Dict, List, Optional, Tuple
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
)
from argus.evidence.model import Evidence
from argus.plugins.interfaces import ControlledMission
from argus.runtime.mission import Mission


def test_adversarial_high_jitter_latency_suppression():
    """
    If baseline latency is already high (e.g. 3.5s due to congested network or heavy server load),
    an injected latency of 4.5s (delta 1.0s) MUST NOT trigger a desynchronization finding.
    """
    res = RequestSmugglingSecurityAnalyzer.analyze_timing_response(
        endpoint_url="http://slow-server.local/heavy-op",
        technique=RequestSmugglingTechnique.CL_TE.value,
        strategy=RequestSmugglingMutationStrategy.STANDARD.value,
        baseline_elapsed=3.50,
        injected_elapsed=4.50,
        threshold=3.0,
        status_code=200,
    )
    assert res is None, "High baseline latency falsely triggered a timing desync finding"


def test_adversarial_socket_timeout_with_fast_baseline():
    """
    When baseline is fast (0.05s) and injected probe times out at 5.0s,
    a timing desync finding MUST be generated with high confidence.
    """
    res = RequestSmugglingSecurityAnalyzer.analyze_timing_response(
        endpoint_url="http://target.local/api",
        technique=RequestSmugglingTechnique.CL_TE.value,
        strategy=RequestSmugglingMutationStrategy.STANDARD.value,
        baseline_elapsed=0.05,
        injected_elapsed=5.0,
        threshold=3.0,
        status_code=0,
        error_message="socket_timeout",
    )
    assert res is not None
    assert res.matched_signature == "differential_timing_desync_delay"
    assert res.cvss_score == 9.8


def test_adversarial_crlf_header_folding_obfuscation():
    """
    Tests multiline / folded Transfer-Encoding headers (RFC 7230 §3.2.4 deprecation exploit).
    """
    mutations = RequestSmugglingPayloadGenerator.generate_te_te_mutations("target.org", "/api")
    folding_probes = [m for m in mutations if "Transfer-Encoding:\r\n chunked" in m[1]]
    assert len(folding_probes) >= 1
    strat, probe, fol, desc = folding_probes[0]
    assert strat == RequestSmugglingMutationStrategy.HEADER_CASING_WHITESPACE
    assert "Transfer-Encoding:\r\n chunked" in probe


def test_adversarial_dual_conflicting_headers():
    """
    Tests dual conflicting Transfer-Encoding headers (e.g. Transfer-Encoding: x and Transfer-Encoding: chunked).
    """
    mutations = RequestSmugglingPayloadGenerator.generate_te_te_mutations("target.org", "/api")
    dual_probes = [m for m in mutations if m[0] == RequestSmugglingMutationStrategy.DUAL_HEADER]
    assert len(dual_probes) >= 2


def test_adversarial_hop_by_hop_connection_stripping():
    """
    Tests Connection: Transfer-Encoding header stripping through proxies.
    """
    mutations = RequestSmugglingPayloadGenerator.generate_te_te_mutations("target.org", "/api")
    hop_probes = [m for m in mutations if m[0] == RequestSmugglingMutationStrategy.HOP_BY_HOP]
    assert len(hop_probes) >= 2
    assert any("Connection: Transfer-Encoding" in m[1] for m in hop_probes)


def test_adversarial_chunk_extensions_and_hex_variations():
    """
    Tests chunk extension ';foo=bar' and uppercase hex '0X0' mutations.
    """
    mutations = RequestSmugglingPayloadGenerator.generate_te_te_mutations("target.org", "/api")
    chunk_exts = [m for m in mutations if m[0] == RequestSmugglingMutationStrategy.CHUNK_EXTENSION]
    hex_muts = [m for m in mutations if m[0] == RequestSmugglingMutationStrategy.HEX_MUTATION]
    assert len(chunk_exts) >= 1
    assert len(hex_muts) >= 1
    assert "0;foo=bar" in chunk_exts[0][1]
    assert "0X0" in hex_muts[0][1]


def test_adversarial_h2_path_pseudo_header_crlf_injection():
    """
    Tests simulated HTTP/2 :path pseudo-header CRLF injection.
    """
    probes = RequestSmugglingPayloadGenerator.generate_h2_downgrade_probes("h2.target.org", "/h2_test")
    crlf_probes = [p for p in probes if p[0] == RequestSmugglingTechnique.H2_CRLF]
    assert len(crlf_probes) >= 2
    path_crlf = [p for p in crlf_probes if p[1] == RequestSmugglingMutationStrategy.H2_PSEUDO_HEADER]
    assert len(path_crlf) >= 1
    assert "\r\nTransfer-Encoding: chunked" in path_crlf[0][2][":path"]


def test_adversarial_status_inversion_with_canary_reflection():
    """
    Tests pipeline response analysis when follow-up returns 405 Method Not Allowed
    and reflects the canary in response body.
    """
    atk_r = RawHttpResponse(status_code=200, body="Accepted", elapsed=0.05)
    fol_r = RawHttpResponse(
        status_code=405,
        body="Method GPOST not allowed for /argus_smuggled_canary (ARGUS_SMUGGLE_CANARY)",
        headers={"allow": "GET, POST"},
        elapsed=0.05,
    )
    res = RequestSmugglingSecurityAnalyzer.analyze_pipeline_response(
        endpoint_url="http://target.local/api",
        technique=RequestSmugglingTechnique.CL_TE.value,
        strategy=RequestSmugglingMutationStrategy.STANDARD.value,
        attack_resp=atk_r,
        follow_up_resp=fol_r,
        baseline_status=200,
    )
    assert res is not None
    assert res.matched_signature == "canary_reflection"
    assert res.cvss_score == 9.8


def test_adversarial_hardened_rfc_compliance_suppression():
    """
    When server responds with HTTP 505 HTTP Version Not Supported or 400 Bad Request,
    no finding should be reported.
    """
    atk_r = RawHttpResponse(status_code=505, body="505 HTTP Version Not Supported", elapsed=0.05)
    fol_r = RawHttpResponse(status_code=200, body="Normal", elapsed=0.05)
    res = RequestSmugglingSecurityAnalyzer.analyze_pipeline_response(
        endpoint_url="http://target.local/api",
        technique=RequestSmugglingTechnique.CL_TE.value,
        strategy=RequestSmugglingMutationStrategy.STANDARD.value,
        attack_resp=atk_r,
        follow_up_resp=fol_r,
    )
    assert res is None


def test_adversarial_network_connection_reset_handling():
    """
    Tests that connection resets or socket errors during raw probing are handled gracefully.
    """
    def reset_adapter(url: str, payload: Any, timeout: float = 5.0):
        return RawHttpResponse(
            status_code=0,
            error="[Errno 104] Connection reset by peer",
            elapsed=0.02,
            url=url,
        )

    prober = RawHttpStreamProber(transport_adapter=reset_adapter)
    collector = HTTPRequestSmugglingCollector(prober=prober)
    mission = Mission(id="test_reset", target="http://unstable.local", endpoints=["http://unstable.local/api"])

    evidences = collector.collect(mission)
    assert len(evidences) == 0


def test_adversarial_controlled_mission_publish_finding():
    """
    Tests ControlledMission wrapping and finding publication.
    """
    published_findings: Dict[str, Evidence] = {}

    class MockControlledMission:
        def __init__(self, raw_mission: Mission):
            self._raw_mission = raw_mission
            self.id = raw_mission.id
            self.target = raw_mission.target

        def publish_finding(self, finding_id: str, evidence: Evidence):
            published_findings[finding_id] = evidence

    raw_m = Mission(
        id="cm_mission",
        target="http://controlled.local",
        endpoints=["http://controlled.local/test"],
    )
    cm = MockControlledMission(raw_m)

    res = RequestSmugglingResult(
        technique=RequestSmugglingTechnique.CL_TE.value,
        mutation_strategy=RequestSmugglingMutationStrategy.STANDARD.value,
        severity=RequestSmugglingSeverity.CRITICAL.value,
        confidence=0.95,
        payload="test_payload",
        matched_signature="canary_reflection",
        evidence_snippet="Smuggling confirmed",
        endpoint_url="http://controlled.local/test",
    )

    collector = HTTPRequestSmugglingCollector()
    ev = collector._publish_finding(cm, res, "http://controlled.local", "http://controlled.local/test")

    assert ev is not None
    assert ev.evidence_id in published_findings
    assert published_findings[ev.evidence_id].category == "request_smuggling"


def test_adversarial_custom_ports_and_ipv6_endpoints():
    """
    Tests candidate endpoint discovery with custom ports and IPv6.
    """
    mission = Mission(
        id="ipv6_mission",
        target="http://[::1]:8080",
        endpoints=["http://[::1]:8080/api", "https://sub.target.org:8443/custom"],
        live_hosts=["http://[::1]:8080", "https://sub.target.org:8443"],
    )
    collector = HTTPRequestSmugglingCollector()
    candidates = collector._discover_candidate_endpoints(mission)
    assert "http://[::1]:8080/api" in candidates
    assert "https://sub.target.org:8443/custom" in candidates
    assert any(":8080" in c for c in candidates)
    assert any(":8443" in c for c in candidates)
