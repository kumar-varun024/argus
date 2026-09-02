"""
Adversarial, False Positive Rejection, and Edge-Case Test Suite for Cache Security Detection Module.

Covers:
- False positive rejection of uncached dynamic reflections (Replay returns cache MISS and clean body)
- False positive rejection of unreflected headers (Backend ignores injected header)
- False positive rejection of public static assets without PII (WCD probe on public content)
- False positive rejection of global dynamic reflections (Canary echoes across all requests including control)
- False positive rejection of WAF blocks and rate limiting (HTTP 429 / 403 blocks)
- False positive rejection of internal server errors (500 without caching)
- Monotonic Age progression validation when X-Cache / CF-Cache-Status headers are stripped
- Complex parameter cloaking delimiters and encoding variations
- Handling of malformed, non-ASCII, and empty header response structures
- Web Cache Deception false positive rejection when unauthenticated control also returns same PII
- Graceful recovery during network socket timeouts and connection resets
"""
import pytest
from typing import Any, Dict, List, Optional

from argus.collectors.cache_security import (
    CacheSecurityCollector,
    CacheSecurityPayloadGenerator,
    CacheSecurityProber,
    CacheSecurityAnalyzer,
    CacheProbe,
    CacheProbeResponse,
    CacheVulnerabilityType,
    CacheEngineFamily,
    CacheStatus,
    CacheMutationStrategy,
)
from argus.http.client import HttpResponse


class AdversarialMockHttpClient:
    """Mock HTTP client simulating adversarial edge cases and hardened servers."""

    def __init__(self, mode: str):
        self.mode = mode
        self.calls = 0

    def request(self, method: str, url: str, **kwargs) -> HttpResponse:
        self.calls += 1

        if self.mode == "uncached_reflection":
            # Direct request (perturbed) reflects header dynamically, but is NOT cached (MISS on replay)
            headers = kwargs.get("headers") or {}
            if "x-forwarded-host" in headers:
                body = f'<script src="//{headers["x-forwarded-host"]}/app.js"></script>'
                return HttpResponse(success=True, status_code=200, headers={"cf-cache-status": "MISS", "x-cache": "MISS"}, raw_body=body, body=body, url=url)
            return HttpResponse(success=True, status_code=200, headers={"cf-cache-status": "MISS", "x-cache": "MISS"}, raw_body="Clean Uncached Body", body="Clean Uncached Body", url=url)

        elif self.mode == "unreflected_header":
            # Origin completely ignores the injected header
            return HttpResponse(success=True, status_code=200, headers={"cf-cache-status": "HIT", "x-cache": "HIT"}, raw_body="Standard Page Content", body="Standard Page Content", url=url)

        elif self.mode == "global_dynamic_echo":
            # Origin reflects canary in every request regardless of headers or cache
            return HttpResponse(success=True, status_code=200, headers={"cf-cache-status": "HIT"}, raw_body="global_canary_everywhere", body="global_canary_everywhere", url=url)

        elif self.mode == "waf_rate_limit":
            # Origin or WAF blocks request with 429 Too Many Requests
            return HttpResponse(success=False, status_code=429, headers={"retry-after": "60"}, raw_body="Rate limit exceeded", body="Rate limit exceeded", url=url)

        elif self.mode == "server_error_500":
            # Origin errors out
            return HttpResponse(success=False, status_code=500, headers={}, raw_body="Internal Server Error", body="Internal Server Error", url=url)

        elif self.mode == "stripped_headers_with_age":
            # No X-Cache header, but Age progression indicates caching
            headers = kwargs.get("headers") or {}
            if "x-forwarded-host" in headers:
                body = f'<script src="//{headers["x-forwarded-host"]}/app.js"></script>'
                return HttpResponse(success=True, status_code=200, headers={"age": "0"}, raw_body=body, body=body, url=url)
            # Replay returns cached body with Age > 0
            if "b1" in url:
                return HttpResponse(success=True, status_code=200, headers={"age": "35"}, raw_body='<script src="//poisoned.argus.local/app.js"></script>', body='<script src="//poisoned.argus.local/app.js"></script>', url=url)
            return HttpResponse(success=True, status_code=200, headers={"age": "0"}, raw_body="Clean Content", body="Clean Content", url=url)

        elif self.mode == "network_timeout":
            # Simulates connection timeout
            raise TimeoutError("Connection timed out to origin server")

        return HttpResponse(success=True, status_code=200, headers={}, raw_body="OK", body="OK", url=url)

    def get(self, url: str, **kwargs) -> HttpResponse:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> HttpResponse:
        return self.request("POST", url, **kwargs)


def test_adversarial_rejection_uncached_reflection():
    """
    When an injected header reflects dynamically on the initial request, but the
    replay request returns a cache MISS and clean body, the analyzer MUST reject
    the false positive.
    """
    client = AdversarialMockHttpClient(mode="uncached_reflection")
    prober = CacheSecurityProber(http_client=client)
    probe = CacheProbe(
        probe_id="p_adv_xfh",
        target_url="https://target.com/search",
        vulnerability_type=CacheVulnerabilityType.UNKEYED_HEADER_POISONING,
        strategy=CacheMutationStrategy.DYNAMIC_CACHE_BUSTER_INSERTION,
        headers={"X-Forwarded-Host": "poison.argus.local"},
        canary="poison.argus.local",
        vector_name="X-Forwarded-Host",
        payload_value="poison.argus.local",
    )

    responses = prober.execute_differential_sequence("https://target.com/search", probe)
    analyzer = CacheSecurityAnalyzer()
    res = analyzer.evaluate_unkeyed_header_poisoning(responses, probe)
    assert res is None, "Uncached dynamic reflection was falsely identified as cache poisoning!"


def test_adversarial_rejection_unreflected_header():
    """
    When an injected header is ignored by the backend and not reflected in either
    body or headers, the finding MUST be rejected.
    """
    client = AdversarialMockHttpClient(mode="unreflected_header")
    prober = CacheSecurityProber(http_client=client)
    probe = CacheProbe(
        probe_id="p_adv_unref",
        target_url="https://target.com/about",
        vulnerability_type=CacheVulnerabilityType.UNKEYED_HEADER_POISONING,
        strategy=CacheMutationStrategy.DYNAMIC_CACHE_BUSTER_INSERTION,
        headers={"X-Original-URL": "/admin"},
        canary="/admin",
        vector_name="X-Original-URL",
        payload_value="/admin",
    )

    responses = prober.execute_differential_sequence("https://target.com/about", probe)
    analyzer = CacheSecurityAnalyzer()
    res = analyzer.evaluate_unkeyed_header_poisoning(responses, probe)
    assert res is None, "Unreflected header was falsely identified as cache poisoning!"


def test_adversarial_rejection_public_static_asset_no_pii():
    """
    When a Web Cache Deception probe hits a static asset route that returns 200 OK
    and cache HIT, but contains NO sensitive user PII/tokens, the finding MUST be rejected.
    """
    probe = CacheProbe(
        probe_id="p_adv_wcd_static",
        target_url="https://target.com/static/style",
        vulnerability_type=CacheVulnerabilityType.WEB_CACHE_DECEPTION,
        strategy=CacheMutationStrategy.CACHE_RULE_PROBE_VARIATIONS,
        path_suffix="/nonexistent.css",
        vector_name="wcd_extension_.css",
        payload_value="/nonexistent.css",
        is_auth_required=True,
    )

    baseline_resp = CacheProbeResponse(
        probe=probe, status_code=200, headers={"x-cache": "HIT"}, body="body { color: red; }", raw_body="body { color: red; }",
        elapsed=0.01, cache_status=CacheStatus.HIT, engine=CacheEngineFamily.CLOUDFLARE, pii_detected=False, pii_matches=[]
    )
    perturbed_resp = CacheProbeResponse(
        probe=probe, status_code=200, headers={"x-cache": "HIT"}, body="body { color: red; }", raw_body="body { color: red; }",
        elapsed=0.01, cache_status=CacheStatus.HIT, engine=CacheEngineFamily.CLOUDFLARE, pii_detected=False, pii_matches=[]
    )
    replay_resp = CacheProbeResponse(
        probe=probe, status_code=200, headers={"x-cache": "HIT"}, body="body { color: red; }", raw_body="body { color: red; }",
        elapsed=0.01, cache_status=CacheStatus.HIT, engine=CacheEngineFamily.CLOUDFLARE, pii_detected=False, pii_matches=[]
    )
    control_resp = CacheProbeResponse(
        probe=probe, status_code=200, headers={"x-cache": "HIT"}, body="body { color: red; }", raw_body="body { color: red; }",
        elapsed=0.01, cache_status=CacheStatus.HIT, engine=CacheEngineFamily.CLOUDFLARE, pii_detected=False, pii_matches=[]
    )

    responses = {
        "baseline": baseline_resp,
        "perturbed": perturbed_resp,
        "replay": replay_resp,
        "control": control_resp,
    }

    analyzer = CacheSecurityAnalyzer()
    res = analyzer.evaluate_web_cache_deception(responses, probe)
    assert res is None, "Public static asset without PII was falsely identified as Web Cache Deception!"


def test_adversarial_rejection_global_dynamic_echo():
    """
    When the server dynamically echoes a token on all requests (including fresh control B2),
    it is an application echo rather than a cache persistence flaw; MUST be rejected.
    """
    client = AdversarialMockHttpClient(mode="global_dynamic_echo")
    prober = CacheSecurityProber(http_client=client)
    probe = CacheProbe(
        probe_id="p_adv_echo",
        target_url="https://target.com/echo",
        vulnerability_type=CacheVulnerabilityType.UNKEYED_PARAM_POISONING,
        strategy=CacheMutationStrategy.DYNAMIC_CACHE_BUSTER_INSERTION,
        params={"utm_content": "global_canary_everywhere"},
        canary="global_canary_everywhere",
        vector_name="utm_content",
        payload_value="global_canary_everywhere",
    )

    responses = prober.execute_differential_sequence("https://target.com/echo", probe)
    analyzer = CacheSecurityAnalyzer()
    res = analyzer.evaluate_unkeyed_param_poisoning(responses, probe)
    assert res is None, "Global dynamic echo was falsely identified as cache poisoning!"


def test_adversarial_rejection_waf_rate_limit_block():
    """
    When the server or WAF blocks probe requests with 429 Too Many Requests or 403 Forbidden,
    no cache vulnerability must be emitted.
    """
    client = AdversarialMockHttpClient(mode="waf_rate_limit")
    prober = CacheSecurityProber(http_client=client)
    probe = CacheProbe(
        probe_id="p_adv_waf",
        target_url="https://target.com/api",
        vulnerability_type=CacheVulnerabilityType.UNKEYED_HEADER_POISONING,
        strategy=CacheMutationStrategy.DYNAMIC_CACHE_BUSTER_INSERTION,
        headers={"X-Forwarded-Host": "blocked.local"},
        canary="blocked.local",
        vector_name="X-Forwarded-Host",
        payload_value="blocked.local",
    )

    responses = prober.execute_differential_sequence("https://target.com/api", probe)
    analyzer = CacheSecurityAnalyzer()
    res = analyzer.evaluate_unkeyed_header_poisoning(responses, probe)
    assert res is None, "WAF rate limit was falsely identified as cache poisoning!"


def test_adversarial_rejection_server_error_500():
    """
    When origin server returns 500 Internal Server Error, reject findings unless error caching is confirmed.
    """
    client = AdversarialMockHttpClient(mode="server_error_500")
    prober = CacheSecurityProber(http_client=client)
    probe = CacheProbe(
        probe_id="p_adv_500",
        target_url="https://target.com/crash",
        vulnerability_type=CacheVulnerabilityType.FAT_GET_POISONING,
        strategy=CacheMutationStrategy.REQUEST_NORMALIZATION_INVERSION,
        method="GET",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        body="crash=1",
        canary="crash",
        vector_name="FAT_GET_urlencoded",
        payload_value="crash=1",
    )

    responses = prober.execute_differential_sequence("https://target.com/crash", probe)
    analyzer = CacheSecurityAnalyzer()
    res = analyzer.evaluate_normalization_flaws(responses, probe)
    assert res is None, "Server error without caching was falsely identified as vulnerability!"


def test_adversarial_cache_status_header_stripped_with_age_progression():
    """
    When reverse proxies strip X-Cache / CF-Cache-Status headers, but Age header
    advances monotonically (Age > 0), the prober and analyzer MUST successfully confirm caching.
    """
    client = AdversarialMockHttpClient(mode="stripped_headers_with_age")
    prober = CacheSecurityProber(http_client=client)
    probe = CacheProbe(
        probe_id="p_adv_age",
        target_url="https://target.com/article",
        vulnerability_type=CacheVulnerabilityType.UNKEYED_HEADER_POISONING,
        strategy=CacheMutationStrategy.DYNAMIC_CACHE_BUSTER_INSERTION,
        headers={"X-Forwarded-Host": "poisoned.argus.local"},
        canary="poisoned.argus.local",
        vector_name="X-Forwarded-Host",
        payload_value="poisoned.argus.local",
    )

    responses = prober.execute_differential_sequence("https://target.com/article", probe, probe_nonce="b1")
    analyzer = CacheSecurityAnalyzer()
    res = analyzer.evaluate_unkeyed_header_poisoning(responses, probe)
    assert res is not None, "Monotonic Age progression was not recognized as a cache hit!"
    assert res.is_valid_finding is True
    assert res.metadata["age"] == 35


def test_adversarial_parameter_cloaking_semicolon_and_hash_permutations():
    """
    Verifies parameter cloaking permutations with semicolons and URL encodings.
    """
    generator = CacheSecurityPayloadGenerator()
    probes = generator.build_unkeyed_param_probes("https://target.com/catalog", canary="adv_cloak_canary")

    semi_probe = next(p for p in probes if p.vector_name == "parameter_cloaking_semicolon")
    assert ";utm_content=adv_cloak_canary" in semi_probe.params["k"]

    hash_probe = next(p for p in probes if p.vector_name == "parameter_cloaking_hash")
    assert "%23" in hash_probe.params["utm_content"]


def test_adversarial_empty_and_malformed_headers():
    """
    Verifies analyzer resilience against empty, missing, or malformed cache header dictionaries.
    """
    analyzer = CacheSecurityAnalyzer()

    # Empty dictionary
    s, e, age = analyzer.analyze_cache_lifecycle({})
    assert s == CacheStatus.UNKNOWN
    assert e == CacheEngineFamily.GENERIC
    assert age is None

    # Malformed non-integer Age
    s, e, age = analyzer.analyze_cache_lifecycle({"age": "not-an-int", "x-cache": "invalid_value"})
    assert age is None
    assert s == CacheStatus.UNKNOWN

    # Non-standard uppercase keys
    s, e, age = analyzer.analyze_cache_lifecycle({"CF-CACHE-STATUS": "HIT", "SERVER": "CLOUDFLARE"})
    assert s == CacheStatus.HIT
    assert e == CacheEngineFamily.CLOUDFLARE


def test_adversarial_wcd_public_endpoint_returning_same_pii_on_control():
    """
    When unauthenticated control request B2 also returns the same PII (publicly exposed data
    already available to unauthenticated users, not private tenant leakage), reject WCD finding.
    """
    probe = CacheProbe(
        probe_id="p_adv_wcd_public_pii",
        target_url="https://target.com/public_team_directory",
        vulnerability_type=CacheVulnerabilityType.WEB_CACHE_DECEPTION,
        strategy=CacheMutationStrategy.CACHE_RULE_PROBE_VARIATIONS,
        path_suffix="/team.json",
        vector_name="wcd_extension_.json",
        payload_value="/team.json",
        is_auth_required=True,
    )

    resp_pii = '{"team_lead_email": "lead@company.com", "token": "eyJpub.lic.tok"}'
    responses = {
        "baseline": CacheProbeResponse(probe=probe, status_code=200, headers={"x-cache": "MISS"}, body=resp_pii, raw_body=resp_pii, elapsed=0.05, cache_status=CacheStatus.MISS, engine=CacheEngineFamily.GENERIC, pii_detected=True, pii_matches=["email:1"]),
        "perturbed": CacheProbeResponse(probe=probe, status_code=200, headers={"x-cache": "MISS"}, body=resp_pii, raw_body=resp_pii, elapsed=0.05, cache_status=CacheStatus.MISS, engine=CacheEngineFamily.GENERIC, pii_detected=True, pii_matches=["email:1"]),
        "replay": CacheProbeResponse(probe=probe, status_code=200, headers={"x-cache": "HIT", "age": "10"}, body=resp_pii, raw_body=resp_pii, elapsed=0.01, cache_status=CacheStatus.HIT, engine=CacheEngineFamily.GENERIC, age=10, pii_detected=True, pii_matches=["email:1"]),
        "control": CacheProbeResponse(probe=probe, status_code=200, headers={"x-cache": "MISS"}, body=resp_pii, raw_body=resp_pii, elapsed=0.05, cache_status=CacheStatus.MISS, engine=CacheEngineFamily.GENERIC, pii_detected=True, pii_matches=["email:1"]),
    }

    analyzer = CacheSecurityAnalyzer()
    res = analyzer.evaluate_web_cache_deception(responses, probe)
    assert res is None, "Publicly exposed directory was falsely identified as private Web Cache Deception!"


def test_adversarial_network_timeout_and_connection_error_graceful_recovery():
    """
    Verifies that network connection timeouts and socket resets do not crash the collector
    and are handled gracefully.
    """
    client = AdversarialMockHttpClient(mode="network_timeout")
    prober = CacheSecurityProber(http_client=client)
    collector = CacheSecurityCollector(prober=prober)

    from argus.runtime.mission import Mission
    mission = Mission(id="test_timeout_m", target="https://timeout.target.com", endpoints=["https://timeout.target.com/hang"])

    evidence = collector.collect(mission)
    assert isinstance(evidence, list)
    assert len(evidence) == 0  # No false positives or unhandled crashes on timeout
