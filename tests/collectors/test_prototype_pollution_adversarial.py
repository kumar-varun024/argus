"""
Adversarial, Evasion, Mutation, and Fault-Tolerance Tests for Prototype Pollution Module:
Covers the 5 mutation strategies, WAF/Rate-limit suppression, HTML entity neutralization,
network timeouts, deep traversal, circular redirect loops, and malformed payload resilience.
"""
from __future__ import annotations

import copy
import html
import json
import urllib.parse
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
import pytest

from argus.collectors.prototype_pollution import (
    PrototypePollutionCollector,
    PrototypePollutionPayloadGenerator,
    PrototypePollutionProber,
    PrototypePollutionAnalyzer,
    PrototypePollutionProbe,
    PrototypePollutionProbeResponse,
    PrototypePollutionResult,
    PrototypePollutionVulnerabilityType,
    PrototypePollutionMutationStrategy,
    GadgetFramework,
)
from argus.evidence.model import Evidence
from argus.http.client import HttpResponse
from argus.runtime.mission import Mission


# =============================================================================
# Configurable Mock Adversarial HTTP Client
# =============================================================================

class MockAdversarialHttpClient:
    """Mock client simulating adversarial network conditions, WAFs, and filters."""

    def __init__(self, mode: str = "normal"):
        self.mode = mode
        self.handlers: List[Tuple[Callable[..., bool], Callable[..., HttpResponse]]] = []
        self.request_history: List[Dict[str, Any]] = []

    def add_handler(self, predicate: Callable[..., bool], response_fn: Callable[..., HttpResponse]) -> None:
        self.handlers.append((predicate, response_fn))

    def request(self, *args: Any, **kwargs: Any) -> HttpResponse:
        method = kwargs.get("method")
        url = kwargs.get("url")
        if args:
            if isinstance(args[0], str):
                method = args[0]
                url = args[1] if len(args) > 1 else url
            else:
                method = args[1] if len(args) > 1 else method
                url = args[2] if len(args) > 2 else url
        method = (method or "GET").upper()
        target_url = str(url or "")
        headers = kwargs.get("headers") or {}
        json_data = kwargs.get("json")
        data = kwargs.get("data")
        params = kwargs.get("params") or {}

        req_record = {
            "method": method,
            "url": target_url,
            "headers": headers,
            "json": json_data,
            "data": data,
            "params": params,
        }
        self.request_history.append(req_record)

        # 1. Custom Handlers
        for predicate, resp_fn in self.handlers:
            if predicate(method, target_url, headers, json_data, data, params):
                return resp_fn(method, target_url, headers, json_data, data, params)

        # 2. Modes
        if self.mode == "waf_403":
            return HttpResponse(
                success=False,
                status_code=403,
                body="<html><head><title>403 Forbidden - WAF Blocked Request</title></head><body>Request blocked by security rule</body></html>",
                headers={"Content-Type": "text/html", "Server": "Cloudflare-WAF"},
                url=target_url,
                elapsed=0.02,
            )

        if self.mode == "rate_limit_429":
            return HttpResponse(
                success=False,
                status_code=429,
                body='{"error": "Too Many Requests", "retry_after": 60}',
                headers={"Content-Type": "application/json", "Retry-After": "60"},
                url=target_url,
                elapsed=0.01,
            )

        if self.mode == "unsupported_media_415":
            return HttpResponse(
                success=False,
                status_code=415,
                body='{"error": "Unsupported Media Type: application/x-www-form-urlencoded"}',
                headers={"Content-Type": "application/json"},
                url=target_url,
                elapsed=0.01,
            )

        if self.mode == "socket_drop":
            raise ConnectionResetError("Connection reset by peer: socket drop")

        if self.mode == "html_entity_escaping":
            input_val = str(data or json_data or params or "")
            escaped = html.escape(input_val)
            return HttpResponse(
                success=True,
                status_code=200,
                body=f"<html><body>User feedback: {escaped}</body></html>",
                headers={"Content-Type": "text/html"},
                url=target_url,
                elapsed=0.02,
            )

        # Default fallback response
        return HttpResponse(
            success=True,
            status_code=200,
            body='{"status": "ok"}',
            headers={"Content-Type": "application/json"},
            url=target_url,
            elapsed=0.05,
        )

    def get(self, url: str, headers: Optional[Dict[str, str]] = None, params: Optional[Dict[str, Any]] = None) -> HttpResponse:
        return self.request("GET", url, headers=headers, params=params)

    def post(self, url: str, headers: Optional[Dict[str, str]] = None, json: Optional[Any] = None, data: Optional[Any] = None) -> HttpResponse:
        return self.request("POST", url, headers=headers, json=json, data=data)


# =============================================================================
# Adversarial Tests: The 5 Mutation & Evasion Strategies (R4)
# =============================================================================

def test_mutation_strategy_json_key_encoding_variations():
    gen = PrototypePollutionPayloadGenerator()
    probe = PrototypePollutionProbe(
        probe_id="p_base",
        target_url="http://example.com/api",
        method="POST",
        json_data={"__proto__": {"polluted": "yes"}, "constructor": {"prototype": {"foo": "bar"}}},
    )
    mutated = gen.apply_mutation(probe, PrototypePollutionMutationStrategy.JSON_KEY_ENCODING)
    assert mutated.strategy == PrototypePollutionMutationStrategy.JSON_KEY_ENCODING
    assert "\\u005f\\u005fproto\\u005f\\u005f" in mutated.json_data
    assert 'constructor["prototype"]' in mutated.json_data


def test_mutation_strategy_content_type_manipulation():
    gen = PrototypePollutionPayloadGenerator()
    probe = PrototypePollutionProbe(
        probe_id="p_json",
        target_url="http://example.com/api",
        method="POST",
        json_data={"__proto__": {"polluted": "yes"}},
    )
    mutated = gen.apply_mutation(probe, PrototypePollutionMutationStrategy.CONTENT_TYPE_MANIPULATION)
    assert mutated.strategy == PrototypePollutionMutationStrategy.CONTENT_TYPE_MANIPULATION
    assert mutated.content_type == "application/x-www-form-urlencoded"
    assert "__proto__[polluted]=yes" in str(mutated.data)
    assert mutated.json_data is None


def test_mutation_strategy_redirect_url_encoding_schemes():
    gen = PrototypePollutionPayloadGenerator()
    probes = gen.generate_evasion_probes("http://example.com/login")
    redirect_evasions = [p for p in probes if p.vulnerability_type == PrototypePollutionVulnerabilityType.OPEN_REDIRECT]
    assert len(redirect_evasions) >= 3

    has_scheme_rel = any("//evil.com" in p.target_url for p in redirect_evasions)
    has_auth_at = any("@evil.com" in p.target_url for p in redirect_evasions)
    has_double_enc = any("%252f" in p.target_url for p in redirect_evasions)
    assert has_scheme_rel
    assert has_auth_at
    assert has_double_enc


def test_mutation_strategy_dom_clobbering_variants():
    gen = PrototypePollutionPayloadGenerator()
    probe = PrototypePollutionProbe(
        probe_id="p_form",
        target_url="http://example.com/comments",
        method="POST",
        data={"content": '<form id="cookie"><input id="value"></form>'},
    )
    mutated = gen.apply_mutation(probe, PrototypePollutionMutationStrategy.DOM_CLOBBERING_VARIANTS)
    assert mutated.strategy == PrototypePollutionMutationStrategy.DOM_CLOBBERING_VARIANTS
    assert "<a id=" in str(mutated.data["content"])


def test_mutation_strategy_frame_busting_bypass_techniques():
    gen = PrototypePollutionPayloadGenerator()
    probe = PrototypePollutionProbe(
        probe_id="p_frame",
        target_url="http://example.com/login",
        method="GET",
        vulnerability_type=PrototypePollutionVulnerabilityType.CLICKJACKING,
    )
    mutated = gen.apply_mutation(probe, PrototypePollutionMutationStrategy.FRAME_BUSTING_BYPASS)
    assert mutated.strategy == PrototypePollutionMutationStrategy.FRAME_BUSTING_BYPASS
    assert "frame_sandbox" in mutated.metadata


# =============================================================================
# Adversarial Tests: Robustness, WAF & Fault Tolerance
# =============================================================================

def test_adversarial_waf_403_rejection_not_vulnerable():
    mock_client = MockAdversarialHttpClient(mode="waf_403")
    mission = Mission(target="http://example.com")
    mission.http_client = mock_client
    mission.endpoints = ["http://example.com/api/user"]

    collector = PrototypePollutionCollector()
    ev_list = collector.collect(mission)
    assert len(ev_list) == 0


def test_adversarial_rate_limiting_429_rejection_not_vulnerable():
    mock_client = MockAdversarialHttpClient(mode="rate_limit_429")
    mission = Mission(target="http://example.com")
    mission.http_client = mock_client
    mission.endpoints = ["http://example.com/api/user"]

    collector = PrototypePollutionCollector()
    ev_list = collector.collect(mission)
    assert len(ev_list) == 0


def test_adversarial_unsupported_media_type_415_handling():
    mock_client = MockAdversarialHttpClient(mode="unsupported_media_415")
    mission = Mission(target="http://example.com")
    mission.http_client = mock_client
    mission.endpoints = ["http://example.com/api/user"]

    collector = PrototypePollutionCollector()
    ev_list = collector.collect(mission)
    assert len(ev_list) == 0


def test_adversarial_html_entity_encoded_clobbering_neutralization():
    mock_client = MockAdversarialHttpClient(mode="html_entity_escaping")
    mission = Mission(target="http://example.com")
    mission.http_client = mock_client
    mission.endpoints = ["http://example.com/feedback"]

    collector = PrototypePollutionCollector()
    collector.generator.generate_all_probes = lambda url: [
        PrototypePollutionProbe(
            probe_id="p_escape_test",
            target_url="http://example.com/feedback",
            method="POST",
            vulnerability_type=PrototypePollutionVulnerabilityType.DOM_CLOBBERING,
            data={"comment": '<form id="cookie"></form>'},
            canary_property="document.cookie",
            canary_value='<form id="cookie"></form>',
        )
    ]

    ev_list = collector.collect(mission)
    # Neutralized entity encoded HTML is safe and must NOT generate evidence
    assert len(ev_list) == 0


def test_adversarial_deeply_nested_traversal_depth_analysis():
    analyzer = PrototypePollutionAnalyzer()
    probe = PrototypePollutionProbe(
        probe_id="p_deep",
        target_url="http://example.com/api/nested",
        method="POST",
        vulnerability_type=PrototypePollutionVulnerabilityType.SERVER_SIDE_PROTOTYPE_POLLUTION,
        canary_property="argus_deeply_nested_canary",
        canary_value="deep_val",
        depth=5,
        tested_parameter="level1.level2.level3.level4.__proto__",
    )
    resp = PrototypePollutionProbeResponse(
        probe=probe,
        status_code=200,
        body='{"status": "ok", "argus_deeply_nested_canary": "deep_val"}',
    )

    result = analyzer.evaluate_probe(probe, resp, "http://example.com/api/nested")
    assert result is not None
    assert result.is_valid_finding
    assert result.metadata.get("depth") == 5


def test_adversarial_network_timeout_and_socket_drop():
    mock_client = MockAdversarialHttpClient(mode="socket_drop")
    mission = Mission(target="http://example.com")
    mission.http_client = mock_client
    mission.endpoints = ["http://example.com/api/test"]

    collector = PrototypePollutionCollector()
    # Ensure collector handles socket errors gracefully without raising uncaught exceptions
    ev_list = collector.collect(mission)
    assert len(ev_list) == 0


def test_adversarial_malformed_json_and_html_handling():
    analyzer = PrototypePollutionAnalyzer()
    probe = PrototypePollutionProbe(
        probe_id="p_malformed",
        target_url="http://example.com/api",
        method="POST",
        vulnerability_type=PrototypePollutionVulnerabilityType.SERVER_SIDE_PROTOTYPE_POLLUTION,
        canary_property="canary_prop",
    )
    # Malformed response body (truncated JSON / unclosed tags)
    resp = PrototypePollutionProbeResponse(
        probe=probe,
        status_code=200,
        body='{"status": "partial, unclosed string...',
    )
    result = analyzer.evaluate_probe(probe, resp, "http://example.com/api")
    assert result is None


def test_adversarial_high_concurrency_burst():
    collector = PrototypePollutionCollector()
    mission = Mission(target="http://example.com")
    mission.http_client = MockAdversarialHttpClient(mode="normal")
    mission.endpoints = [f"http://example.com/api/v1/endpoint_{i}" for i in range(10)]

    ev_list = collector.collect(mission)
    assert isinstance(ev_list, list)


def test_adversarial_empty_redirect_destination():
    analyzer = PrototypePollutionAnalyzer()
    probe = PrototypePollutionProbe(
        probe_id="p_empty_redir",
        target_url="http://example.com/redir",
        vulnerability_type=PrototypePollutionVulnerabilityType.OPEN_REDIRECT,
    )
    resp = PrototypePollutionProbeResponse(
        probe=probe,
        status_code=302,
        headers={"Location": ""},
        redirect_history=["http://example.com/redir"],
    )
    result = analyzer.evaluate_probe(probe, resp, "http://example.com/redir")
    assert result is None


def test_adversarial_circular_redirect_loop_bounded():
    mock_client = MockAdversarialHttpClient()
    # A -> B -> A -> B loop
    mock_client.add_handler(
        lambda m, u, *a: u == "http://example.com/loop_a",
        lambda *a: HttpResponse(success=True, status_code=302, headers={"Location": "http://example.com/loop_b"}, url="http://example.com/loop_a"),
    )
    mock_client.add_handler(
        lambda m, u, *a: u == "http://example.com/loop_b",
        lambda *a: HttpResponse(success=True, status_code=302, headers={"Location": "http://example.com/loop_a"}, url="http://example.com/loop_b"),
    )

    mission = Mission(target="http://example.com")
    mission.http_client = mock_client

    prober = PrototypePollutionProber()
    probe = PrototypePollutionProbe(
        probe_id="p_loop",
        target_url="http://example.com/loop_a",
        vulnerability_type=PrototypePollutionVulnerabilityType.OPEN_REDIRECT,
    )

    resp = prober.execute_redirect_chain_probe(mission, "http://example.com/loop_a", probe, max_hops=5)
    # Loop must be terminated at max_hops (e.g. 5 or 6 items in history) without hanging
    assert len(resp.redirect_history) <= 6
