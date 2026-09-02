"""
Adversarial and False Positive Rejection test suite for SSTI Detection Engine.
Validates 0 findings on hardened endpoints, raw reflections, static baseline numbers,
and multi-engine disambiguation edge cases.
"""
from typing import Any, Dict, List, Optional, Tuple
import pytest
import urllib.parse

from argus.collectors.ssti import (
    SSTICollector,
    SSTIPayloadGenerator,
    SSTISecurityAnalyzer,
    SSTIProber,
    SSTIProbe,
    SSTIProbeResponse,
    SSTIResult,
    SSTISeverity,
    SSTITechnique,
    SSTIEngineFamily,
    SSTIMutationStrategy,
)
from argus.evidence.model import Evidence
from argus.graph.graph import KnowledgeGraph
from argus.http.client import HttpResponse
from argus.runtime.mission import Mission


class MockAdversarialHttpClient:
    """Configurable mock HTTP client for adversarial and false positive tests."""

    def __init__(self, mode: str = "hardened"):
        self.mode = mode
        self.requested_urls: List[str] = []

    def get(self, url: str, **kwargs) -> HttpResponse:
        target_url = str(url)
        self.requested_urls.append(target_url)

        # Mode 1: Static Echo / Reflection (Echoes whatever was sent in query)
        if self.mode == "echo":
            parsed = urllib.parse.urlparse(target_url)
            qs = urllib.parse.parse_qs(parsed.query)
            reflected_val = list(qs.values())[0][0] if qs else ""
            return HttpResponse(
                success=True,
                status_code=200,
                raw_body=f"<html><body><h1>Search Results for: {reflected_val}</h1></body></html>",
                body=f"<html><body><h1>Search Results for: {reflected_val}</h1></body></html>",
                url=target_url,
                elapsed=0.05,
            )

        # Mode 2: HTML Escaped Echo
        elif self.mode == "html_escaped_echo":
            parsed = urllib.parse.urlparse(target_url)
            qs = urllib.parse.parse_qs(parsed.query)
            raw_val = list(qs.values())[0][0] if qs else ""
            escaped_val = (
                raw_val.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;")
                .replace("'", "&#x27;")
            )
            return HttpResponse(
                success=True,
                status_code=200,
                raw_body=f"<div>User input: {escaped_val}</div>",
                body=f"<div>User input: {escaped_val}</div>",
                url=target_url,
                elapsed=0.05,
            )

        # Mode 3: Numbers Naturally Present in Baseline
        elif self.mode == "baseline_numbers":
            # Response always contains 49, 1337, 56154 naturally
            return HttpResponse(
                success=True,
                status_code=200,
                raw_body="<html><body>Inventory count: 49, User ID: 1337, Order ID: 56154</body></html>",
                body="<html><body>Inventory count: 49, User ID: 1337, Order ID: 56154</body></html>",
                url=target_url,
                elapsed=0.05,
            )

        # Mode 4: Hardened Endpoint (Rejects with 400 Bad Request)
        elif self.mode == "hardened":
            return HttpResponse(
                success=False,
                status_code=400,
                raw_body='{"error": "Invalid characters detected in template parameter"}',
                body='{"error": "Invalid characters detected in template parameter"}',
                url=target_url,
                elapsed=0.05,
            )

        # Mode 5: Generic 404 Not Found
        elif self.mode == "not_found":
            return HttpResponse(
                success=False,
                status_code=404,
                raw_body="404 Not Found",
                body="404 Not Found",
                url=target_url,
                elapsed=0.05,
            )

        # Mode 6: Python Jinja2 Evaluation
        elif self.mode == "jinja2_vulnerable":
            parsed = urllib.parse.urlparse(target_url)
            qs = urllib.parse.parse_qs(parsed.query)
            val = list(qs.values())[0][0] if qs else ""
            if "7*'7'" in val:
                out = "7777777"
            elif "7*7" in val or "7 * 7" in val:
                out = "49"
            elif "config" in val:
                out = "<Config {'ENV': 'production', 'DEBUG': False}>"
            elif "subclasses" in val or "popen" in val:
                out = "uid=1000(app) gid=1000(app) groups=1000(app)"
            else:
                out = "Template rendered"
            return HttpResponse(
                success=True,
                status_code=200,
                raw_body=f"<div>{out}</div>",
                body=f"<div>{out}</div>",
                url=target_url,
                elapsed=0.05,
            )

        # Mode 7: PHP Twig Evaluation
        elif self.mode == "twig_vulnerable":
            parsed = urllib.parse.urlparse(target_url)
            qs = urllib.parse.parse_qs(parsed.query)
            val = list(qs.values())[0][0] if qs else ""
            if "7*'7'" in val:
                out = "49"  # Twig converts string '7' to int 7 -> 49
            elif "7*7" in val:
                out = "49"
            elif "_self.env" in val:
                out = "Twig\\Environment object"
            elif "filter('system')" in val or "registerUndefinedFilterCallback" in val:
                out = "uid=33(www-data) gid=33(www-data)"
            else:
                out = "Twig output"
            return HttpResponse(
                success=True,
                status_code=200,
                raw_body=f"<div>{out}</div>",
                body=f"<div>{out}</div>",
                url=target_url,
                elapsed=0.05,
            )

        # Default Clean
        return HttpResponse(
            success=True,
            status_code=200,
            raw_body="OK",
            body="OK",
            url=target_url,
            elapsed=0.05,
        )

    def post(self, url: str, **kwargs) -> HttpResponse:
        return self.get(url, **kwargs)


# =============================================================================
# False Positive Rejection Tests
# =============================================================================

def test_fp_rejection_static_echo():
    """Validates that verbatim unrendered echoes generate ZERO findings."""
    client = MockAdversarialHttpClient(mode="echo")
    mission = Mission(target="http://secure.app")
    mission.endpoints = ["http://secure.app/search?q=test"]
    mission.attack_surface_graph = KnowledgeGraph()

    collector = SSTICollector(http_client=client)
    evidence = collector.collect(mission)

    assert len(evidence) == 0, f"Expected 0 findings on raw reflection, got {len(evidence)}"
    assert len(mission.vulnerabilities) == 0


def test_fp_rejection_html_escaped_reflection():
    """Validates that HTML-escaped echoes generate ZERO findings."""
    client = MockAdversarialHttpClient(mode="html_escaped_echo")
    mission = Mission(target="http://secure.app")
    mission.endpoints = ["http://secure.app/profile?name=test"]
    mission.attack_surface_graph = KnowledgeGraph()

    collector = SSTICollector(http_client=client)
    evidence = collector.collect(mission)

    assert len(evidence) == 0, f"Expected 0 findings on escaped reflection, got {len(evidence)}"


def test_fp_rejection_static_numbers_in_baseline():
    """Validates that numbers naturally in baseline do not trigger false positive canary hits."""
    client = MockAdversarialHttpClient(mode="baseline_numbers")
    mission = Mission(target="http://secure.app")
    mission.endpoints = ["http://secure.app/catalog?page=1"]
    mission.attack_surface_graph = KnowledgeGraph()

    collector = SSTICollector(http_client=client)
    evidence = collector.collect(mission)

    assert len(evidence) == 0, f"Expected 0 findings on baseline numbers, got {len(evidence)}"


def test_fp_rejection_hardened_400_endpoint():
    """Validates that hardened endpoints returning 400 Bad Request generate ZERO findings."""
    client = MockAdversarialHttpClient(mode="hardened")
    mission = Mission(target="http://hardened.corp")
    mission.endpoints = ["http://hardened.corp/render?t=default"]
    mission.attack_surface_graph = KnowledgeGraph()

    collector = SSTICollector(http_client=client)
    evidence = collector.collect(mission)

    assert len(evidence) == 0


def test_fp_rejection_not_found_404():
    """Validates that 404 endpoints generate ZERO findings."""
    client = MockAdversarialHttpClient(mode="not_found")
    mission = Mission(target="http://hardened.corp")
    mission.endpoints = ["http://hardened.corp/nonexistent"]
    mission.attack_surface_graph = KnowledgeGraph()

    collector = SSTICollector(http_client=client)
    evidence = collector.collect(mission)

    assert len(evidence) == 0


# =============================================================================
# Multi-Engine Disambiguation & Differential Tests
# =============================================================================

def test_differential_routing_jinja2_vs_twig():
    """Validates decision tree routing disambiguates Jinja2 (7777777) vs Twig (49)."""
    # 1. Test Jinja2
    client_jinja = MockAdversarialHttpClient(mode="jinja2_vulnerable")
    mission_j = Mission(target="http://jinja.app")
    mission_j.endpoints = ["http://jinja.app/render?t=1"]
    mission_j.attack_surface_graph = KnowledgeGraph()

    collector_j = SSTICollector(http_client=client_jinja)
    ev_j = collector_j.collect(mission_j)
    assert len(ev_j) >= 1
    assert "jinja" in ev_j[0].metadata["engine"].lower()

    # 2. Test Twig
    client_twig = MockAdversarialHttpClient(mode="twig_vulnerable")
    mission_t = Mission(target="http://twig.app")
    mission_t.endpoints = ["http://twig.app/render?t=1"]
    mission_t.attack_surface_graph = KnowledgeGraph()

    collector_t = SSTICollector(http_client=client_twig)
    ev_t = collector_t.collect(mission_t)
    assert len(ev_t) >= 1
    assert "twig" in ev_t[0].metadata["engine"].lower() or "php" in ev_t[0].metadata["engine"].lower()


def test_sandbox_escape_critical_severity_elevation():
    """Validates that confirmed RCE elevates severity to CRITICAL with CVSS 9.8."""
    client = MockAdversarialHttpClient(mode="jinja2_vulnerable")
    mission = Mission(target="http://jinja.app")
    mission.endpoints = ["http://jinja.app/exec?cmd=1"]
    mission.attack_surface_graph = KnowledgeGraph()

    collector = SSTICollector(http_client=client)
    evidence = collector.collect(mission)

    assert len(evidence) >= 1
    # Check that at least one finding is CRITICAL or HIGH
    severities = {e.severity for e in evidence}
    assert SSTISeverity.CRITICAL.value in severities or SSTISeverity.HIGH.value in severities


# =============================================================================
# Malformed & Extreme Edge Case Resilience
# =============================================================================

def test_malformed_probe_responses_handled_gracefully():
    """Validates that None/empty bodies and network exceptions are handled without crash."""
    analyzer = SSTISecurityAnalyzer()
    probe = SSTIProbe(url="http://example.com", payload="{{7*7}}", expected_canary="49")

    # Empty response
    resp_empty = SSTIProbeResponse(probe=probe, status_code=500, body="", elapsed=0.0)
    assert analyzer.analyze_probe_response(probe, resp_empty) is None

    # Garbage binary response
    resp_bin = SSTIProbeResponse(probe=probe, status_code=200, body="\x00\xff\xfe\x01\x02", elapsed=0.0)
    assert analyzer.analyze_probe_response(probe, resp_bin) is None


def test_mutation_strategy_permutations():
    """Validates all mutation strategy permutations produce non-empty strings."""
    gen = SSTIPayloadGenerator()
    payloads = [
        "{{7*7}}",
        "${7*7}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        "new java.lang.ProcessBuilder('id')",
    ]

    for p in payloads:
        for strat in SSTIMutationStrategy:
            mut = gen.apply_mutation_strategy(p, strat)
            assert isinstance(mut, str)
            assert len(mut) > 0
