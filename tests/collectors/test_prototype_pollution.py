"""
Unit and Component tests for Prototype Pollution & Client-Side Attack Detection Module:
PrototypePollutionCollector, PrototypePollutionPayloadGenerator, PrototypePollutionProber,
PrototypePollutionAnalyzer, Quadruple State Publishing, and False Positive Rejection.
"""
from __future__ import annotations

import copy
import html
import json
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple, Union
import pytest

from argus.collectors.prototype_pollution import (
    PrototypePollutionCollector,
    ClientSideAttackCollector,
    DOMClobberingCollector,
    OpenRedirectCollector,
    ClickjackingCollector,
    ProtoPollutionCollector,
    PrototypePollutionPayloadGenerator,
    PrototypePollutionProber,
    PrototypePollutionAnalyzer,
    PrototypePollutionProbe,
    PrototypePollutionProbeResponse,
    PrototypePollutionResult,
    ClientSideAttackResult,
    PrototypePollutionVulnerabilityType,
    ClientSideVulnerabilityType,
    PrototypePollutionTechnique,
    ClientSideTechnique,
    PrototypePollutionMutationStrategy,
    ClientSideMutationStrategy,
    PrototypePollutionStrategy,
    ClientSideStrategy,
    PrototypePollutionSeverity,
    ClientSideSeverity,
    GadgetFramework,
)
from argus.evidence.model import Evidence
from argus.evidence.store import EvidenceStore
from argus.graph.graph import KnowledgeGraph
from argus.graph.node import Node
from argus.http.client import HttpResponse
from argus.runtime.mission import Mission


# =============================================================================
# Configurable Mock HTTP Client for Prototype Pollution Unit Testing
# =============================================================================

class MockPrototypePollutionHttpClient:
    """Configurable mock HTTP client for client-side and prototype pollution tests."""

    def __init__(self, routes: Optional[Dict[str, Tuple[int, str, Dict[str, str], float]]] = None):
        # key -> (status_code, body, headers, elapsed)
        self.routes: Dict[str, Tuple[int, str, Dict[str, str], float]] = dict(routes or {})
        self.request_history: List[Dict[str, Any]] = []

    def set_route(
        self,
        key: str,
        status_code: int,
        body: str,
        headers: Optional[Dict[str, str]] = None,
        elapsed: float = 0.05,
    ) -> None:
        self.routes[key] = (status_code, body, headers or {}, elapsed)

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

        self.request_history.append({
            "method": method,
            "url": target_url,
            "headers": headers,
            "json": json_data,
            "data": data,
            "params": params,
        })

        # 1. Exact URL match
        if target_url in self.routes:
            st, bd, hd, el = self.routes[target_url]
            return HttpResponse(
                success=(200 <= st < 300),
                status_code=st,
                raw_body=bd,
                body=bd,
                headers=hd,
                url=target_url,
                elapsed=el,
            )

        # 2. Match based on JSON payload contents (e.g. __proto__, constructor)
        if json_data and isinstance(json_data, dict):
            if "__proto__" in json_data and "json:__proto__" in self.routes:
                st, bd, hd, el = self.routes["json:__proto__"]
                return HttpResponse(
                    success=(200 <= st < 300),
                    status_code=st,
                    raw_body=bd,
                    body=bd,
                    headers=hd,
                    url=target_url,
                    elapsed=el,
                )
            if "constructor" in json_data and "json:constructor" in self.routes:
                st, bd, hd, el = self.routes["json:constructor"]
                return HttpResponse(
                    success=(200 <= st < 300),
                    status_code=st,
                    raw_body=bd,
                    body=bd,
                    headers=hd,
                    url=target_url,
                    elapsed=el,
                )

        # 3. Match based on Query / URL substrings
        if "__proto__" in target_url and "query:__proto__" in self.routes:
            st, bd, hd, el = self.routes["query:__proto__"]
            return HttpResponse(
                success=(200 <= st < 300),
                status_code=st,
                raw_body=bd,
                body=bd,
                headers=hd,
                url=target_url,
                elapsed=el,
            )

        # Default fallback response
        return HttpResponse(
            success=True,
            status_code=200,
            raw_body='{"status": "ok"}',
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
# Unit Tests: Enums & Aliases
# =============================================================================

def test_prototype_pollution_severity_enums_and_aliases():
    assert PrototypePollutionSeverity.CRITICAL == "critical"
    assert PrototypePollutionSeverity.HIGH == "high"
    assert PrototypePollutionSeverity.MEDIUM == "medium"
    assert PrototypePollutionSeverity.LOW == "low"
    assert PrototypePollutionSeverity.INFO == "info"
    assert PrototypePollutionSeverity.CRIT == "critical"
    assert ClientSideSeverity == PrototypePollutionSeverity


def test_prototype_pollution_vulnerability_type_enums_and_aliases():
    assert PrototypePollutionVulnerabilityType.SERVER_SIDE_PROTOTYPE_POLLUTION == "server_side_prototype_pollution"
    assert PrototypePollutionVulnerabilityType.CLIENT_SIDE_PROTOTYPE_POLLUTION == "client_side_prototype_pollution"
    assert PrototypePollutionVulnerabilityType.DOM_CLOBBERING == "dom_clobbering"
    assert PrototypePollutionVulnerabilityType.OPEN_REDIRECT == "open_redirect"
    assert PrototypePollutionVulnerabilityType.CLICKJACKING == "clickjacking"
    assert PrototypePollutionVulnerabilityType.GADGET_POLLUTION == "gadget_pollution"
    assert PrototypePollutionVulnerabilityType.DOS_POLLUTION == "dos_pollution"
    assert PrototypePollutionVulnerabilityType.RCE_GADGET == "rce_gadget"
    assert ClientSideVulnerabilityType == PrototypePollutionVulnerabilityType
    assert PrototypePollutionTechnique == PrototypePollutionVulnerabilityType
    assert ClientSideTechnique == PrototypePollutionVulnerabilityType


def test_prototype_pollution_mutation_strategy_enums_and_aliases():
    assert PrototypePollutionMutationStrategy.JSON_KEY_ENCODING == "json_key_encoding"
    assert PrototypePollutionMutationStrategy.CONTENT_TYPE_MANIPULATION == "content_type_manipulation"
    assert PrototypePollutionMutationStrategy.REDIRECT_URL_ENCODING == "redirect_url_encoding"
    assert PrototypePollutionMutationStrategy.DOM_CLOBBERING_VARIANTS == "dom_clobbering_variants"
    assert PrototypePollutionMutationStrategy.FRAME_BUSTING_BYPASS == "frame_busting_bypass"
    assert PrototypePollutionMutationStrategy.STANDARD == "standard"
    assert ClientSideMutationStrategy == PrototypePollutionMutationStrategy
    assert PrototypePollutionStrategy == PrototypePollutionMutationStrategy
    assert ClientSideStrategy == PrototypePollutionMutationStrategy


def test_gadget_framework_enums():
    assert GadgetFramework.EXPRESS == "express"
    assert GadgetFramework.LODASH == "lodash"
    assert GadgetFramework.JQUERY == "jquery"
    assert GadgetFramework.HANDLEBARS == "handlebars"
    assert GadgetFramework.NODEJS_CHILD_PROCESS == "nodejs_child_process"
    assert GadgetFramework.GENERIC == "generic"


# =============================================================================
# Unit Tests: Payload Generator
# =============================================================================

def test_payload_generator_server_side_pp_probes():
    gen = PrototypePollutionPayloadGenerator()
    probes = gen.generate_server_side_pp_probes("http://example.com/api/user")
    assert len(probes) >= 3
    has_proto = any("__proto__" in str(p.json_data) for p in probes)
    has_ctor = any("constructor" in str(p.json_data) for p in probes)
    has_nested = any(p.depth > 1 for p in probes)
    assert has_proto
    assert has_ctor
    assert has_nested


def test_payload_generator_client_side_pp_probes():
    gen = PrototypePollutionPayloadGenerator()
    probes = gen.generate_client_side_pp_probes("http://example.com/app")
    assert len(probes) >= 4
    has_bracket = any("__proto__[" in p.target_url for p in probes)
    has_dot = any("__proto__." in p.target_url for p in probes)
    has_hash = any("#__proto__" in p.target_url for p in probes)
    has_ctor = any("constructor[prototype]" in p.target_url for p in probes)
    assert has_bracket
    assert has_dot
    assert has_hash
    assert has_ctor


def test_payload_generator_dom_clobbering_probes():
    gen = PrototypePollutionPayloadGenerator()
    probes = gen.generate_dom_clobbering_probes("http://example.com/comments")
    assert len(probes) >= 3
    targets = [p.metadata.get("clobbered_target") for p in probes]
    assert "document.cookie" in targets
    assert "a.href" in targets or "document.body" in targets


def test_payload_generator_open_redirect_probes():
    gen = PrototypePollutionPayloadGenerator()
    probes = gen.generate_open_redirect_probes("http://example.com/login")
    assert len(probes) >= len(gen.REDIRECT_PARAMS)
    params = [p.tested_parameter for p in probes]
    assert "url" in params
    assert "next" in params
    assert "redirect" in params
    assert "return_to" in params


def test_payload_generator_clickjacking_probes():
    gen = PrototypePollutionPayloadGenerator()
    sensitive_probes = gen.generate_clickjacking_probes("http://example.com/login")
    assert len(sensitive_probes) >= 1
    assert sensitive_probes[0].vulnerability_type == PrototypePollutionVulnerabilityType.CLICKJACKING

    non_sensitive_probes = gen.generate_clickjacking_probes("http://example.com/static/image.png")
    assert len(non_sensitive_probes) == 0


def test_payload_generator_framework_gadget_probes():
    gen = PrototypePollutionPayloadGenerator()
    probes = gen.generate_gadget_chain_probes("http://example.com/api")
    assert len(probes) >= 5
    frameworks = [p.framework_target for p in probes if p.framework_target]
    assert GadgetFramework.EXPRESS in frameworks
    assert GadgetFramework.LODASH in frameworks
    assert GadgetFramework.HANDLEBARS in frameworks
    assert GadgetFramework.JQUERY in frameworks
    assert GadgetFramework.NODEJS_CHILD_PROCESS in frameworks


def test_payload_generator_benign_baseline_probes():
    gen = PrototypePollutionPayloadGenerator()
    probes = gen.generate_benign_baseline_probes("http://example.com/api")
    assert len(probes) == 2
    assert all(p.is_benign_baseline for p in probes)


def test_payload_generator_all_probes_aggregation():
    gen = PrototypePollutionPayloadGenerator()
    all_probes = gen.generate_all_probes("http://example.com/login")
    assert len(all_probes) >= 20


# =============================================================================
# Unit Tests: Prober
# =============================================================================

def test_prober_http_dispatch_and_history():
    mock_client = MockPrototypePollutionHttpClient()
    mock_client.set_route("http://example.com/api", 200, '{"result": "argus_polluted_canary_123"}', {"Content-Type": "application/json"})
    
    mission = Mission(target="http://example.com")
    mission.http_client = mock_client
    
    prober = PrototypePollutionProber()
    probe = PrototypePollutionProbe(
        probe_id="p1",
        target_url="http://example.com/api",
        method="POST",
        json_data={"__proto__": {"canary": "123"}},
        canary_property="argus_polluted_canary_123",
    )
    
    resp = prober.execute_probe(mission, "http://example.com/api", probe)
    assert resp.success
    assert resp.status_code == 200
    assert resp.side_effect_observed
    assert "argus_polluted_canary_123" in resp.polluted_properties


def test_prober_redirect_chain_tracing():
    mock_client = MockPrototypePollutionHttpClient()
    mock_client.set_route("http://example.com/step1", 302, "", {"Location": "http://example.com/step2"})
    mock_client.set_route("http://example.com/step2", 302, "", {"Location": "https://evil.com/landing"})
    mock_client.set_route("https://evil.com/landing", 200, "evil landing page", {})

    mission = Mission(target="http://example.com")
    mission.http_client = mock_client

    prober = PrototypePollutionProber()
    probe = PrototypePollutionProbe(
        probe_id="p_redir",
        target_url="http://example.com/step1",
        method="GET",
        vulnerability_type=PrototypePollutionVulnerabilityType.OPEN_REDIRECT,
    )

    resp = prober.execute_redirect_chain_probe(mission, "http://example.com/step1", probe, max_hops=5)
    assert len(resp.redirect_history) == 3
    assert resp.redirect_history[0] == "http://example.com/step1"
    assert resp.redirect_history[1] == "http://example.com/step2"
    assert resp.redirect_history[2] == "https://evil.com/landing"


def test_prober_error_and_timeout_resilience():
    mock_client = MockPrototypePollutionHttpClient()
    mission = Mission(target="http://example.com")
    mission.http_client = mock_client

    # Force error route
    mock_client.set_route("http://example.com/error", 500, "Internal Server Error", {})
    prober = PrototypePollutionProber()
    probe = PrototypePollutionProbe(
        probe_id="p_err",
        target_url="http://example.com/error",
        method="GET",
    )

    resp = prober.execute_probe(mission, "http://example.com/error", probe)
    assert resp.status_code == 500


# =============================================================================
# Unit Tests: Analyzer
# =============================================================================

def test_analyzer_server_side_pp_detection():
    analyzer = PrototypePollutionAnalyzer()
    probe = PrototypePollutionProbe(
        probe_id="p1",
        target_url="http://example.com/api/settings",
        method="POST",
        vulnerability_type=PrototypePollutionVulnerabilityType.SERVER_SIDE_PROTOTYPE_POLLUTION,
        canary_property="argus_polluted_prop",
        canary_value="argus_polluted_val",
        tested_parameter="__proto__",
    )
    resp = PrototypePollutionProbeResponse(
        probe=probe,
        status_code=200,
        body='{"status": "ok", "argus_polluted_prop": "argus_polluted_val"}',
        headers={"Content-Type": "application/json"},
    )

    result = analyzer.evaluate_probe(probe, resp, "http://example.com/api/settings")
    assert result is not None
    assert result.is_valid_finding
    assert result.vulnerability_type == PrototypePollutionVulnerabilityType.SERVER_SIDE_PROTOTYPE_POLLUTION
    assert result.severity == "high"
    assert result.cwe_id == "CWE-1321"
    assert result.cvss_score == 8.2


def test_analyzer_client_side_pp_detection():
    analyzer = PrototypePollutionAnalyzer()
    probe = PrototypePollutionProbe(
        probe_id="p_dom",
        target_url="http://example.com/search?__proto__[polluted]=true",
        method="GET",
        vulnerability_type=PrototypePollutionVulnerabilityType.CLIENT_SIDE_PROTOTYPE_POLLUTION,
        canary_property="polluted",
        tested_parameter="__proto__[polluted]",
    )
    resp = PrototypePollutionProbeResponse(
        probe=probe,
        status_code=200,
        body='<script>var config = {}; Object.assign(config, getParams()); if (config.polluted) { alert(1); }</script>',
    )

    result = analyzer.evaluate_probe(probe, resp, "http://example.com/search")
    assert result is not None
    assert result.is_valid_finding
    assert result.vulnerability_type == PrototypePollutionVulnerabilityType.CLIENT_SIDE_PROTOTYPE_POLLUTION
    assert result.severity == "high"
    assert result.cwe_id == "CWE-1321"
    assert result.cvss_score == 8.1


def test_analyzer_dom_clobbering_detection_logic_vs_xss():
    analyzer = PrototypePollutionAnalyzer()

    # 1. Logic corruption (Medium severity 6.1)
    cookie_probe = PrototypePollutionProbe(
        probe_id="p_cookie",
        target_url="http://example.com/profile",
        vulnerability_type=PrototypePollutionVulnerabilityType.DOM_CLOBBERING,
        canary_value='<form id="cookie" name="cookie"><input id="value" value="clobbered"></form>',
        metadata={"clobbered_target": "document.cookie", "impact": "logic_corruption"},
    )
    cookie_resp = PrototypePollutionProbeResponse(
        probe=cookie_probe,
        status_code=200,
        body='<div><form id="cookie" name="cookie"><input id="value" value="clobbered"></form></div>',
    )
    res_logic = analyzer.evaluate_probe(cookie_probe, cookie_resp, "http://example.com/profile")
    assert res_logic is not None
    assert res_logic.severity == "medium"
    assert res_logic.cvss_score == 6.1
    assert res_logic.cwe_id == "CWE-79"

    # 2. XSS Clobbering (High severity 8.1)
    xss_probe = PrototypePollutionProbe(
        probe_id="p_xss",
        target_url="http://example.com/profile",
        vulnerability_type=PrototypePollutionVulnerabilityType.DOM_CLOBBERING,
        canary_value='<a id="avatar" href="javascript:alert(1)">Click</a>',
        metadata={"clobbered_target": "a.href", "impact": "xss"},
    )
    xss_resp = PrototypePollutionProbeResponse(
        probe=xss_probe,
        status_code=200,
        body='<div><a id="avatar" href="javascript:alert(1)">Click</a></div>',
    )
    res_xss = analyzer.evaluate_probe(xss_probe, xss_resp, "http://example.com/profile")
    assert res_xss is not None
    assert res_xss.severity == "high"
    assert res_xss.cvss_score == 8.1
    assert res_xss.cwe_id == "CWE-79"


def test_analyzer_open_redirect_detection():
    analyzer = PrototypePollutionAnalyzer()
    probe = PrototypePollutionProbe(
        probe_id="p_redir",
        target_url="http://example.com/login?next=https://evil.com/landing",
        method="GET",
        vulnerability_type=PrototypePollutionVulnerabilityType.OPEN_REDIRECT,
        tested_parameter="next",
    )
    resp = PrototypePollutionProbeResponse(
        probe=probe,
        status_code=302,
        headers={"Location": "https://evil.com/landing"},
        redirect_history=["http://example.com/login?next=https://evil.com/landing", "https://evil.com/landing"],
    )

    result = analyzer.evaluate_probe(probe, resp, "http://example.com/login")
    assert result is not None
    assert result.is_valid_finding
    assert result.vulnerability_type == PrototypePollutionVulnerabilityType.OPEN_REDIRECT
    assert result.severity == "medium"
    assert result.cwe_id == "CWE-601"
    assert result.cvss_score == 6.1


def test_analyzer_clickjacking_detection():
    analyzer = PrototypePollutionAnalyzer()
    probe = PrototypePollutionProbe(
        probe_id="p_clickjack",
        target_url="http://example.com/login",
        method="GET",
        vulnerability_type=PrototypePollutionVulnerabilityType.CLICKJACKING,
        tested_parameter="X-Frame-Options",
    )
    # Missing X-Frame-Options and CSP
    resp = PrototypePollutionProbeResponse(
        probe=probe,
        status_code=200,
        headers={"Content-Type": "text/html; charset=utf-8"},
        body="<html><body><h1>Login</h1></body></html>",
    )

    result = analyzer.evaluate_probe(probe, resp, "http://example.com/login")
    assert result is not None
    assert result.is_valid_finding
    assert result.vulnerability_type == PrototypePollutionVulnerabilityType.CLICKJACKING
    assert result.severity == "medium"
    assert result.cwe_id == "CWE-1021"
    assert result.cvss_score == 5.3


def test_analyzer_framework_gadget_express_and_lodash():
    analyzer = PrototypePollutionAnalyzer()

    # Express gadget
    exp_probe = PrototypePollutionProbe(
        probe_id="p_exp",
        target_url="http://example.com/api",
        vulnerability_type=PrototypePollutionVulnerabilityType.GADGET_POLLUTION,
        framework_target=GadgetFramework.EXPRESS,
        canary_property="settings.view options",
        tested_parameter="express_view_options",
    )
    exp_resp = PrototypePollutionProbeResponse(
        probe=exp_probe,
        status_code=200,
        body='{"status": "views configured", "settings.view options": true}',
    )
    res_exp = analyzer.evaluate_probe(exp_probe, exp_resp, "http://example.com/api")
    assert res_exp is not None
    assert res_exp.severity == "high"
    assert res_exp.gadget_framework == "express"

    # Lodash gadget
    lod_probe = PrototypePollutionProbe(
        probe_id="p_lod",
        target_url="http://example.com/api",
        vulnerability_type=PrototypePollutionVulnerabilityType.GADGET_POLLUTION,
        framework_target=GadgetFramework.LODASH,
        canary_property="templateSettings.interpolate",
        tested_parameter="lodash_templateSettings",
    )
    lod_resp = PrototypePollutionProbeResponse(
        probe=lod_probe,
        status_code=200,
        body='{"status": "ok", "templateSettings.interpolate": true}',
    )
    res_lod = analyzer.evaluate_probe(lod_probe, lod_resp, "http://example.com/api")
    assert res_lod is not None
    assert res_lod.severity == "high"
    assert res_lod.gadget_framework == "lodash"


def test_analyzer_rce_gadget_node_child_process():
    analyzer = PrototypePollutionAnalyzer()
    probe = PrototypePollutionProbe(
        probe_id="p_rce",
        target_url="http://example.com/api",
        vulnerability_type=PrototypePollutionVulnerabilityType.RCE_GADGET,
        framework_target=GadgetFramework.NODEJS_CHILD_PROCESS,
        canary_property="NODE_OPTIONS",
        tested_parameter="child_process.exec",
    )
    resp = PrototypePollutionProbeResponse(
        probe=probe,
        status_code=200,
        body='{"status": "NODE_OPTIONS accepted"}',
    )

    result = analyzer.evaluate_probe(probe, resp, "http://example.com/api")
    assert result is not None
    assert result.severity == "critical"
    assert result.cvss_score == 9.8
    assert result.cwe_id == "CWE-1321"


def test_analyzer_dos_pollution_tostring():
    analyzer = PrototypePollutionAnalyzer()
    probe = PrototypePollutionProbe(
        probe_id="p_dos",
        target_url="http://example.com/api",
        vulnerability_type=PrototypePollutionVulnerabilityType.DOS_POLLUTION,
        canary_property="toString",
        tested_parameter="Object.prototype.toString",
    )
    # Status code shifted to 500 with TypeError
    resp = PrototypePollutionProbeResponse(
        probe=probe,
        status_code=500,
        body='{"error": "TypeError: Cannot convert object to primitive value"}',
    )

    result = analyzer.evaluate_probe(probe, resp, "http://example.com/api")
    assert result is not None
    assert result.is_valid_finding
    assert result.vulnerability_type == PrototypePollutionVulnerabilityType.DOS_POLLUTION
    assert result.severity == "high"


# =============================================================================
# Unit Tests: False Positive Rejection
# =============================================================================

def test_analyzer_fp_rejection_proto_sanitization():
    analyzer = PrototypePollutionAnalyzer()
    probe = PrototypePollutionProbe(
        probe_id="p_fp",
        target_url="http://example.com/api/user",
        vulnerability_type=PrototypePollutionVulnerabilityType.SERVER_SIDE_PROTOTYPE_POLLUTION,
        canary_property="argus_polluted_canary",
        canary_value="val123",
    )
    # Server cleanly stripped __proto__ and returns standard response without canary
    resp = PrototypePollutionProbeResponse(
        probe=probe,
        status_code=200,
        body='{"status": "user updated successfully", "user": {"id": 1, "name": "alice"}}',
    )

    result = analyzer.evaluate_probe(probe, resp, "http://example.com/api/user")
    assert result is None


def test_analyzer_fp_rejection_same_origin_redirects():
    analyzer = PrototypePollutionAnalyzer()
    probe = PrototypePollutionProbe(
        probe_id="p_redir_fp",
        target_url="http://example.com/login?next=/dashboard",
        vulnerability_type=PrototypePollutionVulnerabilityType.OPEN_REDIRECT,
        tested_parameter="next",
    )
    # Redirects internally to /dashboard
    resp = PrototypePollutionProbeResponse(
        probe=probe,
        status_code=302,
        headers={"Location": "/dashboard"},
        redirect_history=["http://example.com/login?next=/dashboard", "http://example.com/dashboard"],
    )

    result = analyzer.evaluate_probe(probe, resp, "http://example.com/login")
    assert result is None


def test_analyzer_fp_rejection_proper_frame_busting():
    analyzer = PrototypePollutionAnalyzer()
    probe = PrototypePollutionProbe(
        probe_id="p_click_fp",
        target_url="http://example.com/login",
        vulnerability_type=PrototypePollutionVulnerabilityType.CLICKJACKING,
    )

    # 1. Protected via X-Frame-Options: DENY
    resp_xfo = PrototypePollutionProbeResponse(
        probe=probe,
        status_code=200,
        headers={"X-Frame-Options": "DENY"},
        body="<html><body>Protected Login</body></html>",
    )
    assert analyzer.evaluate_probe(probe, resp_xfo, "http://example.com/login") is None

    # 2. Protected via CSP frame-ancestors 'self'
    resp_csp = PrototypePollutionProbeResponse(
        probe=probe,
        status_code=200,
        headers={"Content-Security-Policy": "default-src 'self'; frame-ancestors 'self'"},
        body="<html><body>Protected Login</body></html>",
    )
    assert analyzer.evaluate_probe(probe, resp_csp, "http://example.com/login") is None


def test_analyzer_fp_rejection_standard_error_codes():
    analyzer = PrototypePollutionAnalyzer()
    probe = PrototypePollutionProbe(
        probe_id="p_400",
        target_url="http://example.com/api",
        vulnerability_type=PrototypePollutionVulnerabilityType.SERVER_SIDE_PROTOTYPE_POLLUTION,
        canary_property="canary_prop",
    )
    # Standard 400 Bad Request rejection message
    resp_400 = PrototypePollutionProbeResponse(
        probe=probe,
        status_code=400,
        body='{"error": "Invalid JSON: property __proto__ is forbidden"}',
    )
    assert analyzer.evaluate_probe(probe, resp_400, "http://example.com/api") is None


def test_analyzer_fp_rejection_benign_baseline():
    analyzer = PrototypePollutionAnalyzer()
    baseline_probe = PrototypePollutionProbe(
        probe_id="p_base",
        target_url="http://example.com/api",
        is_benign_baseline=True,
    )
    resp = PrototypePollutionProbeResponse(
        probe=baseline_probe,
        status_code=200,
        body='{"status": "ok"}',
    )
    assert analyzer.evaluate_probe(baseline_probe, resp, "http://example.com/api") is None


# =============================================================================
# Unit Tests: Collector Lifecycle & Quadruple State Publishing
# =============================================================================

def test_collector_endpoint_discovery_hierarchy():
    collector = PrototypePollutionCollector()

    # 1. From mission.inputs
    m1 = Mission(target="http://example.com")
    m1.inputs = {"endpoints": ["http://example.com/api/v1", "http://example.com/login"]}
    assert collector._discover_candidate_endpoints(m1) == ["http://example.com/api/v1", "http://example.com/login"]

    # 2. From mission.endpoints
    m2 = Mission(target="http://example.com")
    m2.endpoints = [{"url": "http://example.com/api/v2"}]
    assert collector._discover_candidate_endpoints(m2) == ["http://example.com/api/v2"]

    # 3. From live_hosts
    m3 = Mission(target="http://example.com")
    m3.live_hosts = ["http://example.com:8080"]
    assert collector._discover_candidate_endpoints(m3) == ["http://example.com:8080"]

    # 4. Fallback to target
    m4 = Mission(target="http://example.com")
    assert collector._discover_candidate_endpoints(m4) == ["http://example.com"]


def test_collector_quadruple_state_publishing():
    mock_client = MockPrototypePollutionHttpClient()
    # Configure mock client to respond vulnerable to JSON __proto__ injection
    mock_client.set_route(
        "http://example.com/api/settings",
        200,
        '{"status": "updated", "argus_polluted_canary": "polluted_value"}',
        {"Content-Type": "application/json"},
    )

    mission = Mission(target="http://example.com")
    mission.http_client = mock_client
    mission.endpoints = ["http://example.com/api/settings"]
    mission.evidence = EvidenceStore()
    mission.vulnerabilities = []
    mission.attack_surface_graph = KnowledgeGraph()

    published_findings = []
    mission.publish_finding = lambda fid, ev: published_findings.append((fid, ev))

    collector = PrototypePollutionCollector()
    collector.generator.generate_all_probes = lambda url: [
        PrototypePollutionProbe(
            probe_id="p_test_emit",
            target_url="http://example.com/api/settings",
            method="POST",
            vulnerability_type=PrototypePollutionVulnerabilityType.SERVER_SIDE_PROTOTYPE_POLLUTION,
            canary_property="argus_polluted_canary",
            canary_value="polluted_value",
            tested_parameter="__proto__",
        )
    ]

    ev_list = collector.collect(mission)
    assert len(ev_list) == 1
    ev = ev_list[0]

    # 1. Verify raw_mission.evidence
    all_ev = mission.evidence.all()
    assert len(all_ev) == 1
    assert all_ev[0].category == "prototype_pollution"

    # 2. Verify raw_mission.vulnerabilities
    assert len(mission.vulnerabilities) == 1
    assert mission.vulnerabilities[0]["cwe_id"] == "CWE-1321"

    # 3. Verify attack_surface_graph (HAS_ENDPOINT, HAS_VULNERABILITY)
    g = mission.attack_surface_graph
    assert "live_host:http://example.com" in g.nodes
    assert "endpoint:http://example.com/api/settings" in g.nodes
    assert len(g.edges) >= 3
    has_lh_ep = any(e.source == "live_host:http://example.com" and e.target == "endpoint:http://example.com/api/settings" for e in g.edges)
    has_ep_vuln = any(e.source == "endpoint:http://example.com/api/settings" and e.type == "HAS_VULNERABILITY" for e in g.edges)
    assert has_lh_ep
    assert has_ep_vuln

    # 4. Verify ControlledMission.publish_finding
    assert len(published_findings) == 1


def test_collector_backward_compatibility_aliases():
    assert ClientSideAttackCollector == PrototypePollutionCollector
    assert DOMClobberingCollector == PrototypePollutionCollector
    assert OpenRedirectCollector == PrototypePollutionCollector
    assert ClickjackingCollector == PrototypePollutionCollector
    assert ProtoPollutionCollector == PrototypePollutionCollector
    assert ClientSideAttackResult == PrototypePollutionResult


def test_collector_empty_mission_resilience():
    collector = PrototypePollutionCollector()
    m_empty = Mission(target="")
    evs = collector.collect(m_empty)
    assert evs == []
