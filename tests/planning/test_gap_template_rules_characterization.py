"""
Characterization test for TaskGenerator._resolve_template_for_gap.

This is a CHARACTERIZATION test (V-02): the expected answers were captured
from the implementation itself before its extraction into
argus.planning.gapTemplateRules, not derived from an external spec. It is
evidence the extraction preserved behavior -- it is not evidence that any
individual area/keyword -> template mapping is "correct" business logic.

The 360-case input matrix (every area alias literal the method recognizes,
plus one representative input per conditional/keyword-ladder branch) achieves
100% line and branch coverage of the original 408-line method, measured with
`coverage run --branch` before the extraction. If a change to behavior is
intentional, regenerate deliberately with:

    ARGUS_UPDATE_SNAPSHOTS=1 python -m pytest tests/planning/test_gap_template_rules_characterization.py -q

and review the resulting diff as part of that change.
"""
from __future__ import annotations

import json
import os
import pathlib

from argus.planning.models import CoverageGap, TaskCategory
from argus.planning.task_generator import TaskGenerator
from argus.planning.templates import _RECON_TEMPLATES, _SPECIALIST_TEMPLATES
from argus.runtime.mission import Mission

SNAP_PATH = pathlib.Path(__file__).parent / "snapshots" / "gap_template_rules.json"
_UPDATE = os.environ.get("ARGUS_UPDATE_SNAPSHOTS") == "1"

NEUTRAL_DESC = "coverage gap needs more automated validation of the target."
UNMATCHED_AREA = "totally unspecified coverage area xyz"

# Every area-alias string literal the method recognizes, extracted via AST
# from the pre-extraction source. Kept as an independent, frozen list (not
# derived from argus.planning.gapTemplateRules) so a future accidental drop
# or edit of an alias in that module is caught here.
ALL_AREAS = ['2fa bypass', 'access control', 'access_control', 'account lockout', 'api', 'api endpoints', 'api security', 'api security testing', 'api vulnerabilities', 'api_security', 'arbitrary file read', 'arbitrary file upload', 'auth bypass', 'auth_bypass', 'authentication', 'authentication bypass', 'authentication workflows', 'authentication_bypass', 'authorization', 'authorization boundaries', 'authorization graph', 'binary formatter', 'binary_formatter', 'bola', 'broken access control', 'broken object level authorization', 'broken_object_level_authorization', 'brute force', 'brute_force', 'business logic', 'business logic flaws', 'business logic workflows', 'cache deception', 'cache fingerprinting', 'cache key normalization', 'cache poisoning', 'cache security', 'cl.te', 'cl_te', 'clickjacking', 'client side attacks', 'client-side attacks', 'client-side prototype pollution', 'client_side_attacks', 'client_side_prototype_pollution', 'cloud metadata', 'cmd_injection', 'cmdi', 'command injection', 'command_injection', 'concurrency', 'concurrency vulnerabilities', 'content security policy', 'cors', 'cors misconfiguration', 'cors security', 'cors_security', 'coupon stacking', 'credential attack', 'credential attacks', 'credential stuffing', 'credential_attack', 'cross site scripting', 'cross-site scripting', 'cross-site websocket hijacking', 'csp', 'cswsh', 'database injection', 'default credentials', 'default_credentials', 'deserialization', 'desync', 'directory traversal', 'dom clobbering', 'dom xss', 'dom_clobbering', 'double extension bypass', 'ejs', 'endpoint crawling', 'endpoint discovery', 'endpoints', 'erb', 'evidence correlation', 'excessive data exposure', 'excessive_data_exposure', 'exposed files', 'fat get', 'file upload', 'file upload security', 'file upload vulnerabilities', 'file_upload', 'frame busting', 'frame_busting', 'freemarker', 'gadget chain', 'graphql', 'graphql batching', 'graphql dos', 'graphql injection', 'graphql introspection', 'graphql query depth', 'graphql schema', 'graphql security', 'graphql validation', 'graphql vulnerability', 'grpc', 'grpc security', 'h2 smuggling', 'h2.cl', 'h2.te', 'hsts', 'html clobbering', 'http desync', 'http request smuggling', 'http security headers', 'http2 smuggling', 'idor', 'info disclosure', 'information disclosure', 'insecure deserialization', 'java deserialization', 'javascript', 'javascript analysis', 'jinja', 'jinja2', 'jwt', 'jwt manipulation', 'jwt_manipulation', 'lfi', 'limit overrun', 'limit_overrun', 'live host discovery', 'live hosts', 'live_hosts', 'local file inclusion', 'mako', 'mass assignment', 'mass_assignment', 'metadata injection', 'method tampering', 'method_tampering', 'mfa bypass', 'mfa_bypass', 'mime type bypass', 'multi-redemption', 'oauth', 'oauth authentication', 'oauth2', 'oauth_oidc', 'object injection', 'objectinputstream', 'oidc', 'oidc token', 'open redirect', 'open redirect chain', 'open_redirect', 'open_redirect_chain', 'openid', 'os command injection', 'os injection', 'parameter tampering', 'parameter_tampering', 'password reset', 'password_reset', 'path confusion', 'path traversal', 'path_traversal', 'php unserialize', 'pickle', 'polyglot upload', 'price tampering', 'privilege escalation', 'proto pollution', 'proto_pollution', 'prototype pollution', 'prototype pollution gadgets', 'prototype_pollution', 'pug', 'python pickle', 'quantity tampering', 'race condition', 'race conditions', 'race window', 'race_condition', 'race_conditions', 'rate limit', 'rate limiting', 'rate limiting bypass', 'rate_limit', 'rate_limit_bypass', 'rate_limiting', 'rce', 'redirect chain', 'reflected xss', 'remote code execution', 'request smuggling', 'request_smuggling', 'rest api', 'rest api security', 'ruby marshal', 'secrets', 'security headers', 'sensitive files', 'server side request forgery', 'server side template injection', 'server-side prototype pollution', 'server-side request forgery', 'server-side template injection', 'server_side_prototype_pollution', 'session fixation', 'session management', 'session token analysis', 'session_fixation', 'shell injection', 'single packet attack', 'single-packet attack', 'smarty', 'smuggling', 'socket.io', 'spel', 'spring expression language', 'sql', 'sql injection', 'sql vulnerabilities', 'sql_injection', 'sqli', 'sqli detection', 'ssrf', 'ssrf detection', 'ssrf validation', 'ssti', 'ssti detection', 'state machine', 'stored xss', 'strict transport security', 'subdomain discovery', 'subdomains', 'te.cl', 'te.te', 'te_cl', 'te_te', 'technologies', 'template injection', 'template injection detection', 'thymeleaf', 'time-of-check to time-of-use', 'toctou', 'token', 'token validation', 'traversal', 'twig', 'ui redressing', 'ui_redressing', 'unkeyed headers', 'unkeyed parameters', 'unkeyed query parameters', 'unrestricted file upload', 'unrestricted upload', 'unsafe deserialization', 'unserialize', 'upload security', 'velocity', 'viewstate', 'vulnerabilities', 'vulnerability scan', 'vulnerability scanning', 'wcd', 'web cache deception', 'web cache poisoning', 'web shell detection', 'websocket', 'websocket authentication', 'websocket dos', 'websocket injection', 'websocket security', 'workflow bypass', 'ws', 'wss', 'x-frame-options', 'xml', 'xml external entity', 'xml injection', 'xml parser', 'xml parser validation', 'xml_external_entity', 'xml_parser', 'xss', 'xss detection', 'xxe']

# (branch_name, keywords, recon_key) for the EVIDENCE_CORRELATION category
# fallback ladder, in source order (order is load-bearing: see
# argus.planning.gapTemplateRules.categoryFallback docstring).
EVIDENCE_LADDER = [
    ("auth_oauth", ["oauth", "oidc", "jwt", "token"], "oauth"),
    ("auth_bypass_kw", ["auth bypass", "authentication bypass", "credential attack", "brute force", "mfa bypass", "session fixation", "jwt manipulation", "default credential", "password reset"], "auth_bypass"),
    ("proto_pollution_kw", ["prototype pollution", "prototype", "proto pollution", "proto", "dom clobbering", "clobbering", "open redirect", "redirect chain", "clickjacking", "ui redressing", "frame busting", "gadget chain", "client-side attacks", "client side"], "prototype_pollution"),
    ("api_security_kw", ["api security", "rest api", "grpc", "parameter tamper", "mass assignment", "rate limit", "rate limiting", "bola", "idor", "excessive data", "method tamper"], "api_security"),
    ("file_upload_kw", ["file upload", "upload security", "unrestricted upload", "arbitrary upload", "mime type bypass", "double extension", "polyglot", "web shell", "file upload vulnerability"], "file_upload"),
    ("race_kw", ["race", "concurrency", "toctou", "limit overrun", "multi-redemption", "overdraft", "single-packet", "single packet"], "race_conditions"),
    ("business_logic_kw", ["business logic", "state machine", "price tamper", "quantity tamper", "step skip", "workflow skip", "workflow bypass", "mass assignment", "coupon stack", "idempotency abuse", "parameter tamper"], "business_logic"),
    ("ssti_kw", ["ssti", "template injection", "server-side template", "jinja", "twig", "freemarker", "velocity", "mako", "spel", "thymeleaf", "erb", "smarty"], "ssti"),
    ("cache_kw", ["cache security", "cache poison", "cache deception", "web cache", "unkeyed header", "unkeyed param", "fat get", "cache key", "parameter cloaking", "wcd"], "cache_security"),
    ("cors_kw", ["cors", "cross-origin", "origin reflection", "null origin", "security header", "csp", "content-security-policy", "hsts", "strict-transport-security", "x-frame-options", "clickjacking", "nosniff", "referrer-policy", "permissions-policy"], "cors_security"),
    ("smuggling_kw", ["smuggl", "cl.te", "te.cl", "te.te", "cl_te", "te_cl", "te_te", "h2.cl", "h2.te", "h2_cl", "h2_te", "desync", "request smuggling"], "request_smuggling"),
    ("websocket_kw", ["websocket", "cswsh", "socket.io", "ws://", "wss://", "upgrade"], "websocket_security"),
    ("deser_kw", ["deserializ", "pickle", "unserialize", "marshal", "viewstate", "objectinputstream", "object injection"], "deserialization"),
    ("graphql_kw", ["graphql", "introspection"], "graphql_security"),
    ("xml_kw", ["xml", "xxe", "entity", "external entity"], "xml_parser_validation"),
    ("cmdi_kw", ["command", "cmdi", "rce", "os injection", "shell"], "command_injection"),
    ("ssrf_kw", ["ssrf", "request forgery", "metadata", "server-side"], "ssrf"),
    ("xss_kw", ["xss", "cross-site", "scripting"], "xss"),
    ("sqli_kw", ["sql", "sqli", "database injection"], "sql_injection"),
    ("traversal_kw", ["traversal", "lfi", "file read", "path"], "path_traversal"),
    ("info_disc_kw", ["information disclosure", "sensitive file", "secret"], "info_disclosure"),
    ("nuclei_kw", ["scan", "vulnerabilit"], "nuclei"),
]


def _pickRepresentative(branchIdx: int) -> str:
    """First keyword of this branch with no substring collision against any
    earlier branch's keywords, so a description built from it exercises
    exactly this branch (order in EVIDENCE_LADDER is load-bearing)."""
    _, keywords, _ = EVIDENCE_LADDER[branchIdx]
    earlier = [kw for i in range(branchIdx) for kw in EVIDENCE_LADDER[i][1]]
    for kw in keywords:
        if not any(kw in e or e in kw for e in earlier):
            return kw
    raise AssertionError(f"no clean representative keyword for branch {branchIdx}")


def _idLabel(reconById: dict, specialistById: dict, obj: dict) -> str:
    key = id(obj)
    if key in reconById:
        return f"RECON:{reconById[key]}"
    if key in specialistById:
        return f"SPECIALIST:{specialistById[key].name}"
    raise AssertionError(f"resolved template is neither a known recon nor specialist template: {obj!r}")


def _makeGap(area: str, desc: str, category: TaskCategory) -> CoverageGap:
    return CoverageGap(area=area, description=desc, category=category, severity=0.8)


def _makeMission(**kwargs) -> Mission:
    mission = Mission(target="example.com")
    for key, value in kwargs.items():
        setattr(mission, key, value)
    return mission


def _runAllAreaAliases(results, label):
    tg = TaskGenerator(_makeMission())
    for area in ALL_AREAS:
        gap = _makeGap(area, NEUTRAL_DESC, TaskCategory.EVIDENCE_CORRELATION)
        results[f"area::{area}"] = label(tg._resolve_template_for_gap(gap))


def _runMissionStateGroups(results, label):
    for missionLabel, kwargs in [("empty", {}), ("has_subdomains", {"subdomains": ["a.example.com"]})]:
        tg = TaskGenerator(_makeMission(**kwargs))
        gap = _makeGap("technologies", NEUTRAL_DESC, TaskCategory.EVIDENCE_CORRELATION)
        results[f"technologies::{missionLabel}"] = label(tg._resolve_template_for_gap(gap))

    combos = [
        ("no_endpoints_no_crawl", {}, NEUTRAL_DESC),
        ("endpoints_crawl", {"endpoints": [{"url": "https://example.com/a"}]}, "please crawl further"),
        ("endpoints_no_crawl", {"endpoints": [{"url": "https://example.com/a"}]}, NEUTRAL_DESC),
    ]
    for area in ("api endpoints", "api"):
        for comboLabel, missionKwargs, desc in combos:
            tg = TaskGenerator(_makeMission(**missionKwargs))
            gap = _makeGap(area, desc, TaskCategory.EVIDENCE_CORRELATION)
            results[f"area_{area}::{comboLabel}"] = label(tg._resolve_template_for_gap(gap))


def _runDescriptionDrivenAreaGroups(results, label):
    tg = TaskGenerator(_makeMission())
    authCases = [("oauth_branch", "oauth token needed"), ("websocket_branch", "websocket handshake"), ("else_branch", NEUTRAL_DESC)]
    for area in ("authentication workflows", "authentication", "authorization", "authorization graph"):
        for caseLabel, desc in authCases:
            gap = _makeGap(area, desc, TaskCategory.EVIDENCE_CORRELATION)
            results[f"area_{area}::{caseLabel}"] = label(tg._resolve_template_for_gap(gap))

    blCases = [("race_branch", "race condition risk"), ("tamper_branch", "price tampering seen"), ("else_branch", NEUTRAL_DESC)]
    for area in ("business logic", "business logic workflows", "business logic flaws"):
        for caseLabel, desc in blCases:
            gap = _makeGap(area, desc, TaskCategory.EVIDENCE_CORRELATION)
            results[f"area_{area}::{caseLabel}"] = label(tg._resolve_template_for_gap(gap))


def _runCategoryFallbacksWithState(results, label):
    for missionLabel, kwargs in [("empty", {}), ("has_live_hosts", {"live_hosts": ["https://example.com"]})]:
        tg = TaskGenerator(_makeMission(**kwargs))
        gap = _makeGap(UNMATCHED_AREA, NEUTRAL_DESC, TaskCategory.TECHNOLOGY_DISCOVERY)
        results[f"cat_TECHNOLOGY_DISCOVERY::{missionLabel}"] = label(tg._resolve_template_for_gap(gap))

    combos = [
        ("no_endpoints", {}, NEUTRAL_DESC),
        ("endpoints_crawl", {"endpoints": [{"url": "https://example.com/a"}]}, "please crawl further"),
        ("endpoints_no_crawl", {"endpoints": [{"url": "https://example.com/a"}]}, NEUTRAL_DESC),
    ]
    for comboLabel, missionKwargs, desc in combos:
        tg = TaskGenerator(_makeMission(**missionKwargs))
        gap = _makeGap(UNMATCHED_AREA, desc, TaskCategory.API_DISCOVERY)
        results[f"cat_API_DISCOVERY::{comboLabel}"] = label(tg._resolve_template_for_gap(gap))


def _runCategoryFallbacksKeywordDriven(results, label):
    tg = TaskGenerator(_makeMission())

    authnCases = [("oauth_branch", "oauth flow"), ("auth_bypass_branch", "credential stuffing seen"),
                  ("websocket_branch", "websocket handshake"), ("else_branch", NEUTRAL_DESC)]
    for caseLabel, desc in authnCases:
        gap = _makeGap(UNMATCHED_AREA, desc, TaskCategory.AUTHENTICATION_ANALYSIS)
        results[f"cat_AUTHENTICATION_ANALYSIS::{caseLabel}"] = label(tg._resolve_template_for_gap(gap))

    authzCases = [("oauth_branch", "oauth flow"), ("access_control_branch", "idor risk"),
                  ("websocket_branch", "websocket handshake"), ("else_branch", NEUTRAL_DESC)]
    for caseLabel, desc in authzCases:
        gap = _makeGap(UNMATCHED_AREA, desc, TaskCategory.AUTHORIZATION_ANALYSIS)
        results[f"cat_AUTHORIZATION_ANALYSIS::{caseLabel}"] = label(tg._resolve_template_for_gap(gap))

    for idx, (name, _, _) in enumerate(EVIDENCE_LADDER):
        desc = f"gap covering {_pickRepresentative(idx)} here"
        gap = _makeGap(UNMATCHED_AREA, desc, TaskCategory.EVIDENCE_CORRELATION)
        results[f"cat_EVIDENCE_CORRELATION::{name}"] = label(tg._resolve_template_for_gap(gap))
    gap = _makeGap(UNMATCHED_AREA, NEUTRAL_DESC, TaskCategory.EVIDENCE_CORRELATION)
    results["cat_EVIDENCE_CORRELATION::else_branch"] = label(tg._resolve_template_for_gap(gap))


def _runDefaultCategoryFallback(results, label):
    tg = TaskGenerator(_makeMission())
    handled = {
        TaskCategory.TECHNOLOGY_DISCOVERY, TaskCategory.API_DISCOVERY,
        TaskCategory.AUTHENTICATION_ANALYSIS, TaskCategory.AUTHORIZATION_ANALYSIS,
        TaskCategory.EVIDENCE_CORRELATION,
    }
    for category in TaskCategory:
        if category in handled:
            continue
        gap = _makeGap(UNMATCHED_AREA, NEUTRAL_DESC, category)
        results[f"cat_default::{category.name}"] = label(tg._resolve_template_for_gap(gap))


def _buildAllResults() -> dict:
    reconById = {id(v): k for k, v in _RECON_TEMPLATES.items()}
    specialistById = {id(v): k for k, v in _SPECIALIST_TEMPLATES.items()}
    label = lambda obj: _idLabel(reconById, specialistById, obj)

    results: dict = {}
    _runAllAreaAliases(results, label)
    _runMissionStateGroups(results, label)
    _runDescriptionDrivenAreaGroups(results, label)
    _runCategoryFallbacksWithState(results, label)
    _runCategoryFallbacksKeywordDriven(results, label)
    _runDefaultCategoryFallback(results, label)
    return results


def test_characterization_resolve_template_for_gap():
    """360-case input/output equivalence oracle for _resolve_template_for_gap.

    Characterization test (V-02): pins current behavior captured before the
    if/elif-chain -> data-table extraction; not an assertion that any given
    mapping reflects an external spec.
    """
    results = _buildAllResults()
    if _UPDATE:
        SNAP_PATH.write_text(json.dumps(results, indent=2, sort_keys=True) + "\n")
        return
    assert SNAP_PATH.exists(), f"Missing snapshot {SNAP_PATH}; generate with ARGUS_UPDATE_SNAPSHOTS=1"
    expected = json.loads(SNAP_PATH.read_text())
    assert results == expected, (
        "gap-template resolution behavior drifted. If intentional, regenerate with "
        "ARGUS_UPDATE_SNAPSHOTS=1 python -m pytest tests/planning/test_gap_template_rules_characterization.py -q "
        "and review the diff."
    )
