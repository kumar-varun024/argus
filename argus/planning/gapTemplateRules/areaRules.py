"""Ordered area-alias -> task-template rules for TaskGenerator.

Extracted verbatim (as data) from the former if/elif chain in
`TaskGenerator._resolve_template_for_gap`. AREA_RULES order is load-bearing:
three area aliases -- "idor", "session fixation", and "mass assignment" --
each appear in two different rule groups (idor: access_control vs.
api_security; session fixation: oauth vs. auth_bypass; mass assignment:
business_logic vs. api_security). The original code was an if/elif chain, so
the EARLIER rule always won; AREA_RULES preserves that by being tried in this
exact order, first match wins.

Behavior preserved and pinned by
tests/planning/test_gap_template_rules_characterization.py.

One dead branch was removed during extraction: the original "business logic"
area block checked for tamper-keywords and returned `business_logic` if
present, then unconditionally returned `business_logic` again as a
fallthrough -- both arms produced the identical template object, so the check
was dead code. BUSINESS_LOGIC_LADDER encodes only the observable behavior
(race keywords -> race_conditions, everything else -> business_logic).
"""
from __future__ import annotations

from typing import Any, Dict, Tuple

from argus.planning.models import TaskCategory
from argus.planning.templates import _RECON_TEMPLATES, _SPECIALIST_TEMPLATES
from argus.planning.gapTemplateRules.outcomeResolution import (
    KeywordRule,
    Outcome,
    dynamic,
    firstKeywordOutcome,
    recon,
    resolveOutcome,
    specialist,
)


def technologiesHandler(generator, gap, areaLower, descLower) -> Dict[str, Any]:
    subdomains = list(getattr(generator.mission, "subdomains", []) or [])
    liveHosts = list(getattr(generator.mission, "live_hosts", []) or [])
    if not subdomains and not liveHosts:
        return _RECON_TEMPLATES["subfinder"]
    return _RECON_TEMPLATES["httpx"]


def apiEndpointsHandler(generator, gap, areaLower, descLower) -> Dict[str, Any]:
    endpoints = list(getattr(generator.mission, "endpoints", []) or [])
    if not endpoints or "crawl" in descLower:
        return _RECON_TEMPLATES["katana_crawler"]
    return _SPECIALIST_TEMPLATES[TaskCategory.API_DISCOVERY]


AUTHENTICATION_WORKFLOWS_LADDER: Tuple[KeywordRule, ...] = (
    (frozenset({"oauth", "oidc", "jwt", "token", "session"}), recon("oauth")),
    (frozenset({"websocket", "cswsh"}), recon("websocket_security")),
)


def _authenticationWorkflowsHandler(generator, gap, areaLower, descLower) -> Dict[str, Any]:
    outcome = firstKeywordOutcome(descLower, AUTHENTICATION_WORKFLOWS_LADDER, specialist(TaskCategory.AUTHENTICATION_ANALYSIS))
    return resolveOutcome(generator, gap, areaLower, descLower, outcome)


AUTHORIZATION_LADDER: Tuple[KeywordRule, ...] = (
    (frozenset({"oauth", "oidc", "jwt", "token"}), recon("oauth")),
    (frozenset({"websocket", "cswsh"}), recon("websocket_security")),
)


def _authorizationHandler(generator, gap, areaLower, descLower) -> Dict[str, Any]:
    outcome = firstKeywordOutcome(descLower, AUTHORIZATION_LADDER, specialist(TaskCategory.AUTHORIZATION_ANALYSIS))
    return resolveOutcome(generator, gap, areaLower, descLower, outcome)


BUSINESS_LOGIC_LADDER: Tuple[KeywordRule, ...] = (
    (frozenset({"race", "concurrency", "toctou", "limit overrun", "multi-redemption", "overdraft"}), recon("race_conditions")),
)


def _businessLogicHandler(generator, gap, areaLower, descLower) -> Dict[str, Any]:
    outcome = firstKeywordOutcome(descLower, BUSINESS_LOGIC_LADDER, recon("business_logic"))
    return resolveOutcome(generator, gap, areaLower, descLower, outcome)


# Tried in order; first area_lower membership match wins. See module docstring
# for the three aliases whose group depends on this exact ordering.
AREA_RULES: Tuple[Tuple[frozenset, Outcome], ...] = (
    (frozenset({"subdomains", "subdomain discovery"}), recon("subfinder")),
    (frozenset({"live hosts", "live host discovery", "live_hosts"}), recon("httpx")),
    (frozenset({"endpoints", "endpoint discovery", "endpoint crawling"}), recon("katana_crawler")),
    (frozenset({"vulnerability scanning", "vulnerabilities", "vulnerability scan"}), recon("nuclei")),
    (frozenset({"information disclosure", "info disclosure", "exposed files", "sensitive files", "secrets"}), recon("info_disclosure")),
    (frozenset({"access control", "access_control", "idor", "broken access control", "authorization boundaries", "privilege escalation"}), recon("access_control")),
    (frozenset({"path traversal", "path_traversal", "directory traversal", "traversal", "lfi", "local file inclusion", "arbitrary file read"}), recon("path_traversal")),
    (frozenset({"sql injection", "sqli", "sql_injection", "database injection", "sql vulnerabilities", "sqli detection", "sql"}), recon("sql_injection")),
    (frozenset({"xss", "xss detection", "cross site scripting", "cross-site scripting", "stored xss", "reflected xss", "dom xss"}), recon("xss")),
    (frozenset({"command injection", "cmdi", "command_injection", "cmd_injection", "os command injection", "remote code execution", "rce", "os injection", "shell injection"}), recon("command_injection")),
    (frozenset({"ssrf", "ssrf detection", "server side request forgery", "server-side request forgery", "ssrf validation", "metadata injection", "cloud metadata"}), recon("ssrf")),
    (frozenset({"oauth", "oidc", "oauth2", "oauth_oidc", "openid", "jwt", "token validation", "token", "session fixation", "session management", "oauth authentication", "oidc token"}), recon("oauth")),
    (frozenset({"xml parser", "xml_parser", "xml parser validation", "xxe", "xml external entity", "xml_external_entity", "xml injection", "xml"}), recon("xml_parser_validation")),
    (frozenset({
        "insecure deserialization", "deserialization", "unsafe deserialization", "pickle", "python pickle",
        "java deserialization", "php unserialize", "unserialize", "viewstate", "ruby marshal",
        "objectinputstream", "object injection", "binary formatter", "binary_formatter",
    }), recon("deserialization")),
    (frozenset({
        "graphql security", "graphql vulnerability", "graphql injection", "graphql dos",
        "graphql introspection", "graphql batching", "graphql query depth", "graphql validation",
    }), recon("graphql_security")),
    (frozenset({
        "websocket security", "websocket", "cswsh", "cross-site websocket hijacking", "websocket injection",
        "websocket dos", "websocket authentication", "ws", "wss", "socket.io",
    }), recon("websocket_security")),
    (frozenset({
        "request smuggling", "http request smuggling", "request_smuggling", "cl.te", "te.cl", "te.te",
        "cl_te", "te_cl", "te_te", "h2 smuggling", "http2 smuggling", "h2.cl", "h2.te", "http desync",
        "smuggling", "desync",
    }), recon("request_smuggling")),
    (frozenset({
        "race conditions", "race condition", "race_conditions", "race_condition", "concurrency",
        "limit overrun", "limit_overrun", "toctou", "time-of-check to time-of-use", "multi-redemption",
        "race window", "single-packet attack", "single packet attack", "concurrency vulnerabilities",
    }), recon("race_conditions")),
    (frozenset({"technologies"}), dynamic(technologiesHandler)),
    (frozenset({"api endpoints", "api"}), dynamic(apiEndpointsHandler)),
    (frozenset({"graphql schema", "graphql"}), specialist(TaskCategory.GRAPHQL_ANALYSIS)),
    (frozenset({"authentication workflows", "authentication"}), dynamic(_authenticationWorkflowsHandler)),
    (frozenset({"authorization", "authorization graph"}), dynamic(_authorizationHandler)),
    (frozenset({
        "business logic", "business logic workflows", "business logic flaws", "state machine",
        "workflow bypass", "price tampering", "quantity tampering", "mass assignment", "coupon stacking",
    }), dynamic(_businessLogicHandler)),
    (frozenset({
        "ssti", "ssti detection", "server-side template injection", "server side template injection",
        "template injection", "template injection detection", "jinja2", "jinja", "twig", "freemarker",
        "velocity", "mako", "spel", "spring expression language", "thymeleaf", "erb", "smarty", "pug", "ejs",
    }), recon("ssti")),
    (frozenset({
        "cache security", "cache poisoning", "web cache poisoning", "cache deception", "web cache deception",
        "unkeyed headers", "unkeyed query parameters", "unkeyed parameters", "cache key normalization",
        "cache fingerprinting", "fat get", "path confusion", "wcd",
    }), recon("cache_security")),
    (frozenset({
        "cors", "cors security", "cors misconfiguration", "security headers", "http security headers",
        "csp", "content security policy", "hsts", "strict transport security", "x-frame-options", "cors_security",
    }), recon("cors_security")),
    (frozenset({
        "file upload", "file_upload", "file upload security", "upload security", "unrestricted file upload",
        "unrestricted upload", "arbitrary file upload", "mime type bypass", "double extension bypass",
        "polyglot upload", "web shell detection", "file upload vulnerabilities",
    }), recon("file_upload")),
    (frozenset({
        "api security", "api_security", "rest api security", "rest api", "grpc security", "grpc",
        "parameter tampering", "parameter_tampering", "mass assignment", "mass_assignment", "rate limiting",
        "rate_limiting", "rate limiting bypass", "rate_limit_bypass", "rate limit", "rate_limit", "bola",
        "idor", "broken object level authorization", "broken_object_level_authorization",
        "excessive data exposure", "excessive_data_exposure", "method tampering", "method_tampering",
        "api vulnerabilities", "api security testing",
    }), recon("api_security")),
    (frozenset({
        "auth bypass", "auth_bypass", "authentication bypass", "authentication_bypass", "credential attack",
        "credential_attack", "credential attacks", "brute force", "brute_force", "account lockout",
        "password reset", "password_reset", "mfa bypass", "mfa_bypass", "2fa bypass", "session fixation",
        "session_fixation", "jwt manipulation", "jwt_manipulation", "default credentials",
        "default_credentials", "session token analysis", "credential stuffing",
    }), recon("auth_bypass")),
    (frozenset({
        "prototype pollution", "prototype_pollution", "proto pollution", "proto_pollution",
        "client-side prototype pollution", "client_side_prototype_pollution", "server-side prototype pollution",
        "server_side_prototype_pollution", "dom clobbering", "dom_clobbering", "html clobbering",
        "open redirect", "open_redirect", "open redirect chain", "open_redirect_chain", "redirect chain",
        "clickjacking", "ui redressing", "ui_redressing", "frame busting", "frame_busting",
        "client-side attacks", "client_side_attacks", "client side attacks", "gadget chain",
        "prototype pollution gadgets",
    }), recon("prototype_pollution")),
    (frozenset({"javascript analysis", "javascript"}), specialist(TaskCategory.JAVASCRIPT_ANALYSIS)),
    (frozenset({"evidence correlation"}), specialist(TaskCategory.EVIDENCE_CORRELATION)),
)
