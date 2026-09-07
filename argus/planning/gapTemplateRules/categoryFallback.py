"""Category-based fallback rules, used only when no AREA_RULES entry matched.

gap.category dispatch itself has no ordering concern (a gap has exactly one
category, so CATEGORY_FALLBACK_HANDLERS is a plain lookup, unlike the keyword
ladders below). Within EVIDENCE_CORRELATION_LADDER, however, order IS
load-bearing: e.g. "clickjacking" is a keyword in both the prototype-pollution
and cors-security entries, and the earlier (prototype-pollution) entry must
keep winning, exactly as in the original if/elif chain.
"""
from __future__ import annotations

from typing import Any, Dict, Tuple

from argus.planning.models import TaskCategory
from argus.planning.templates import _RECON_TEMPLATES, _SPECIALIST_TEMPLATES
from argus.planning.gapTemplateRules.areaRules import apiEndpointsHandler, technologiesHandler
from argus.planning.gapTemplateRules.outcomeResolution import KeywordRule, dynamic, firstKeywordOutcome, recon, resolveOutcome, specialist


def _authenticationAnalysisFallback(generator, gap, areaLower, descLower) -> Dict[str, Any]:
    ladder = (
        (frozenset({"oauth", "oidc"}), recon("oauth")),
        (frozenset({
            "auth", "login", "jwt", "session", "mfa", "credential", "brute force", "password reset",
            "session fixation", "default credential", "token",
        }), recon("auth_bypass")),
        (frozenset({"websocket", "cswsh"}), recon("websocket_security")),
    )
    outcome = firstKeywordOutcome(
        descLower, ladder,
        dynamic(lambda g, gp, a, d: _RECON_TEMPLATES.get("auth_bypass", _SPECIALIST_TEMPLATES[TaskCategory.AUTHENTICATION_ANALYSIS])),
    )
    return resolveOutcome(generator, gap, areaLower, descLower, outcome)


def _authorizationAnalysisFallback(generator, gap, areaLower, descLower) -> Dict[str, Any]:
    ladder = (
        (frozenset({"oauth", "oidc", "jwt", "token"}), recon("oauth")),
        (frozenset({"idor", "access control", "escalation", "bypass"}), recon("access_control")),
        (frozenset({"websocket", "cswsh"}), recon("websocket_security")),
    )
    outcome = firstKeywordOutcome(descLower, ladder, specialist(TaskCategory.AUTHORIZATION_ANALYSIS))
    return resolveOutcome(generator, gap, areaLower, descLower, outcome)


EVIDENCE_CORRELATION_LADDER: Tuple[KeywordRule, ...] = (
    (frozenset({"oauth", "oidc", "jwt", "token"}), recon("oauth")),
    (frozenset({
        "auth bypass", "authentication bypass", "credential attack", "brute force", "mfa bypass",
        "session fixation", "jwt manipulation", "default credential", "password reset",
    }), recon("auth_bypass")),
    (frozenset({
        "prototype pollution", "prototype", "proto pollution", "proto", "dom clobbering", "clobbering",
        "open redirect", "redirect chain", "clickjacking", "ui redressing", "frame busting", "gadget chain",
        "client-side attacks", "client side",
    }), recon("prototype_pollution")),
    (frozenset({
        "api security", "rest api", "grpc", "parameter tamper", "mass assignment", "rate limit",
        "rate limiting", "bola", "idor", "excessive data", "method tamper",
    }), recon("api_security")),
    (frozenset({
        "file upload", "upload security", "unrestricted upload", "arbitrary upload", "mime type bypass",
        "double extension", "polyglot", "web shell", "file upload vulnerability",
    }), recon("file_upload")),
    (frozenset({
        "race", "concurrency", "toctou", "limit overrun", "multi-redemption", "overdraft",
        "single-packet", "single packet",
    }), recon("race_conditions")),
    (frozenset({
        "business logic", "state machine", "price tamper", "quantity tamper", "step skip", "workflow skip",
        "workflow bypass", "mass assignment", "coupon stack", "idempotency abuse", "parameter tamper",
    }), recon("business_logic")),
    (frozenset({
        "ssti", "template injection", "server-side template", "jinja", "twig", "freemarker", "velocity",
        "mako", "spel", "thymeleaf", "erb", "smarty",
    }), recon("ssti")),
    (frozenset({
        "cache security", "cache poison", "cache deception", "web cache", "unkeyed header", "unkeyed param",
        "fat get", "cache key", "parameter cloaking", "wcd",
    }), recon("cache_security")),
    (frozenset({
        "cors", "cross-origin", "origin reflection", "null origin", "security header", "csp",
        "content-security-policy", "hsts", "strict-transport-security", "x-frame-options", "clickjacking",
        "nosniff", "referrer-policy", "permissions-policy",
    }), recon("cors_security")),
    (frozenset({
        "smuggl", "cl.te", "te.cl", "te.te", "cl_te", "te_cl", "te_te", "h2.cl", "h2.te", "h2_cl", "h2_te",
        "desync", "request smuggling",
    }), recon("request_smuggling")),
    (frozenset({"websocket", "cswsh", "socket.io", "ws://", "wss://", "upgrade"}), recon("websocket_security")),
    (frozenset({
        "deserializ", "pickle", "unserialize", "marshal", "viewstate", "objectinputstream", "object injection",
    }), recon("deserialization")),
    (frozenset({"graphql", "introspection"}), recon("graphql_security")),
    (frozenset({"xml", "xxe", "entity", "external entity"}), recon("xml_parser_validation")),
    (frozenset({"command", "cmdi", "rce", "os injection", "shell"}), recon("command_injection")),
    (frozenset({"ssrf", "request forgery", "metadata", "server-side"}), recon("ssrf")),
    (frozenset({"xss", "cross-site", "scripting"}), recon("xss")),
    (frozenset({"sql", "sqli", "database injection"}), recon("sql_injection")),
    (frozenset({"traversal", "lfi", "file read", "path"}), recon("path_traversal")),
    (frozenset({"information disclosure", "sensitive file", "secret"}), recon("info_disclosure")),
    (frozenset({"scan", "vulnerabilit"}), recon("nuclei")),
)


def _evidenceCorrelationFallback(generator, gap, areaLower, descLower) -> Dict[str, Any]:
    outcome = firstKeywordOutcome(descLower, EVIDENCE_CORRELATION_LADDER, specialist(TaskCategory.EVIDENCE_CORRELATION))
    return resolveOutcome(generator, gap, areaLower, descLower, outcome)


# gap.category dispatch has no ordering concern (a gap has exactly one
# category, so this is a plain lookup, unlike the keyword ladders above).
CATEGORY_FALLBACK_HANDLERS: Dict[TaskCategory, Any] = {
    TaskCategory.TECHNOLOGY_DISCOVERY: technologiesHandler,
    TaskCategory.API_DISCOVERY: apiEndpointsHandler,
    TaskCategory.AUTHENTICATION_ANALYSIS: _authenticationAnalysisFallback,
    TaskCategory.AUTHORIZATION_ANALYSIS: _authorizationAnalysisFallback,
    TaskCategory.EVIDENCE_CORRELATION: _evidenceCorrelationFallback,
}
