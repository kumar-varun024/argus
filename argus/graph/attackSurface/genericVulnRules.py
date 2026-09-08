"""Config table for the 20 sections that share GenericVulnRule's shape:
sections 9,10,11 (GENERIC_VULN_RULES_PART1) then section 12/XSS (bespoke,
see bespokeVulnSections.py) then sections 13-29 (GENERIC_VULN_RULES_PART2).

Split into two ordered tuples -- rather than one -- specifically to keep
XSS's insertion point self-documenting in evidenceBuilder.py; call order
within each tuple mirrors the original section numbering exactly, which is
load-bearing: a later section's live-host resolution can see a live_host
node an earlier section's fallback created (both read/write the same
`graph`), so reordering these would change output.

Every field here was read directly off the pre-unification per-section
functions (see git history of vulnSections1.py..vulnSections5.py) -- not
inferred or guessed. Behavior pinned by
tests/graph/test_attack_surface_characterization.py.
"""
from __future__ import annotations

from typing import Tuple

from argus.graph.attackSurface.genericVulnRule import GenericVulnRule

GENERIC_VULN_RULES_PART1: Tuple[GenericVulnRule, ...] = (
    GenericVulnRule(
        section_num=9, categories=("broken_access_control",), template_id_default="broken-access-control",
        has_param=False, param_keys=(), detail_keys=(), detail_default="",
        name_template="Broken Access Control (IDOR)", default_severity="critical",
        endpoint_includes_status_code=False,
    ),
    GenericVulnRule(
        section_num=10, categories=("path_traversal",), template_id_default="path-traversal",
        has_param=False, param_keys=(), detail_keys=(), detail_default="",
        name_template="Path Traversal", default_severity="critical",
    ),
    GenericVulnRule(
        section_num=11, categories=("sql_injection",), template_id_default="sqli",
        has_param=True, param_keys=("parameter",), detail_keys=(), detail_default="",
        name_template="SQL Injection", default_severity="critical",
    ),
)

GENERIC_VULN_RULES_PART2: Tuple[GenericVulnRule, ...] = (
    GenericVulnRule(
        section_num=13, categories=("command_injection", "cmdi", "os_command_injection", "cmd_injection"),
        template_id_default="cmdi", has_param=True, param_keys=("parameter",),
        detail_keys=("technique",), detail_default="result_based",
        name_template="Command Injection ({detail})", default_severity="critical",
    ),
    GenericVulnRule(
        section_num=14, categories=("ssrf", "server_side_request_forgery", "ssrf_validation"),
        template_id_default="ssrf", has_param=True, param_keys=("parameter",),
        detail_keys=("technique",), detail_default="cloud_metadata",
        name_template="Server-Side Request Forgery ({detail})", default_severity="critical",
    ),
    GenericVulnRule(
        section_num=15, categories=(
            "oauth", "oidc", "oauth_oidc", "oauth_misconfiguration", "token_validation",
            "session_management", "authentication",
        ),
        template_id_default="oauth-misconfiguration", has_param=True, param_keys=("parameter",),
        detail_keys=("misconfiguration_type",), detail_default="authentication",
        name_template="OAuth / Stateful Auth Vulnerability ({detail})", default_severity="high",
    ),
    GenericVulnRule(
        section_num=16, categories=(
            "xml_parser_validation", "xxe", "xml_external_entity", "xml_parser", "xml_parser_security",
        ),
        template_id_default="xxe", has_param=True, param_keys=("parameter",),
        detail_keys=("technique",), detail_default="external_entity",
        name_template="XML Parser Misconfiguration ({detail})", default_severity="critical",
    ),
    GenericVulnRule(
        section_num=17, categories=(
            "deserialization", "insecure_deserialization", "unsafe_deserialization", "java_deserialization",
            "python_pickle", "php_unserialize", "ruby_marshal", "dotnet_viewstate", "dotnet_binary_formatter",
        ),
        template_id_default="deserialization", has_param=True, param_keys=("parameter",),
        detail_keys=("format",), detail_default="deserialization",
        name_template="Insecure Deserialization ({detail})", default_severity="critical",
    ),
    GenericVulnRule(
        section_num=18, categories=(
            "graphql", "graphql_security", "graphql_introspection", "graphql_dos", "graphql_batching",
            "graphql_access_control",
        ),
        template_id_default="graphql-security", has_param=True, param_keys=("parameter", "technique"),
        detail_keys=("vulnerability_type", "technique"), detail_default="security_misconfiguration",
        name_template="GraphQL Security ({detail})", default_severity="medium",
    ),
    GenericVulnRule(
        section_num=19, categories=(
            "websocket", "websocket_security", "cswsh", "websocket_injection", "websocket_dos", "websocket_auth",
        ),
        template_id_default="websocket-security", has_param=True, param_keys=("parameter", "technique"),
        detail_keys=("vulnerability_type", "technique"), detail_default="security_misconfiguration",
        name_template="WebSocket Security ({detail})", default_severity="medium",
    ),
    GenericVulnRule(
        section_num=20, categories=(
            "request_smuggling", "http_request_smuggling", "cl_te", "te_cl", "te_te", "h2_smuggling",
            "smuggling", "http_desync",
        ),
        template_id_default="request-smuggling", has_param=True, param_keys=("parameter", "technique"),
        detail_keys=("vulnerability_type", "technique"), detail_default="request_smuggling",
        name_template="HTTP Request Smuggling ({detail})", default_severity="critical",
    ),
    GenericVulnRule(
        section_num=21, categories=(
            "race_condition", "race_conditions", "limit_overrun", "toctou", "concurrency",
            "concurrency_limit", "session_concurrency", "multi_redemption",
        ),
        template_id_default="race-conditions", has_param=True, param_keys=("parameter", "technique"),
        detail_keys=("vulnerability_type", "technique"), detail_default="race_condition",
        name_template="Race Condition ({detail})", default_severity="high",
    ),
    GenericVulnRule(
        section_num=22, categories=(
            "business_logic", "business_logic_flaws", "business_logic_security", "state_machine",
            "state_machine_security", "price_tampering", "quantity_tampering", "parameter_tampering",
            "workflow_bypass", "workflow_skip", "workflow_step_skip", "mass_assignment", "coupon_stacking",
            "idempotency_abuse", "differential_state_verification", "differential_state",
        ),
        template_id_default="business-logic", has_param=True, param_keys=("parameter", "technique"),
        detail_keys=("vulnerability_type", "technique"), detail_default="business_logic",
        name_template="Business Logic Vulnerability ({detail})", default_severity="high",
    ),
    GenericVulnRule(
        section_num=23, categories=(
            "ssti", "server_side_template_injection", "template_injection", "ssti_rce", "ssti_blind",
            "ssti_error", "jinja2", "twig", "freemarker", "velocity", "mako", "spel", "thymeleaf", "erb",
            "smarty", "pug", "ejs",
        ),
        template_id_default="ssti", has_param=True, param_keys=("parameter", "technique"),
        detail_keys=("engine", "vulnerability_type", "technique"), detail_default="template_injection",
        name_template="Server-Side Template Injection ({detail})", default_severity="high",
    ),
    GenericVulnRule(
        section_num=24, categories=(
            "cache_security", "cache_poisoning", "web_cache_poisoning", "cache_deception",
            "web_cache_deception", "unkeyed_header_poisoning", "unkeyed_param_poisoning",
            "unkeyed_query_poisoning", "parameter_cloaking", "cache_key_normalization", "fat_get_poisoning",
            "method_override_poisoning", "wcd",
        ),
        template_id_default="web-cache-poisoning", has_param=True, param_keys=("parameter", "technique"),
        detail_keys=("vulnerability_type", "technique"), detail_default="cache_security",
        name_template="Web Cache Security ({detail})", default_severity="high",
    ),
    GenericVulnRule(
        section_num=25, categories=(
            "cors", "cors_security", "cors_headers", "cors_misconfiguration", "security_headers",
            "http_security_headers", "http_headers", "security_header", "header_security",
        ),
        template_id_default="cors-security-finding", has_param=True,
        param_keys=("parameter", "vector_name", "header_name"),
        detail_keys=("vulnerability_type", "technique"), detail_default="cors_security",
        name_template="CORS / Security Header ({detail})", default_severity="medium",
    ),
    GenericVulnRule(
        section_num=26, categories=(
            "file_upload", "upload_security", "unrestricted_upload", "unrestricted_file_upload",
            "arbitrary_file_upload", "mime_type_bypass", "double_extension_bypass", "polyglot_magic_bytes",
            "path_traversal_filename", "web_shell_execution",
        ),
        template_id_default="file-upload-finding", has_param=True, param_keys=("filename", "parameter"),
        detail_keys=("vulnerability_type", "technique"), detail_default="file_upload",
        name_template="File Upload Vulnerability ({detail})", default_severity="high",
    ),
    GenericVulnRule(
        section_num=27, categories=(
            "api_security", "api_security_testing", "rest_api_security", "rest_security", "grpc_security",
            "parameter_tampering", "mass_assignment", "rate_limiting", "rate_limiting_bypass",
            "rate_limit_bypass", "bola", "idor", "bola_idor", "broken_object_level_authorization",
            "excessive_data_exposure", "method_tampering", "api_bypass",
        ),
        template_id_default="api-security-finding", has_param=True,
        param_keys=("parameter", "field", "endpoint"),
        detail_keys=("vulnerability_type", "technique"), detail_default="api_security",
        name_template="API Security Vulnerability ({detail})", default_severity="high",
    ),
    GenericVulnRule(
        section_num=28, categories=(
            "auth_bypass", "authentication", "authentication_bypass", "credential_attack",
            "credential_attacks", "brute_force", "password_reset", "password_reset_abuse", "mfa_bypass",
            "session_fixation", "jwt_manipulation", "default_credentials", "session_token_analysis",
            "credential_stuffing",
        ),
        template_id_default="auth-bypass-finding", has_param=True,
        param_keys=("parameter", "field", "endpoint"),
        detail_keys=("vulnerability_type", "technique"), detail_default="auth_bypass",
        name_template="Authentication Vulnerability ({detail})", default_severity="high",
    ),
    GenericVulnRule(
        section_num=29, categories=(
            "prototype_pollution", "client_side_prototype_pollution", "server_side_prototype_pollution",
            "dom_clobbering", "html_clobbering", "open_redirect", "open_redirect_chain", "clickjacking",
            "ui_redressing", "client_side_attacks",
        ),
        template_id_default="prototype-pollution-finding", has_param=True,
        param_keys=("parameter", "gadget", "field", "endpoint"),
        detail_keys=("vulnerability_type", "technique"), detail_default="prototype_pollution",
        name_template="Client-Side Attack Vulnerability ({detail})", default_severity="high",
    ),
)
