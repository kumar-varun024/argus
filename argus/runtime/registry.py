from typing import List, Optional, Dict
import shutil
from argus.runtime.models import Tool


class ToolRegistry:
    """Registry for all executable capabilities (tools and plugins) in Argus."""

    def __init__(self):
        self.tools: Dict[str, Tool] = {}

    def register(self, tool: Tool):
        """Registers a tool using its unique ID."""
        self.tools[tool.id] = tool

    def get(self, key: str) -> Optional[Tool]:
        """Retrieves a tool by ID or capability name."""
        aliases = {
            "httpx": "httpx",
            "httpx_toolkit": "httpx",
            "httpx-toolkit": "httpx",
            "live_host_detector": "httpx",
            "live_hosts": "httpx",
            "subfinder": "subfinder",
            "subdomain_enumerator": "subfinder",
            "katana": "katana_crawler",
            "katana_crawler": "katana_crawler",
            "crawler": "katana_crawler",
            "nuclei": "nuclei",
            "vulnerability_scanner": "nuclei",
            "auth_bypass": "auth_bypass",
            "auth_bypass_collector": "auth_bypass",
            "authentication_bypass": "auth_bypass",
            "auth_collector": "auth_bypass",
            "auth": "auth_bypass",
            "credential_attack": "auth_bypass",
            "credential_attacks": "auth_bypass",
            "brute_force": "auth_bypass",
            "account_lockout": "auth_bypass",
            "password_reset": "auth_bypass",
            "password_reset_abuse": "auth_bypass",
            "mfa_bypass": "auth_bypass",
            "2fa_bypass": "auth_bypass",
            "session_fixation": "auth_bypass",
            "jwt_manipulation": "auth_bypass",
            "jwt_bypass": "auth_bypass",
            "jwt": "auth_bypass",
            "default_credentials": "auth_bypass",
            "default_creds": "auth_bypass",
            "session_token_analysis": "auth_bypass",
            "credential_stuffing": "auth_bypass",
            "prototype_pollution": "prototype_pollution",
            "prototype_pollution_collector": "prototype_pollution",
            "prototype_pollution_detector": "prototype_pollution",
            "prototype_pollution_specialist": "prototype_pollution",
            "proto_pollution": "prototype_pollution",
            "server_side_prototype_pollution": "prototype_pollution",
            "client_side_prototype_pollution": "prototype_pollution",
            "client_side_attacks": "prototype_pollution",
            "client_side_collector": "prototype_pollution",
            "client_side_detector": "prototype_pollution",
            "client_side_attack_collector": "prototype_pollution",
            "dom_clobbering": "prototype_pollution",
            "dom_clobbering_detector": "prototype_pollution",
            "dom_clobbering_collector": "prototype_pollution",
            "html_clobbering": "prototype_pollution",
            "open_redirect": "prototype_pollution",
            "open_redirect_collector": "prototype_pollution",
            "open_redirect_detector": "prototype_pollution",
            "open_redirect_chain": "prototype_pollution",
            "clickjacking_detector": "prototype_pollution",
            "ui_redressing": "prototype_pollution",
            "gadget_analyzer": "prototype_pollution",
            "cross_site_scripting": "xss",
            "sqli": "sql_injection",
            "cmdi": "command_injection",
            "cmd_injection": "command_injection",
            "command_injection_collector": "command_injection",
            "os_command_injection": "command_injection",
            "rce": "command_injection",
            "ssrf_validator": "ssrf",
            "ssrf_collector": "ssrf",
            "server_side_request_forgery": "ssrf",
            "oauth_collector": "oauth",
            "oidc": "oauth",
            "oidc_collector": "oauth",
            "oauth_oidc": "oauth",
            "xxe": "xml_parser_validation",
            "xxe_collector": "xml_parser_validation",
            "xml_parser": "xml_parser_validation",
            "xml_external_entity": "xml_parser_validation",
            "xml_parser_validator": "xml_parser_validation",
            "xml_security": "xml_parser_validation",
            "insecure_deserialization": "deserialization",
            "insecure_deserialization_collector": "deserialization",
            "deserialization_validator": "deserialization",
            "deserialization_collector": "deserialization",
            "deser": "deserialization",
            "pickle": "deserialization",
            "python_pickle": "deserialization",
            "unserialize": "deserialization",
            "php_unserialize": "deserialization",
            "java_deserialization": "deserialization",
            "object_input_stream": "deserialization",
            "ruby_marshal": "deserialization",
            "dotnet_viewstate": "deserialization",
            "dotnet_binary_formatter": "deserialization",
            "viewstate": "deserialization",
            "binary_formatter": "deserialization",
            "object_injection": "deserialization",
            "graphql_security": "graphql_security",
            "graphql_security_collector": "graphql_security",
            "graphql_detector": "graphql_security",
            "graphql_vuln": "graphql_security",
            "graphql_vulnerability": "graphql_security",
            "graphql_introspection": "graphql_security",
            "graphql_collector": "graphql_security",
            "graphql_security_validator": "graphql_security",
            "graphql_dos": "graphql_security",
            "graphql_batching": "graphql_security",
            "websocket": "websocket_security",
            "websocket_security": "websocket_security",
            "websocket_security_collector": "websocket_security",
            "websocket_collector": "websocket_security",
            "websocket_detector": "websocket_security",
            "websocket_vuln": "websocket_security",
            "websocket_vulnerability": "websocket_security",
            "websocket_injection": "websocket_security",
            "websocket_dos": "websocket_security",
            "websocket_auth": "websocket_security",
            "cswsh": "websocket_security",
            "cswsh_collector": "websocket_security",
            "cswsh_detector": "websocket_security",
            "ws_security": "websocket_security",
            "ws_collector": "websocket_security",
            "ws": "websocket_security",
            "wss": "websocket_security",
            "request_smuggling": "request_smuggling",
            "http_request_smuggling": "request_smuggling",
            "request_smuggling_collector": "request_smuggling",
            "request_smuggling_detector": "request_smuggling",
            "cl_te": "request_smuggling",
            "te_cl": "request_smuggling",
            "te_te": "request_smuggling",
            "h2_smuggling": "request_smuggling",
            "http2_smuggling": "request_smuggling",
            "h2_cl": "request_smuggling",
            "h2_te": "request_smuggling",
            "h2_crlf": "request_smuggling",
            "smuggling": "request_smuggling",
            "http_smuggling": "request_smuggling",
            "http_desync": "request_smuggling",
            "desync": "request_smuggling",
            "race_conditions": "race_conditions",
            "race_condition": "race_conditions",
            "race_conditions_collector": "race_conditions",
            "race_condition_collector": "race_conditions",
            "race_conditions_detector": "race_conditions",
            "race_condition_detector": "race_conditions",
            "concurrency": "race_conditions",
            "concurrency_collector": "race_conditions",
            "concurrency_detector": "race_conditions",
            "toctou": "race_conditions",
            "toctou_detector": "race_conditions",
            "toctou_collector": "race_conditions",
            "limit_overrun": "race_conditions",
            "limit_overrun_detector": "race_conditions",
            "multi_redemption": "race_conditions",
            "single_packet": "race_conditions",
            "single_packet_attack": "race_conditions",
            "race_window": "race_conditions",
            "race": "race_conditions",
            "business_logic": "business_logic",
            "business_logic_collector": "business_logic",
            "business_logic_detector": "business_logic",
            "business_logic_flaws": "business_logic",
            "business_logic_security": "business_logic",
            "state_machine": "business_logic",
            "state_machine_security": "business_logic",
            "workflow_bypass": "business_logic",
            "workflow_skip": "business_logic",
            "parameter_tampering": "business_logic",
            "price_tampering": "business_logic",
            "quantity_tampering": "business_logic",
            "mass_assignment": "business_logic",
            "coupon_stacking": "business_logic",
            "idempotency_abuse": "business_logic",
            "ssti": "ssti",
            "ssti_collector": "ssti",
            "ssti_detector": "ssti",
            "ssti_validator": "ssti",
            "server_side_template_injection": "ssti",
            "template_injection": "ssti",
            "template_injection_collector": "ssti",
            "template_injection_detector": "ssti",
            "jinja": "ssti",
            "jinja2": "ssti",
            "twig": "ssti",
            "freemarker": "ssti",
            "velocity": "ssti",
            "mako": "ssti",
            "spel": "ssti",
            "spring_expression_language": "ssti",
            "thymeleaf": "ssti",
            "erb": "ssti",
            "pug": "ssti",
            "jade": "ssti",
            "handlebars": "ssti",
            "ejs": "ssti",
            "smarty": "ssti",
            "blade": "ssti",
            "pebble": "ssti",
            "cache_security": "cache_security",
            "cache_security_collector": "cache_security",
            "cache_security_detector": "cache_security",
            "cache_poisoning": "cache_security",
            "cache_poisoning_collector": "cache_security",
            "web_cache_poisoning": "cache_security",
            "web_cache_poisoning_collector": "cache_security",
            "cache_deception": "cache_security",
            "web_cache_deception": "cache_security",
            "web_cache_deception_collector": "cache_security",
            "wcd": "cache_security",
            "unkeyed_headers": "cache_security",
            "unkeyed_header_poisoning": "cache_security",
            "unkeyed_params": "cache_security",
            "unkeyed_param_poisoning": "cache_security",
            "cache_key_normalization": "cache_security",
            "web_cache": "cache_security",
            "cache_prober": "cache_security",
            "cache_fingerprint": "cache_security",
            "cors": "cors_security",
            "cors_headers": "cors_security",
            "cors_security": "cors_security",
            "cors_collector": "cors_security",
            "cors_headers_collector": "cors_security",
            "cors_misconfiguration": "cors_security",
            "cors_misconfiguration_collector": "cors_security",
            "security_headers": "cors_security",
            "header_security": "cors_security",
            "http_headers": "cors_security",
            "header_audit": "cors_security",
            "header_auditor": "cors_security",
            "security_header_collector": "cors_security",
            "http_security_headers": "cors_security",
            "csp": "cors_security",
            "hsts": "cors_security",
            "clickjacking": "cors_security",
            "x_frame_options": "cors_security",
            "cors_detector": "cors_security",
            "file_upload": "file_upload",
            "file-upload": "file_upload",
            "file_upload_specialist": "file_upload",
            "file_upload_collector": "file_upload",
            "file_upload_detector": "file_upload",
            "unrestricted_file_upload": "file_upload",
            "arbitrary_file_upload": "file_upload",
            "upload_security": "file_upload",
            "api_security": "api_security",
            "api-security": "api_security",
            "api_security_specialist": "api_security",
            "api_security_collector": "api_security",
            "api_security_detector": "api_security",
            "api_security_testing": "api_security",
            "rest_api_security": "api_security",
            "rest_security": "api_security",
            "grpc_security": "api_security",
            "bola": "api_security",
            "idor_detector": "api_security",
            "excessive_data_exposure": "api_security",
            "rate_limit_bypass": "api_security",
            "rate_limiting": "api_security",
            "rate_limiting_bypass": "api_security",
            "method_tampering": "api_security",
        }

        if key in aliases and aliases[key] in self.tools:
            tool = self.tools[aliases[key]]
            self._ensure_tool_command(tool)
            return tool
        if key in self.tools:
            tool = self.tools[key]
            self._ensure_tool_command(tool)
            return tool
        # Fallback to capability lookup for backwards compatibility
        for tool in self.tools.values():
            if tool.capability == key or key in tool.capabilities:
                self._ensure_tool_command(tool)
                return tool
        return None

    def _ensure_tool_command(self, tool: Tool) -> None:
        """Dynamically ensures tool command points to an available binary if possible."""
        if tool.id == "httpx" and tool.command:
            if not shutil.which(tool.command):
                for cand in ["httpx-toolkit", "httpx", "/usr/bin/httpx-toolkit", "/usr/bin/httpx"]:
                    if shutil.which(cand):
                        tool.command = cand
                        break

    def resolve_tool_command(self, tool_id_or_cmd: str) -> str:
        """Resolves the executable binary name or path for a tool."""
        tool = self.get(tool_id_or_cmd)
        cmd = tool.command if tool and tool.command else tool_id_or_cmd
        if tool and tool.id == "httpx":
            for cand in ["httpx-toolkit", "httpx", "/usr/bin/httpx-toolkit", "/usr/bin/httpx"]:
                if shutil.which(cand):
                    return cand
        return shutil.which(cmd) or cmd

    def list(self) -> List[Tool]:
        """Returns all registered tools."""
        return list(self.tools.values())

    def find_compatible_tools(self, task_category: str) -> List[Tool]:
        """Finds tools that support the given task category, sorted deterministically."""
        compatible = []
        for tool in self.tools.values():
            if task_category in tool.supported_tasks:
                compatible.append(tool)
        # Deterministic sorting: priority descending, then tool id alphabetically
        compatible.sort(key=lambda t: (-t.priority, t.id))
        return compatible


def _resolve_httpx_command() -> str:
    for candidate in ["httpx-toolkit", "httpx", "/usr/bin/httpx-toolkit", "/usr/bin/httpx"]:
        if shutil.which(candidate):
            return candidate
    return "/usr/bin/httpx-toolkit"


# Instantiate global registry
registry = ToolRegistry()

# Register legacy/external CLI tools
registry.register(
    Tool(
        id="dnsx",
        name="dnsx",
        capability="dns_resolver",
        command="dnsx",
        description="DNS resolution and CNAME record querying utility",
        supported_tasks=["DNS Resolution", "Subdomain Takeover Detection", "Subdomain Enumeration"],
        required_inputs=["subdomains"],
        produced_outputs=["dns_records", "cnames"],
        capabilities=["dns_resolver"],
        safety_requirements={"type": "external", "permissions": ["network"]},
        timeout=300.0,
        priority=100,
    )
)

registry.register(
    Tool(
        id="subfinder",
        name="Subfinder",
        capability="subdomain_enumerator",
        command="subfinder",
        description="Discover subdomains",
        supported_tasks=["Technology Discovery", "API Discovery"],
        required_inputs=["target"],
        produced_outputs=["subdomains"],
        capabilities=["subdomain_enumerator"],
        safety_requirements={"type": "external", "permissions": ["network"]},
        timeout=300.0,
        priority=100
    )
)

registry.register(
    Tool(
        id="httpx",
        name="httpx",
        capability="live_host_detector",
        command=_resolve_httpx_command(),
        description="Find live hosts",
        supported_tasks=["Technology Discovery", "API Discovery"],
        required_inputs=["subdomains"],
        produced_outputs=["live_hosts"],
        capabilities=["live_host_detector"],
        safety_requirements={"type": "external", "permissions": ["network"]},
        timeout=300.0,
        priority=100
    )
)

registry.register(
    Tool(
        id="katana_crawler",
        name="Katana",
        capability="crawler",
        command="katana",
        description="Discover endpoints",
        supported_tasks=["API Discovery"],
        required_inputs=["live_hosts"],
        produced_outputs=["endpoints"],
        capabilities=["crawler"],
        safety_requirements={"type": "external", "permissions": ["network"]},
        timeout=300.0,
        priority=100
    )
)

registry.register(
    Tool(
        id="nuclei",
        name="Nuclei",
        capability="vulnerability_scanner",
        command="nuclei",
        description="Template based vulnerability scanner",
        supported_tasks=["Vulnerability Scanning", "Evidence Correlation", "API Discovery"],
        required_inputs=["live_hosts"],
        produced_outputs=["vulnerabilities", "observations"],
        capabilities=["vulnerability_scanner"],
        safety_requirements={"type": "external", "permissions": ["network"]},
        timeout=600.0,
        priority=90
    )
)

# Register internal specialist tools/plugins
registry.register(
    Tool(
        id="graphql_specialist",
        name="GraphQL Specialist",
        capability="graphql_analyzer",
        description="Models GraphQL endpoints, schemas, and operations.",
        supported_tasks=["GraphQL Analysis"],
        required_inputs=["endpoints"],
        produced_outputs=["graphql_state", "observations"],
        capabilities=["graphql_analyzer"],
        safety_requirements={"type": "internal", "permissions": ["network", "db_read", "db_write"]},
        timeout=600.0,
        priority=100
    )
)

registry.register(
    Tool(
        id="javascript_specialist",
        name="JavaScript Specialist",
        capability="javascript_analyzer",
        description="Models JavaScript files, routing, and AST structures.",
        supported_tasks=["JavaScript Analysis"],
        required_inputs=["files"],
        produced_outputs=["javascript_state", "observations"],
        capabilities=["javascript_analyzer"],
        safety_requirements={"type": "internal", "permissions": ["filesystem", "db_read", "db_write"]},
        timeout=600.0,
        priority=100
    )
)

registry.register(
    Tool(
        id="authorization_specialist",
        name="Authorization Specialist",
        capability="authorization_reviewer",
        description="Reviews authorization workflows and maps access policies.",
        supported_tasks=["Authorization Analysis"],
        required_inputs=["endpoints", "workflows"],
        produced_outputs=["authorization_state", "observations"],
        capabilities=["authorization_reviewer"],
        safety_requirements={"type": "internal", "permissions": ["db_read", "db_write"]},
        timeout=600.0,
        priority=100
    )
)

registry.register(
    Tool(
        id="authentication_specialist",
        name="Authentication Specialist",
        capability="authentication_analyzer",
        description="Analyzes authentication mechanisms and session management.",
        supported_tasks=["Authentication Analysis"],
        required_inputs=["endpoints"],
        produced_outputs=["authentication_state", "observations"],
        capabilities=["authentication_analyzer"],
        safety_requirements={"type": "internal", "permissions": ["network", "db_read", "db_write"]},
        timeout=600.0,
        priority=100
    )
)

registry.register(
    Tool(
        id="file_upload_specialist",
        name="File Upload Specialist",
        capability="file_upload_analyzer",
        description="Analyzes file upload forms and storage configurations.",
        supported_tasks=["Coverage Improvement"],
        required_inputs=["endpoints"],
        produced_outputs=["file_inventory", "observations"],
        capabilities=["file_upload_analyzer"],
        safety_requirements={"type": "internal", "permissions": ["network", "db_read", "db_write"]},
        timeout=600.0,
        priority=100
    )
)

registry.register(
    Tool(
        id="api_specialist",
        name="API Specialist",
        capability="api_analyzer",
        description="Coordinates API discovery and profiles resource structures.",
        supported_tasks=["API Discovery"],
        required_inputs=["live_hosts"],
        produced_outputs=["api_inventory", "observations"],
        capabilities=["api_analyzer"],
        safety_requirements={"type": "internal", "permissions": ["network", "db_read", "db_write"]},
        timeout=600.0,
        priority=90  # Lower priority than Katana so Katana gets selected first deterministically
    )
)

registry.register(
    Tool(
        id="business_logic_specialist",
        name="Business Logic Specialist",
        capability="business_logic_analyzer",
        description="Infers business logic constraints and maps workflow rules.",
        supported_tasks=["Business Logic Analysis"],
        required_inputs=["endpoints", "workflows"],
        produced_outputs=["business_objects", "observations"],
        capabilities=["business_logic_analyzer"],
        safety_requirements={"type": "internal", "permissions": ["db_read", "db_write"]},
        timeout=600.0,
        priority=100
    )
)

registry.register(
    Tool(
        id="info_disclosure",
        name="Information Disclosure Collector",
        capability="information_disclosure_detector",
        description="Actively probes live hosts and endpoints for exposed configuration files, .env, .git, and actuator endpoints.",
        supported_tasks=["Information Disclosure Detection", "Information Disclosure", "Vulnerability Scanning", "Evidence Correlation", "API Discovery", "Technology Discovery"],
        required_inputs=["live_hosts"],
        produced_outputs=["vulnerabilities", "observations", "evidence", "subdomains"],
        capabilities=["information_disclosure_detector"],
        safety_requirements={"type": "internal", "permissions": ["network", "db_read", "db_write"]},
        timeout=300.0,
        priority=95
    )
)

registry.register(
    Tool(
        id="access_control",
        name="Access Control & IDOR Collector",
        capability="access_control_collector",
        description="Tests for horizontal IDOR, vertical privilege escalation, and access control bypasses across identities.",
        supported_tasks=["Authorization Analysis", "Access Control Analysis", "IDOR Detection", "Vulnerability Scanning", "Evidence Correlation"],
        required_inputs=["endpoints"],
        produced_outputs=["vulnerabilities", "observations", "evidence"],
        capabilities=["access_control_collector"],
        safety_requirements={"type": "internal", "permissions": ["network", "db_read", "db_write"]},
        timeout=300.0,
        priority=95,
    )
)

registry.register(
    Tool(
        id="path_traversal",
        name="Path Traversal Collector",
        capability="path_traversal_detector",
        description="Actively fuzzes endpoints and parameters for directory escape and arbitrary file read vulnerabilities.",
        supported_tasks=["Path Traversal Detection", "Directory Traversal", "Vulnerability Scanning", "Evidence Correlation", "API Discovery"],
        required_inputs=["endpoints"],
        produced_outputs=["vulnerabilities", "observations", "evidence"],
        capabilities=["path_traversal_detector", "path_traversal_collector"],
        safety_requirements={"type": "internal", "permissions": ["network", "db_read", "db_write"]},
        timeout=300.0,
        priority=95,
    )
)

registry.register(
    Tool(
        id="sql_injection",
        name="SQL Injection Collector",
        capability="sql_injection_detector",
        description="Actively injects SQL payloads into discovered endpoint parameters (query, body, headers) detecting error-based, boolean-based, and time-based blind SQLi.",
        supported_tasks=["SQL Injection Detection", "SQL Injection", "Vulnerability Scanning", "Evidence Correlation", "API Discovery"],
        required_inputs=["endpoints"],
        produced_outputs=["vulnerabilities", "observations", "evidence"],
        capabilities=["sql_injection_detector", "sql_injection_collector"],
        safety_requirements={"type": "internal", "permissions": ["network", "db_read", "db_write"]},
        timeout=300.0,
        priority=95,
    )
)

registry.register(
    Tool(
        id="xss",
        name="Cross-Site Scripting (XSS) Collector",
        capability="xss_detector",
        description="Actively injects context-aware XSS payloads into discovered endpoint parameters and forms detecting reflected and stored XSS using AuthenticatedHttpClient.",
        supported_tasks=["XSS Detection", "Cross-Site Scripting", "Vulnerability Scanning", "Evidence Correlation", "API Discovery"],
        required_inputs=["endpoints"],
        produced_outputs=["vulnerabilities", "observations", "evidence"],
        capabilities=["xss_detector", "xss_collector"],
        safety_requirements={"type": "internal", "permissions": ["network", "db_read", "db_write"]},
        timeout=300.0,
        priority=95,
    )
)

registry.register(
    Tool(
        id="command_injection",
        name="Command Injection Collector",
        capability="command_injection_detector",
        description="Actively injects command injection payloads into discovered endpoint parameters (query, body, path, headers) detecting result-based, time-based blind, and error-based OS command injection using AuthenticatedHttpClient.",
        supported_tasks=["Command Injection Detection", "Command Injection", "OS Command Injection", "Remote Code Execution", "Vulnerability Scanning", "Evidence Correlation", "API Discovery"],
        required_inputs=["endpoints"],
        produced_outputs=["vulnerabilities", "observations", "evidence"],
        capabilities=["command_injection_detector", "command_injection_collector", "cmdi_detector", "cmdi_collector"],
        safety_requirements={"type": "internal", "permissions": ["network", "db_read", "db_write"]},
        timeout=300.0,
        priority=95,
    )
)

registry.register(
    Tool(
        id="ssrf",
        name="SSRF Validation Collector",
        capability="ssrf_detector",
        description="Actively injects SSRF payloads into discovered endpoint parameters (query, body, path, headers) probing cloud metadata, internal services, and blind differential timing using AuthenticatedHttpClient.",
        supported_tasks=["SSRF Detection", "Server-Side Request Forgery", "SSRF Validation", "Cloud Metadata Probe", "Internal Service Probe", "Vulnerability Scanning", "Evidence Correlation", "API Discovery"],
        required_inputs=["endpoints"],
        produced_outputs=["vulnerabilities", "observations", "evidence"],
        capabilities=["ssrf_detector", "ssrf_collector", "ssrf_validator", "server_side_request_forgery"],
        safety_requirements={"type": "internal", "permissions": ["network", "db_read", "db_write"]},
        timeout=300.0,
        priority=95,
    )
)

registry.register(
    Tool(
        id="oauth",
        name="OAuth/OIDC Authentication Collector",
        capability="oauth_oidc_detector",
        description="Actively tests discovered OAuth and OIDC endpoints for authentication and authorization misconfigurations, JWT signature and claims validation, and stateful session security using AuthenticatedHttpClient.",
        supported_tasks=[
            "OAuth Detection",
            "OIDC Detection",
            "Token Validation",
            "Stateful Authentication",
            "Session Management",
            "Authorization Analysis",
            "Authentication Analysis",
            "Evidence Correlation",
            "API Discovery",
        ],
        required_inputs=["endpoints"],
        produced_outputs=["vulnerabilities", "observations", "evidence"],
        capabilities=[
            "oauth_oidc_detector",
            "oauth_collector",
            "oidc_collector",
            "oauth_detector",
            "jwt_validator",
            "session_security_analyzer",
        ],
        safety_requirements={"type": "internal", "permissions": ["network", "db_read", "db_write"]},
        timeout=300.0,
        priority=95,
    )
)

registry.register(
    Tool(
        id="xml_parser_validation",
        name="XML Parser Configuration Validation Collector",
        capability="xml_parser_security_validator",
        description="Actively validates XML parser configurations on discovered endpoints, testing for external entity resolution, parameter entities, and recursive entity expansion using AuthenticatedHttpClient.",
        supported_tasks=[
            "XML Parser Security Validation",
            "XML Parser Validation",
            "XXE Validation",
            "XXE Detection",
            "XML External Entity",
            "Vulnerability Scanning",
            "Evidence Correlation",
            "API Discovery",
        ],
        required_inputs=["endpoints"],
        produced_outputs=["vulnerabilities", "observations", "evidence"],
        capabilities=[
            "xml_parser_security_validator",
            "xml_parser_validation_collector",
            "xxe_detector",
            "xxe_collector",
        ],
        safety_requirements={"type": "internal", "permissions": ["network", "db_read", "db_write"]},
        timeout=300.0,
        priority=95,
    )
)

registry.register(
    Tool(
        id="deserialization",
        name="Insecure Deserialization Validation Collector",
        capability="deserialization_detector",
        description="Actively tests discovered endpoint parameters, POST bodies, headers, and cookies for insecure deserialization vulnerabilities across multiple formats (Java ObjectInputStream, Python pickle, PHP serialize, Ruby Marshal, .NET ViewState) using AuthenticatedHttpClient.",
        supported_tasks=[
            "Insecure Deserialization Detection",
            "Deserialization Validation",
            "Deserialization",
            "Unsafe Deserialization",
            "Vulnerability Scanning",
            "Evidence Correlation",
            "API Discovery",
        ],
        required_inputs=["endpoints"],
        produced_outputs=["vulnerabilities", "observations", "evidence"],
        capabilities=[
            "deserialization_detector",
            "deserialization_collector",
            "deserialization_validator",
            "insecure_deserialization_detector",
            "insecure_deserialization_collector",
            "java_deserialization",
            "python_pickle",
            "php_unserialize",
            "ruby_marshal",
            "dotnet_viewstate",
            "dotnet_binary_formatter",
            "object_injection",
        ],
        safety_requirements={"type": "internal", "permissions": ["network", "db_read", "db_write"]},
        timeout=300.0,
        priority=95,
    )
)

registry.register(
    Tool(
        id="graphql_security",
        name="GraphQL Security Detection Collector",
        capability="graphql_security_detector",
        description="Actively tests discovered GraphQL endpoints for introspection leakage, query depth/complexity DoS, query batching abuse, and field-level authorization bypass using AuthenticatedHttpClient.",
        supported_tasks=[
            "GraphQL Security Validation",
            "GraphQL Analysis",
            "Introspection Detection",
            "GraphQL DoS",
            "GraphQL Batching",
            "Vulnerability Scanning",
            "Evidence Correlation",
            "API Discovery",
        ],
        required_inputs=["endpoints"],
        produced_outputs=["vulnerabilities", "observations", "evidence"],
        capabilities=[
            "graphql_security_detector",
            "graphql_security_collector",
            "graphql_introspection_detector",
            "graphql_dos_detector",
            "graphql_batching_detector",
            "graphql_access_control",
        ],
        safety_requirements={"type": "internal", "permissions": ["network", "db_read", "db_write"]},
        timeout=300.0,
        priority=95,
    )
)

registry.register(
    Tool(
        id="websocket_security",
        name="WebSocket Security Detection Collector",
        capability="websocket_security_detector",
        description="Actively tests discovered WebSocket endpoints for Cross-Site WebSocket Hijacking (CSWSH), unauthenticated handshakes, message frame injection, and WebSocket DoS/rate-limiting resilience using AuthenticatedHttpClient and WebSocket handshake probers.",
        supported_tasks=[
            "WebSocket Security Validation",
            "WebSocket Analysis",
            "CSWSH Detection",
            "WebSocket Frame Injection",
            "WebSocket DoS",
            "WebSocket Rate Limiting",
            "Vulnerability Scanning",
            "Evidence Correlation",
            "API Discovery",
        ],
        required_inputs=["endpoints"],
        produced_outputs=["vulnerabilities", "observations", "evidence"],
        capabilities=[
            "websocket_security_detector",
            "websocket_security_collector",
            "cswsh_detector",
            "websocket_injection_detector",
            "websocket_dos_detector",
            "websocket_auth_detector",
        ],
        safety_requirements={"type": "internal", "permissions": ["network", "db_read", "db_write"]},
        timeout=300.0,
        priority=95,
    )
)

registry.register(
    Tool(
        id="request_smuggling",
        name="HTTP Request Smuggling Detection Collector",
        capability="request_smuggling_detector",
        description="Actively tests discovered endpoints and reverse proxies for HTTP request smuggling (CL.TE, TE.CL, TE.TE, HTTP/2 downgrading) and boundary desynchronization.",
        supported_tasks=[
            "Request Smuggling Validation",
            "HTTP Request Smuggling",
            "Request Smuggling",
            "CL.TE Detection",
            "TE.CL Detection",
            "TE.TE Detection",
            "HTTP/2 Smuggling",
            "Vulnerability Scanning",
            "Evidence Correlation",
            "API Discovery",
        ],
        required_inputs=["endpoints"],
        produced_outputs=["vulnerabilities", "observations", "evidence"],
        capabilities=[
            "request_smuggling_detector",
            "request_smuggling_collector",
            "http_request_smuggling_detector",
            "cl_te_detector",
            "te_cl_detector",
            "te_te_detector",
            "h2_smuggling_detector",
            "http_desync_detector",
        ],
        safety_requirements={"type": "internal", "permissions": ["network", "db_read", "db_write"]},
        timeout=300.0,
        priority=95,
    )
)

registry.register(
    Tool(
        id="race_conditions",
        name="Race Conditions & Concurrency Detection Collector",
        capability="race_conditions_detector",
        description="Actively tests discovered endpoints for race conditions, limit overruns, TOCTOU desynchronization, session concurrency, and multi-endpoint partial state bugs using concurrent multi-request synchronization probers.",
        supported_tasks=[
            "Race Condition Validation",
            "Race Conditions",
            "Race Condition Detection",
            "Limit Overrun Detection",
            "TOCTOU Validation",
            "Concurrency Analysis",
            "Vulnerability Scanning",
            "Evidence Correlation",
            "API Discovery",
        ],
        required_inputs=["endpoints"],
        produced_outputs=["vulnerabilities", "observations", "evidence"],
        capabilities=[
            "race_conditions_detector",
            "race_condition_detector",
            "race_conditions_collector",
            "limit_overrun_detector",
            "toctou_detector",
            "concurrency_detector",
        ],
        safety_requirements={"type": "internal", "permissions": ["network", "db_read", "db_write"]},
        timeout=300.0,
        priority=95,
    )
)

registry.register(
    Tool(
        id="business_logic",
        name="Business Logic & State Machine Security Collector",
        capability="business_logic_detector",
        description="Actively validates whether multi-step workflows, e-commerce checkout flows, state transitions, price/quantity tampering, and mass assignment can bypass business rules using AuthenticatedHttpClient and stateful probers.",
        supported_tasks=[
            "Business Logic Validation",
            "Business Logic Analysis",
            "Business Logic Flaws",
            "State Machine Security",
            "Workflow Bypass Detection",
            "Price Tampering Detection",
            "Parameter Tampering Detection",
            "Mass Assignment Detection",
            "Coupon Abuse Detection",
            "Vulnerability Scanning",
            "Evidence Correlation",
            "API Discovery",
        ],
        required_inputs=["endpoints"],
        produced_outputs=["vulnerabilities", "observations", "evidence"],
        capabilities=[
            "business_logic_detector",
            "business_logic_collector",
            "state_machine_detector",
            "workflow_bypass_detector",
            "parameter_tampering_detector",
            "mass_assignment_detector",
            "coupon_stacking_detector",
        ],
        safety_requirements={"type": "internal", "permissions": ["network", "db_read", "db_write"]},
        timeout=300.0,
        priority=95,
    )
)

registry.register(
    Tool(
        id="ssti",
        name="Server-Side Template Injection (SSTI) Detection Collector",
        capability="ssti_detector",
        description="Actively discovers and validates Server-Side Template Injection vulnerabilities across major template engine families (Jinja2, Mako, Twig, Freemarker, Velocity, SpEL, Thymeleaf, ERB, etc.) using AuthenticatedHttpClient and polyglot arithmetic probers.",
        supported_tasks=[
            "SSTI Detection",
            "Server-Side Template Injection",
            "Template Injection",
            "Template Engine Identification",
            "Vulnerability Scanning",
            "Evidence Correlation",
            "API Discovery",
        ],
        required_inputs=["endpoints"],
        produced_outputs=["vulnerabilities", "observations", "evidence"],
        capabilities=[
            "ssti_detector",
            "ssti_collector",
            "ssti_validator",
            "template_injection_detector",
            "template_injection_collector",
            "jinja_detector",
            "twig_detector",
            "freemarker_detector",
        ],
        safety_requirements={"type": "internal", "permissions": ["network", "db_read", "db_write"]},
        timeout=300.0,
        priority=95,
    )
)

registry.register(
    Tool(
        id="cache_security",
        name="Web Cache Poisoning & Cache Deception Detection Collector",
        capability="cache_security_detector",
        description="Actively discovers and validates Web Cache Poisoning (unkeyed headers/query params, cloaking, fat GETs, normalization flaws) and Web Cache Deception across reverse proxies, CDNs, and web caches using AuthenticatedHttpClient.",
        supported_tasks=[
            "Web Cache Security",
            "Cache Poisoning Detection",
            "Cache Deception Detection",
            "Web Cache Poisoning",
            "Web Cache Deception",
            "Unkeyed Header Analysis",
            "Unkeyed Parameter Analysis",
            "CDN Lifecycle Fingerprinting",
            "Vulnerability Scanning",
            "Evidence Correlation",
            "API Discovery",
        ],
        required_inputs=["endpoints"],
        produced_outputs=["vulnerabilities", "observations", "evidence"],
        capabilities=[
            "cache_security_detector",
            "cache_security_collector",
            "cache_poisoning_detector",
            "cache_deception_detector",
            "unkeyed_input_detector",
            "cache_fingerprint_detector",
        ],
        safety_requirements={"type": "internal", "permissions": ["network", "db_read", "db_write"]},
        timeout=300.0,
        priority=95,
    )
)

registry.register(
    Tool(
        id="cors_security",
        name="CORS & HTTP Security Header Audit",
        capability="cors_security_detector",
        description="Detects CORS misconfigurations and missing/weak HTTP security headers across discovered endpoints and live hosts.",
        supported_tasks=["CORS Security Testing", "HTTP Header Audit", "Security Header Validation", "Vulnerability Scanning"],
        required_inputs=["endpoints"],
        produced_outputs=["vulnerabilities", "observations", "evidence"],
        capabilities=["cors_security", "cors_security_detector", "cors_security_collector", "cors_security_validator", "header_security", "header_audit"],
        safety_requirements={"type": "internal", "permissions": ["network", "db_read", "db_write"]},
        timeout=300.0,
        priority=95,
    )
)

registry.register(
    Tool(
        id="file_upload",
        name="File Upload Vulnerability Detection Collector",
        capability="file_upload_detector",
        description="Actively discovers and validates file upload vulnerabilities (unrestricted executable uploads, MIME type bypasses, double extension bypasses, polyglots, path traversal in filenames, and web shell execution) using AuthenticatedHttpClient.",
        supported_tasks=[
            "File Upload Security",
            "Unrestricted File Upload",
            "MIME Type Bypass",
            "Double Extension Bypass",
            "Polyglot Upload",
            "Path Traversal in Filename",
            "Web Shell Detection",
            "Vulnerability Scanning",
            "Evidence Correlation",
            "API Discovery",
        ],
        required_inputs=["endpoints"],
        produced_outputs=["vulnerabilities", "observations", "evidence"],
        capabilities=[
            "file_upload_detector",
            "file_upload_collector",
            "file_upload_analyzer",
            "unrestricted_file_upload",
            "file_upload_specialist",
        ],
        safety_requirements={"type": "internal", "permissions": ["network", "db_read", "db_write"]},
        timeout=300.0,
        priority=95,
    )
)

registry.register(
    Tool(
        id="api_security",
        name="API Security Testing Collector",
        capability="api_security_detector",
        description="Actively discovers and validates REST and gRPC API vulnerabilities (parameter tampering, mass assignment, rate limiting bypass, BOLA/IDOR, excessive data exposure, and HTTP method tampering) using AuthenticatedHttpClient.",
        supported_tasks=[
            "API Security Testing",
            "API Security",
            "BOLA Detection",
            "Mass Assignment Detection",
            "Rate Limiting Bypass Detection",
            "Excessive Data Exposure Detection",
            "Parameter Tampering Detection",
            "Method Tampering Detection",
            "Vulnerability Scanning",
            "Evidence Correlation",
            "API Discovery",
        ],
        required_inputs=["endpoints"],
        produced_outputs=["vulnerabilities", "observations", "evidence"],
        capabilities=[
            "api_security_detector",
            "api_security_collector",
            "api_security_specialist",
            "api_security",
            "bola_detector",
            "mass_assignment_detector",
            "rate_limit_detector",
            "excessive_data_exposure_detector",
        ],
        safety_requirements={"type": "internal", "permissions": ["network", "db_read", "db_write"]},
        timeout=300.0,
        priority=95,
    )
)

registry.register(
    Tool(
        id="auth_bypass",
        name="Authentication Bypass & Credential Attack Detection Collector",
        capability="auth_bypass_detector",
        description="Actively discovers and validates authentication bypass vulnerabilities (brute force, account lockout missing, password reset abuse, MFA bypass, session fixation, JWT manipulation, and default credentials) using AuthenticatedHttpClient.",
        supported_tasks=[
            "Authentication Bypass Testing",
            "Credential Attack Detection",
            "Brute Force Analysis",
            "Account Lockout Verification",
            "Password Reset Abuse Detection",
            "MFA Bypass Testing",
            "Session Fixation Detection",
            "JWT Manipulation",
            "Default Credentials Detection",
            "Session Token Analysis",
            "Credential Stuffing Susceptibility",
            "Vulnerability Scanning",
            "Evidence Correlation",
            "Authentication Analysis",
        ],
        required_inputs=["endpoints"],
        produced_outputs=["vulnerabilities", "observations", "evidence"],
        capabilities=[
            "auth_bypass_detector",
            "auth_bypass_collector",
            "auth_bypass_specialist",
            "auth_bypass",
            "authentication_bypass",
            "credential_attack",
            "brute_force_detector",
            "jwt_detector",
            "mfa_bypass_detector",
            "session_fixation_detector",
            "default_credentials_detector",
        ],
        safety_requirements={"type": "internal", "permissions": ["network", "db_read", "db_write"]},
        timeout=300.0,
        priority=95,
    )
)

registry.register(
    Tool(
        id="prototype_pollution",
        name="Prototype Pollution & Client-Side Attack Detection Collector",
        capability="prototype_pollution_detector",
        description="Actively discovers and validates prototype pollution (server-side and client-side gadgets), DOM clobbering, open redirect chains, and clickjacking vulnerabilities using AuthenticatedHttpClient.",
        supported_tasks=[
            "Prototype Pollution Testing",
            "Server-Side Prototype Pollution",
            "Client-Side Prototype Pollution",
            "DOM Clobbering Detection",
            "Open Redirect Chain Detection",
            "Clickjacking & UI Redressing Validation",
            "Gadget Chain Analysis",
            "Vulnerability Scanning",
            "Evidence Correlation",
            "Client-Side Attack Analysis",
        ],
        required_inputs=["endpoints"],
        produced_outputs=["vulnerabilities", "observations", "evidence"],
        capabilities=[
            "prototype_pollution_detector",
            "prototype_pollution_collector",
            "prototype_pollution_specialist",
            "prototype_pollution",
            "client_side_attacks",
            "client_side_detector",
            "dom_clobbering_detector",
            "open_redirect_detector",
            "clickjacking_detector",
            "gadget_analyzer",
        ],
        safety_requirements={"type": "internal", "permissions": ["network", "db_read", "db_write"]},
        timeout=300.0,
        priority=95,
    )
)















