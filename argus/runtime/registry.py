from typing import List, Optional, Dict
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
        if key in self.tools:
            return self.tools[key]
        aliases = {
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
        }

        if key in aliases and aliases[key] in self.tools:
            return self.tools[aliases[key]]
        # Fallback to capability lookup for backwards compatibility
        for tool in self.tools.values():
            if tool.capability == key or key in tool.capabilities:
                return tool
        return None

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
        command="/usr/bin/httpx-toolkit",
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








