"""
Task Generator.

Converts coverage gaps and mission context into concrete, dependency-aware ResearchTask objects.
Each task describes a recommended action for the runtime with explicit metadata.tool_id routing.
Never executes anything itself.
"""
from typing import List, Any, Dict, Optional
from argus.planning.models import ResearchTask, CoverageGap, TaskCategory


# Task templates live in argus.planning.templates (single source of truth,
# shared with argus.scanning.dag). Imported here under their historical names.
from argus.planning.templates import (
    _RECON_TEMPLATES,
    _TOOL_TEMPLATES,
    _SPECIALIST_TEMPLATES,
)


class TaskGenerator:
    """Generates ResearchTask objects from coverage gaps and mission context."""

    def __init__(self, mission: Any):
        self.mission = mission

    def generate_recon_tasks(self) -> List[ResearchTask]:
        """
        Generate the full chain of concrete, dependency-aware recon tasks:
        1. Discover Subdomains (subfinder)
        2. Fingerprint Live Hosts (httpx) -> depends on Discover Subdomains
        3. Discover API Endpoints (katana_crawler) -> depends on Fingerprint Live Hosts
        4. Scan Live Hosts (nuclei) -> depends on Fingerprint Live Hosts
        """
        tasks = []
        target = str(getattr(self.mission, 'target', '') or '')
        subdomains = list(getattr(self.mission, 'subdomains', []) or [])
        live_hosts = list(getattr(self.mission, 'live_hosts', []) or [])

        # 1. Discover Subdomains (subfinder)
        t_sub = _RECON_TEMPLATES["subfinder"]
        tasks.append(ResearchTask(
            title=t_sub["title"],
            description=f"Discover subdomains for target {target}" if target else "Discover subdomains",
            goal=t_sub["goal"],
            category=t_sub["category"],
            required_inputs=[target] if target else ["target"],
            expected_outputs=list(t_sub["expected_outputs"]),
            priority=t_sub["priority"],
            confidence=0.8,
            dependencies=list(t_sub["dependencies"]),
            required_specialists=list(t_sub["required_specialists"]),
            estimated_duration_minutes=t_sub["estimated_duration_minutes"],
            reason="Initial recon: subdomain enumeration",
            supporting_evidence=[target] if target else [],
            metadata=dict(t_sub["metadata"]),
        ))

        # 2. Fingerprint Live Hosts (httpx)
        t_http = _RECON_TEMPLATES["httpx"]
        tasks.append(ResearchTask(
            title=t_http["title"],
            description="Probe subdomains for live HTTP hosts and technologies",
            goal=t_http["goal"],
            category=t_http["category"],
            required_inputs=[str(s) for s in subdomains[:10] if s is not None] if subdomains else ([target] if target else ["subdomains"]),
            expected_outputs=list(t_http["expected_outputs"]),
            priority=t_http["priority"],
            confidence=0.8,
            dependencies=list(t_http["dependencies"]),
            required_specialists=list(t_http["required_specialists"]),
            estimated_duration_minutes=t_http["estimated_duration_minutes"],
            reason="Active recon: live host and technology fingerprinting",
            supporting_evidence=[str(s) for s in subdomains[:10] if s is not None],
            metadata=dict(t_http["metadata"]),
        ))

        # 3. Discover API Endpoints (katana_crawler)
        t_kat = _RECON_TEMPLATES["katana_crawler"]
        host_inputs = [str(h.get('url', h)) if isinstance(h, dict) else str(h) for h in live_hosts[:10] if h is not None] if live_hosts else ([target] if target else ["live_hosts"])
        tasks.append(ResearchTask(
            title=t_kat["title"],
            description="Crawl live hosts to discover API endpoints",
            goal=t_kat["goal"],
            category=t_kat["category"],
            required_inputs=host_inputs,
            expected_outputs=list(t_kat["expected_outputs"]),
            priority=t_kat["priority"],
            confidence=0.8,
            dependencies=list(t_kat["dependencies"]),
            required_specialists=list(t_kat["required_specialists"]),
            estimated_duration_minutes=t_kat["estimated_duration_minutes"],
            reason="API discovery: endpoint crawling",
            supporting_evidence=host_inputs,
            metadata=dict(t_kat["metadata"]),
        ))

        # 4. Scan Live Hosts (nuclei)
        t_nuc = _RECON_TEMPLATES["nuclei"]
        tasks.append(ResearchTask(
            title=t_nuc["title"],
            description="Scan live hosts with automated vulnerability templates",
            goal=t_nuc["goal"],
            category=t_nuc["category"],
            required_inputs=host_inputs,
            expected_outputs=list(t_nuc["expected_outputs"]),
            priority=t_nuc["priority"],
            confidence=0.8,
            dependencies=list(t_nuc["dependencies"]),
            required_specialists=list(t_nuc["required_specialists"]),
            estimated_duration_minutes=t_nuc["estimated_duration_minutes"],
            reason="Vulnerability assessment: template scanning",
            supporting_evidence=host_inputs,
            metadata=dict(t_nuc["metadata"]),
        ))

        # 5. Probe Information Disclosure (info_disclosure)
        t_info = _RECON_TEMPLATES["info_disclosure"]
        tasks.append(ResearchTask(
            title=t_info["title"],
            description="Probe live hosts and endpoints for exposed sensitive files and secrets",
            goal=t_info["goal"],
            category=t_info["category"],
            required_inputs=host_inputs,
            expected_outputs=list(t_info["expected_outputs"]),
            priority=t_info["priority"],
            confidence=0.8,
            dependencies=list(t_info["dependencies"]),
            required_specialists=list(t_info["required_specialists"]),
            estimated_duration_minutes=t_info["estimated_duration_minutes"],
            reason="Vulnerability assessment: information disclosure probing",
            supporting_evidence=host_inputs,
            metadata=dict(t_info["metadata"]),
        ))

        return tasks


    def _resolve_template_for_gap(self, gap: CoverageGap) -> Dict[str, Any]:
        """Resolve the appropriate task template for a given CoverageGap."""
        area_lower = (gap.area or "").lower()
        gap_desc_lower = (gap.description or "").lower()

        # Explicit recon areas
        if area_lower in ("subdomains", "subdomain discovery"):
            return _RECON_TEMPLATES["subfinder"]

        if area_lower in ("live hosts", "live host discovery", "live_hosts"):
            return _RECON_TEMPLATES["httpx"]

        if area_lower in ("endpoints", "endpoint discovery", "endpoint crawling"):
            return _RECON_TEMPLATES["katana_crawler"]

        if area_lower in ("vulnerability scanning", "vulnerabilities", "vulnerability scan"):
            return _RECON_TEMPLATES["nuclei"]

        if area_lower in ("information disclosure", "info disclosure", "exposed files", "sensitive files", "secrets"):
            return _RECON_TEMPLATES["info_disclosure"]

        if area_lower in ("access control", "access_control", "idor", "broken access control", "authorization boundaries", "privilege escalation"):
            return _RECON_TEMPLATES["access_control"]

        if area_lower in ("path traversal", "path_traversal", "directory traversal", "traversal", "lfi", "local file inclusion", "arbitrary file read"):
            return _RECON_TEMPLATES["path_traversal"]

        if area_lower in ("sql injection", "sqli", "sql_injection", "database injection", "sql vulnerabilities", "sqli detection", "sql"):
            return _RECON_TEMPLATES["sql_injection"]

        if area_lower in ("xss", "xss detection", "cross site scripting", "cross-site scripting", "stored xss", "reflected xss", "dom xss"):
            return _RECON_TEMPLATES["xss"]

        if area_lower in ("command injection", "cmdi", "command_injection", "cmd_injection", "os command injection", "remote code execution", "rce", "os injection", "shell injection"):
            return _RECON_TEMPLATES["command_injection"]

        if area_lower in ("ssrf", "ssrf detection", "server side request forgery", "server-side request forgery", "ssrf validation", "metadata injection", "cloud metadata"):
            return _RECON_TEMPLATES["ssrf"]

        if area_lower in ("oauth", "oidc", "oauth2", "oauth_oidc", "openid", "jwt", "token validation", "token", "session fixation", "session management", "oauth authentication", "oidc token"):
            return _RECON_TEMPLATES["oauth"]

        if area_lower in ("xml parser", "xml_parser", "xml parser validation", "xxe", "xml external entity", "xml_external_entity", "xml injection", "xml"):
            return _RECON_TEMPLATES["xml_parser_validation"]

        if area_lower in (
            "insecure deserialization",
            "deserialization",
            "unsafe deserialization",
            "pickle",
            "python pickle",
            "java deserialization",
            "php unserialize",
            "unserialize",
            "viewstate",
            "ruby marshal",
            "objectinputstream",
            "object injection",
            "binary formatter",
            "binary_formatter",
        ):
            return _RECON_TEMPLATES["deserialization"]

        if area_lower in (
            "graphql security",
            "graphql vulnerability",
            "graphql injection",
            "graphql dos",
            "graphql introspection",
            "graphql batching",
            "graphql query depth",
            "graphql validation",
        ):
            return _RECON_TEMPLATES["graphql_security"]

        if area_lower in (
            "websocket security",
            "websocket",
            "cswsh",
            "cross-site websocket hijacking",
            "websocket injection",
            "websocket dos",
            "websocket authentication",
            "ws",
            "wss",
            "socket.io",
        ):
            return _RECON_TEMPLATES["websocket_security"]

        if area_lower in (
            "request smuggling",
            "http request smuggling",
            "request_smuggling",
            "cl.te",
            "te.cl",
            "te.te",
            "cl_te",
            "te_cl",
            "te_te",
            "h2 smuggling",
            "http2 smuggling",
            "h2.cl",
            "h2.te",
            "http desync",
            "smuggling",
            "desync",
        ):
            return _RECON_TEMPLATES["request_smuggling"]

        if area_lower in (
            "race conditions",
            "race condition",
            "race_conditions",
            "race_condition",
            "concurrency",
            "limit overrun",
            "limit_overrun",
            "toctou",
            "time-of-check to time-of-use",
            "multi-redemption",
            "race window",
            "single-packet attack",
            "single packet attack",
            "concurrency vulnerabilities",
        ):
            return _RECON_TEMPLATES["race_conditions"]

        if area_lower == "technologies":
            subdomains = list(getattr(self.mission, 'subdomains', []) or [])
            live_hosts = list(getattr(self.mission, 'live_hosts', []) or [])
            if not subdomains and not live_hosts:
                return _RECON_TEMPLATES["subfinder"]
            else:
                return _RECON_TEMPLATES["httpx"]

        if area_lower in ("api endpoints", "api"):
            endpoints = list(getattr(self.mission, 'endpoints', []) or [])
            if not endpoints or "crawl" in gap_desc_lower:
                return _RECON_TEMPLATES["katana_crawler"]
            return _SPECIALIST_TEMPLATES[TaskCategory.API_DISCOVERY]

        if area_lower in ("graphql schema", "graphql"):
            return _SPECIALIST_TEMPLATES[TaskCategory.GRAPHQL_ANALYSIS]

        if area_lower in ("authentication workflows", "authentication"):
            if "oauth" in gap_desc_lower or "oidc" in gap_desc_lower or "jwt" in gap_desc_lower or "token" in gap_desc_lower or "session" in gap_desc_lower:
                return _RECON_TEMPLATES["oauth"]
            if "websocket" in gap_desc_lower or "cswsh" in gap_desc_lower:
                return _RECON_TEMPLATES["websocket_security"]
            return _SPECIALIST_TEMPLATES[TaskCategory.AUTHENTICATION_ANALYSIS]

        if area_lower in ("authorization", "authorization graph"):
            if "oauth" in gap_desc_lower or "oidc" in gap_desc_lower or "jwt" in gap_desc_lower or "token" in gap_desc_lower:
                return _RECON_TEMPLATES["oauth"]
            if "websocket" in gap_desc_lower or "cswsh" in gap_desc_lower:
                return _RECON_TEMPLATES["websocket_security"]
            return _SPECIALIST_TEMPLATES[TaskCategory.AUTHORIZATION_ANALYSIS]

        if area_lower in ("business logic", "business logic workflows", "business logic flaws", "state machine", "workflow bypass", "price tampering", "quantity tampering", "mass assignment", "coupon stacking"):
            if any(kw in gap_desc_lower for kw in ("race", "concurrency", "toctou", "limit overrun", "multi-redemption", "overdraft")):
                return _RECON_TEMPLATES["race_conditions"]
            if any(kw in gap_desc_lower for kw in ("tamper", "price", "quantity", "amount", "workflow", "step", "state machine", "mass assignment", "coupon", "voucher", "idempotency", "differential", "flaw", "skip", "bypass", "logic")):
                return _RECON_TEMPLATES["business_logic"]
            return _RECON_TEMPLATES["business_logic"]

        if area_lower in (
            "ssti",
            "ssti detection",
            "server-side template injection",
            "server side template injection",
            "template injection",
            "template injection detection",
            "jinja2",
            "jinja",
            "twig",
            "freemarker",
            "velocity",
            "mako",
            "spel",
            "spring expression language",
            "thymeleaf",
            "erb",
            "smarty",
            "pug",
            "ejs",
        ):
            return _RECON_TEMPLATES["ssti"]

        if area_lower in (
            "cache security",
            "cache poisoning",
            "web cache poisoning",
            "cache deception",
            "web cache deception",
            "unkeyed headers",
            "unkeyed query parameters",
            "unkeyed parameters",
            "cache key normalization",
            "cache fingerprinting",
            "fat get",
            "path confusion",
            "wcd",
        ):
            return _RECON_TEMPLATES["cache_security"]

        if area_lower in (
            "cors",
            "cors security",
            "cors misconfiguration",
            "security headers",
            "http security headers",
            "csp",
            "content security policy",
            "hsts",
            "strict transport security",
            "x-frame-options",
            "cors_security",
        ):
            return _RECON_TEMPLATES["cors_security"]

        if area_lower in (
            "file upload",
            "file_upload",
            "file upload security",
            "upload security",
            "unrestricted file upload",
            "unrestricted upload",
            "arbitrary file upload",
            "mime type bypass",
            "double extension bypass",
            "polyglot upload",
            "web shell detection",
            "file upload vulnerabilities",
        ):
            return _RECON_TEMPLATES["file_upload"]

        if area_lower in (
            "api security",
            "api_security",
            "rest api security",
            "rest api",
            "grpc security",
            "grpc",
            "parameter tampering",
            "parameter_tampering",
            "mass assignment",
            "mass_assignment",
            "rate limiting",
            "rate_limiting",
            "rate limiting bypass",
            "rate_limit_bypass",
            "rate limit",
            "rate_limit",
            "bola",
            "idor",
            "broken object level authorization",
            "broken_object_level_authorization",
            "excessive data exposure",
            "excessive_data_exposure",
            "method tampering",
            "method_tampering",
            "api vulnerabilities",
            "api security testing",
        ):
            return _RECON_TEMPLATES["api_security"]

        if area_lower in (
            "auth bypass",
            "auth_bypass",
            "authentication bypass",
            "authentication_bypass",
            "credential attack",
            "credential_attack",
            "credential attacks",
            "brute force",
            "brute_force",
            "account lockout",
            "password reset",
            "password_reset",
            "mfa bypass",
            "mfa_bypass",
            "2fa bypass",
            "session fixation",
            "session_fixation",
            "jwt manipulation",
            "jwt_manipulation",
            "default credentials",
            "default_credentials",
            "session token analysis",
            "credential stuffing",
        ):
            return _RECON_TEMPLATES["auth_bypass"]

        if area_lower in (
            "prototype pollution",
            "prototype_pollution",
            "proto pollution",
            "proto_pollution",
            "client-side prototype pollution",
            "client_side_prototype_pollution",
            "server-side prototype pollution",
            "server_side_prototype_pollution",
            "dom clobbering",
            "dom_clobbering",
            "html clobbering",
            "open redirect",
            "open_redirect",
            "open redirect chain",
            "open_redirect_chain",
            "redirect chain",
            "clickjacking",
            "ui redressing",
            "ui_redressing",
            "frame busting",
            "frame_busting",
            "client-side attacks",
            "client_side_attacks",
            "client side attacks",
            "gadget chain",
            "prototype pollution gadgets",
        ):
            return _RECON_TEMPLATES["prototype_pollution"]

        if area_lower in ("javascript analysis", "javascript"):
            return _SPECIALIST_TEMPLATES[TaskCategory.JAVASCRIPT_ANALYSIS]

        if area_lower in ("evidence correlation",):
            return _SPECIALIST_TEMPLATES[TaskCategory.EVIDENCE_CORRELATION]

        # Category-based fallback
        if gap.category == TaskCategory.TECHNOLOGY_DISCOVERY:
            subdomains = list(getattr(self.mission, 'subdomains', []) or [])
            live_hosts = list(getattr(self.mission, 'live_hosts', []) or [])
            return _RECON_TEMPLATES["subfinder"] if not subdomains and not live_hosts else _RECON_TEMPLATES["httpx"]

        if gap.category == TaskCategory.API_DISCOVERY:
            endpoints = list(getattr(self.mission, 'endpoints', []) or [])
            if not endpoints or "crawl" in gap_desc_lower:
                return _RECON_TEMPLATES["katana_crawler"]
            return _SPECIALIST_TEMPLATES[TaskCategory.API_DISCOVERY]

        if gap.category == TaskCategory.AUTHENTICATION_ANALYSIS:
            if "oauth" in gap_desc_lower or "oidc" in gap_desc_lower:
                return _RECON_TEMPLATES["oauth"]
            if any(kw in gap_desc_lower for kw in ("auth", "login", "jwt", "session", "mfa", "credential", "brute force", "password reset", "session fixation", "default credential", "token")):
                return _RECON_TEMPLATES["auth_bypass"]
            if "websocket" in gap_desc_lower or "cswsh" in gap_desc_lower:
                return _RECON_TEMPLATES["websocket_security"]
            return _RECON_TEMPLATES.get("auth_bypass", _SPECIALIST_TEMPLATES[TaskCategory.AUTHENTICATION_ANALYSIS])

        if gap.category == TaskCategory.AUTHORIZATION_ANALYSIS:
            if "oauth" in gap_desc_lower or "oidc" in gap_desc_lower or "jwt" in gap_desc_lower or "token" in gap_desc_lower:
                return _RECON_TEMPLATES["oauth"]
            if "idor" in gap_desc_lower or "access control" in gap_desc_lower or "escalation" in gap_desc_lower or "bypass" in gap_desc_lower:
                return _RECON_TEMPLATES["access_control"]
            if "websocket" in gap_desc_lower or "cswsh" in gap_desc_lower:
                return _RECON_TEMPLATES["websocket_security"]
            return _SPECIALIST_TEMPLATES[TaskCategory.AUTHORIZATION_ANALYSIS]

        if gap.category == TaskCategory.EVIDENCE_CORRELATION:
            if "oauth" in gap_desc_lower or "oidc" in gap_desc_lower or "jwt" in gap_desc_lower or "token" in gap_desc_lower:
                return _RECON_TEMPLATES["oauth"]
            if any(kw in gap_desc_lower for kw in ("auth bypass", "authentication bypass", "credential attack", "brute force", "mfa bypass", "session fixation", "jwt manipulation", "default credential", "password reset")):
                return _RECON_TEMPLATES["auth_bypass"]
            if any(kw in gap_desc_lower for kw in ("prototype pollution", "prototype", "proto pollution", "proto", "dom clobbering", "clobbering", "open redirect", "redirect chain", "clickjacking", "ui redressing", "frame busting", "gadget chain", "client-side attacks", "client side")):
                return _RECON_TEMPLATES["prototype_pollution"]
            if any(kw in gap_desc_lower for kw in ("api security", "rest api", "grpc", "parameter tamper", "mass assignment", "rate limit", "rate limiting", "bola", "idor", "excessive data", "method tamper")):
                return _RECON_TEMPLATES["api_security"]
            if any(kw in gap_desc_lower for kw in ("file upload", "upload security", "unrestricted upload", "arbitrary upload", "mime type bypass", "double extension", "polyglot", "web shell", "file upload vulnerability")):
                return _RECON_TEMPLATES["file_upload"]
            if any(kw in gap_desc_lower for kw in ("race", "concurrency", "toctou", "limit overrun", "multi-redemption", "overdraft", "single-packet", "single packet")):
                return _RECON_TEMPLATES["race_conditions"]
            if any(kw in gap_desc_lower for kw in ("business logic", "state machine", "price tamper", "quantity tamper", "step skip", "workflow skip", "workflow bypass", "mass assignment", "coupon stack", "idempotency abuse", "parameter tamper")):
                return _RECON_TEMPLATES["business_logic"]
            if any(kw in gap_desc_lower for kw in ("ssti", "template injection", "server-side template", "jinja", "twig", "freemarker", "velocity", "mako", "spel", "thymeleaf", "erb", "smarty")):
                return _RECON_TEMPLATES["ssti"]
            if any(kw in gap_desc_lower for kw in ("cache security", "cache poison", "cache deception", "web cache", "unkeyed header", "unkeyed param", "fat get", "cache key", "parameter cloaking", "wcd")):
                return _RECON_TEMPLATES["cache_security"]
            if any(kw in gap_desc_lower for kw in ("cors", "cross-origin", "origin reflection", "null origin", "security header", "csp", "content-security-policy", "hsts", "strict-transport-security", "x-frame-options", "clickjacking", "nosniff", "referrer-policy", "permissions-policy")):
                return _RECON_TEMPLATES["cors_security"]
            if any(kw in gap_desc_lower for kw in ("smuggl", "cl.te", "te.cl", "te.te", "cl_te", "te_cl", "te_te", "h2.cl", "h2.te", "h2_cl", "h2_te", "desync", "request smuggling")):
                return _RECON_TEMPLATES["request_smuggling"]
            if any(kw in gap_desc_lower for kw in ("websocket", "cswsh", "socket.io", "ws://", "wss://", "upgrade")):
                return _RECON_TEMPLATES["websocket_security"]
            if any(kw in gap_desc_lower for kw in ("deserializ", "pickle", "unserialize", "marshal", "viewstate", "objectinputstream", "object injection")):
                return _RECON_TEMPLATES["deserialization"]
            if "graphql" in gap_desc_lower or "introspection" in gap_desc_lower:
                return _RECON_TEMPLATES["graphql_security"]
            if "xml" in gap_desc_lower or "xxe" in gap_desc_lower or "entity" in gap_desc_lower or "external entity" in gap_desc_lower:
                return _RECON_TEMPLATES["xml_parser_validation"]
            if "command" in gap_desc_lower or "cmdi" in gap_desc_lower or "rce" in gap_desc_lower or "os injection" in gap_desc_lower or "shell" in gap_desc_lower:
                return _RECON_TEMPLATES["command_injection"]
            if "ssrf" in gap_desc_lower or "request forgery" in gap_desc_lower or "metadata" in gap_desc_lower or "server-side" in gap_desc_lower:
                return _RECON_TEMPLATES["ssrf"]
            if "xss" in gap_desc_lower or "cross-site" in gap_desc_lower or "scripting" in gap_desc_lower:
                return _RECON_TEMPLATES["xss"]
            if "sql" in gap_desc_lower or "sqli" in gap_desc_lower or "database injection" in gap_desc_lower:
                return _RECON_TEMPLATES["sql_injection"]
            if "traversal" in gap_desc_lower or "lfi" in gap_desc_lower or "file read" in gap_desc_lower or "path" in gap_desc_lower:
                return _RECON_TEMPLATES["path_traversal"]
            if "information disclosure" in gap_desc_lower or "sensitive file" in gap_desc_lower or "secret" in gap_desc_lower:
                return _RECON_TEMPLATES["info_disclosure"]
            if "scan" in gap_desc_lower or "vulnerabilit" in gap_desc_lower:
                return _RECON_TEMPLATES["nuclei"]
            return _SPECIALIST_TEMPLATES[TaskCategory.EVIDENCE_CORRELATION]

        return _SPECIALIST_TEMPLATES.get(gap.category, _SPECIALIST_TEMPLATES[TaskCategory.COVERAGE_IMPROVEMENT])

    def from_gaps(self, gaps: List[CoverageGap]) -> List[ResearchTask]:
        """Convert a list of CoverageGaps into ResearchTasks."""
        tasks: List[ResearchTask] = []
        seen_titles = set()

        target = str(getattr(self.mission, 'target', '') or '')
        subdomains = list(getattr(self.mission, 'subdomains', []) or [])
        live_hosts = list(getattr(self.mission, 'live_hosts', []) or [])
        endpoints = list(getattr(self.mission, 'endpoints', []) or [])

        for gap in gaps:
            template = self._resolve_template_for_gap(gap)
            title = template["title"]

            # Avoid duplicating tasks with the same title
            if title in seen_titles:
                continue
            seen_titles.add(title)

            # Determine appropriate required_inputs
            if gap.related_assets:
                inputs = [str(a) for a in gap.related_assets if a is not None]
            else:
                tool_id = template.get("metadata", {}).get("tool_id", "")
                if tool_id == "subfinder":
                    inputs = [target] if target else ["target"]
                elif tool_id == "httpx":
                    inputs = [str(s) for s in subdomains[:10] if s is not None] if subdomains else ([target] if target else ["subdomains"])
                elif tool_id in ("katana_crawler", "nuclei", "info_disclosure", "access_control", "path_traversal", "sql_injection", "xss", "command_injection", "ssrf", "oauth", "xml_parser_validation", "deserialization", "graphql_security", "websocket_security", "request_smuggling", "race_conditions", "business_logic", "ssti", "cache_security", "cors_security", "file_upload", "api_security", "auth_bypass", "prototype_pollution"):
                    inputs = [str(e.get('url', e)) if isinstance(e, dict) else str(e) for e in endpoints[:10] if e is not None] if endpoints else ([str(h.get('url', h)) if isinstance(h, dict) else str(h) for h in live_hosts[:10] if h is not None] if live_hosts else ([target] if target else ["endpoints"]))

                elif endpoints:
                    inputs = [str(e.get('url', e)) if isinstance(e, dict) else str(e) for e in endpoints[:10] if e is not None]
                else:
                    inputs = list(template.get("required_inputs", []))




            task = ResearchTask(
                title=title,
                description=gap.description or template.get("goal", ""),
                goal=template["goal"],
                category=template.get("category", gap.category),
                required_inputs=inputs,
                expected_outputs=list(template.get("expected_outputs", [])),
                priority=gap.severity,
                confidence=0.8,
                dependencies=list(template.get("dependencies", [])),
                required_specialists=list(template.get("required_specialists", [])),
                estimated_duration_minutes=template.get("estimated_duration_minutes", 5),
                reason=f"Gap detected: {gap.description}",
                supporting_evidence=[str(a) for a in gap.related_assets if a is not None] if gap.related_assets else [],
                metadata=dict(template.get("metadata", {})),
            )
            tasks.append(task)

        return tasks
