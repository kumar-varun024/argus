"""
Task Generator.

Converts coverage gaps and mission context into concrete, dependency-aware ResearchTask objects.
Each task describes a recommended action for the runtime with explicit metadata.tool_id routing.
Never executes anything itself.
"""
from typing import List, Any, Dict, Optional
from argus.planning.models import ResearchTask, CoverageGap, TaskCategory


# Concrete recon task templates
_RECON_TEMPLATES = {
    "subfinder": {
        "title": "Discover Subdomains",
        "goal": "Enumerate all subdomains in scope for the target.",
        "category": TaskCategory.TECHNOLOGY_DISCOVERY,
        "required_inputs": ["target"],
        "expected_outputs": ["subdomains"],
        "dependencies": [],
        "required_specialists": [],
        "metadata": {"tool_id": "subfinder"},
        "estimated_duration_minutes": 5,
        "priority": 0.95,
    },
    "httpx": {
        "title": "Fingerprint Live Hosts",
        "goal": "Probe subdomains to discover live HTTP/HTTPS hosts and fingerprint technologies.",
        "category": TaskCategory.TECHNOLOGY_DISCOVERY,
        "required_inputs": ["subdomains"],
        "expected_outputs": ["live_hosts", "technologies"],
        "dependencies": ["Discover Subdomains"],
        "required_specialists": [],
        "metadata": {"tool_id": "httpx"},
        "estimated_duration_minutes": 5,
        "priority": 0.90,
    },
    "katana_crawler": {
        "title": "Discover API Endpoints",
        "goal": "Enumerate and crawl endpoints on live hosts.",
        "category": TaskCategory.API_DISCOVERY,
        "required_inputs": ["live_hosts"],
        "expected_outputs": ["endpoints"],
        "dependencies": ["Fingerprint Live Hosts"],
        "required_specialists": [],
        "metadata": {"tool_id": "katana_crawler"},
        "estimated_duration_minutes": 10,
        "priority": 0.85,
    },
    "nuclei": {
        "title": "Scan Live Hosts",
        "goal": "Run automated vulnerability templates against live hosts.",
        "category": TaskCategory.EVIDENCE_CORRELATION,
        "required_inputs": ["live_hosts"],
        "expected_outputs": ["vulnerabilities", "observations"],
        "dependencies": ["Fingerprint Live Hosts"],
        "required_specialists": [],
        "metadata": {"tool_id": "nuclei"},
        "estimated_duration_minutes": 15,
        "priority": 0.80,
    },
    "info_disclosure": {
        "title": "Probe Information Disclosure",
        "goal": "Probe live hosts and endpoints for exposed sensitive files (.git, .env, actuator, phpinfo, source maps) and extract leaked secrets/hostnames.",
        "category": TaskCategory.EVIDENCE_CORRELATION,
        "required_inputs": ["live_hosts"],
        "expected_outputs": ["vulnerabilities", "observations", "evidence", "subdomains"],
        "dependencies": ["Fingerprint Live Hosts"],
        "required_specialists": [],
        "metadata": {"tool_id": "info_disclosure"},
        "estimated_duration_minutes": 5,
        "priority": 0.82,
    },
    "access_control": {
        "title": "Analyze Access Control & IDOR",
        "goal": "Test authorization boundaries, horizontal IDOR, vertical privilege escalation, and proxy header bypasses across identities.",
        "category": TaskCategory.AUTHORIZATION_ANALYSIS,
        "required_inputs": ["endpoints"],
        "expected_outputs": ["vulnerabilities", "observations", "evidence"],
        "dependencies": ["Discover API Endpoints"],
        "required_specialists": [],
        "metadata": {"tool_id": "access_control"},
        "estimated_duration_minutes": 10,
        "priority": 0.81,
    },
    "path_traversal": {
        "title": "Fuzz Path & Directory Traversal",
        "goal": "Actively fuzz discovered endpoint parameters and URL paths for directory traversal and arbitrary file disclosure vulnerabilities using AuthenticatedHttpClient.",
        "category": TaskCategory.EVIDENCE_CORRELATION,
        "required_inputs": ["endpoints"],
        "expected_outputs": ["vulnerabilities", "observations", "evidence"],
        "dependencies": ["Discover API Endpoints"],
        "required_specialists": [],
        "metadata": {"tool_id": "path_traversal"},
        "estimated_duration_minutes": 10,
        "priority": 0.81,
    },
    "sql_injection": {
        "title": "Fuzz SQL Injection",
        "goal": "Actively fuzz discovered endpoint parameters and HTTP headers for error-based, boolean-based, and time-based SQL injection vulnerabilities using AuthenticatedHttpClient.",
        "category": TaskCategory.EVIDENCE_CORRELATION,
        "required_inputs": ["endpoints"],
        "expected_outputs": ["vulnerabilities", "observations", "evidence"],
        "dependencies": ["Discover API Endpoints"],
        "required_specialists": [],
        "metadata": {"tool_id": "sql_injection"},
        "estimated_duration_minutes": 10,
        "priority": 0.81,
    },
    "xss": {
        "title": "Fuzz Cross-Site Scripting (XSS)",
        "goal": "Actively inject context-aware XSS payloads into discovered endpoint parameters and forms detecting reflected and stored XSS using AuthenticatedHttpClient.",
        "category": TaskCategory.EVIDENCE_CORRELATION,
        "required_inputs": ["endpoints"],
        "expected_outputs": ["vulnerabilities", "observations", "evidence"],
        "dependencies": ["Discover API Endpoints"],
        "required_specialists": [],
        "metadata": {"tool_id": "xss"},
        "estimated_duration_minutes": 10,
        "priority": 0.81,
    },
    "command_injection": {
        "title": "Fuzz OS Command Injection",
        "goal": "Actively fuzz discovered endpoint parameters and HTTP headers for result-based, time-based blind, and error-based OS command injection vulnerabilities using AuthenticatedHttpClient.",
        "category": TaskCategory.EVIDENCE_CORRELATION,
        "required_inputs": ["endpoints"],
        "expected_outputs": ["vulnerabilities", "observations", "evidence"],
        "dependencies": ["Discover API Endpoints"],
        "required_specialists": [],
        "metadata": {"tool_id": "command_injection"},
        "estimated_duration_minutes": 10,
        "priority": 0.81,
    },
    "ssrf": {
        "title": "Fuzz Server-Side Request Forgery (SSRF)",
        "goal": "Actively fuzz discovered endpoint parameters and HTTP headers for server-side request forgery, probing cloud metadata services, internal services, and blind differential timing using AuthenticatedHttpClient.",
        "category": TaskCategory.EVIDENCE_CORRELATION,
        "required_inputs": ["endpoints"],
        "expected_outputs": ["vulnerabilities", "observations", "evidence"],
        "dependencies": ["Discover API Endpoints"],
        "required_specialists": [],
        "metadata": {"tool_id": "ssrf"},
        "estimated_duration_minutes": 10,
        "priority": 0.81,
    },
    "oauth": {
        "title": "Analyze OAuth & OIDC Authentication",
        "goal": "Test OAuth/OIDC endpoints, token validation signatures/claims, and stateful session management using AuthenticatedHttpClient.",
        "category": TaskCategory.AUTHORIZATION_ANALYSIS,
        "required_inputs": ["endpoints"],
        "expected_outputs": ["vulnerabilities", "observations", "evidence"],
        "dependencies": ["Discover API Endpoints"],
        "required_specialists": [],
        "metadata": {"tool_id": "oauth"},
        "estimated_duration_minutes": 10,
        "priority": 0.81,
    },
}



# Specialist and fallback templates
_SPECIALIST_TEMPLATES = {
    TaskCategory.API_DISCOVERY: {
        "title": "Analyze API Endpoints",
        "goal": "Enumerate and analyze API endpoints for security issues.",
        "category": TaskCategory.API_DISCOVERY,
        "required_specialists": ["api_specialist"],
        "metadata": {"tool_id": "api_specialist"},
        "expected_outputs": ["api_inventory", "observations"],
        "dependencies": [],
        "estimated_duration_minutes": 10,
    },
    TaskCategory.GRAPHQL_ANALYSIS: {
        "title": "Analyze GraphQL Schema",
        "goal": "Introspect and analyze the GraphQL schema for vulnerabilities.",
        "category": TaskCategory.GRAPHQL_ANALYSIS,
        "required_specialists": ["graphql_specialist"],
        "metadata": {"tool_id": "graphql_specialist"},
        "expected_outputs": ["graphql_state", "observations"],
        "dependencies": [],
        "estimated_duration_minutes": 10,
    },
    TaskCategory.AUTHENTICATION_ANALYSIS: {
        "title": "Analyze Authentication Workflows",
        "goal": "Evaluate authentication mechanisms and session management.",
        "category": TaskCategory.AUTHENTICATION_ANALYSIS,
        "required_specialists": ["authentication_specialist"],
        "metadata": {"tool_id": "authentication_specialist"},
        "expected_outputs": ["authentication_state", "observations"],
        "dependencies": [],
        "estimated_duration_minutes": 10,
    },
    TaskCategory.AUTHORIZATION_ANALYSIS: {
        "title": "Analyze Authorization Relationships",
        "goal": "Build authorization graph and detect access control issues.",
        "category": TaskCategory.AUTHORIZATION_ANALYSIS,
        "required_specialists": ["authorization_specialist"],
        "metadata": {"tool_id": "authorization_specialist"},
        "expected_outputs": ["authorization_state", "observations"],
        "dependencies": ["Analyze Authentication Workflows"],
        "estimated_duration_minutes": 15,
    },
    TaskCategory.BUSINESS_LOGIC_ANALYSIS: {
        "title": "Analyze Business Logic Workflows",
        "goal": "Identify flaws in application-specific workflows.",
        "category": TaskCategory.BUSINESS_LOGIC_ANALYSIS,
        "required_specialists": ["business_logic_specialist"],
        "metadata": {"tool_id": "business_logic_specialist"},
        "expected_outputs": ["business_objects", "observations"],
        "dependencies": [],
        "estimated_duration_minutes": 15,
    },
    TaskCategory.JAVASCRIPT_ANALYSIS: {
        "title": "Analyze JavaScript Bundles",
        "goal": "Parse and analyze JavaScript bundles for secrets and endpoints.",
        "category": TaskCategory.JAVASCRIPT_ANALYSIS,
        "required_specialists": ["javascript_specialist"],
        "metadata": {"tool_id": "javascript_specialist"},
        "expected_outputs": ["javascript_state", "observations"],
        "dependencies": [],
        "estimated_duration_minutes": 10,
    },
    TaskCategory.EVIDENCE_CORRELATION: {
        "title": "Correlate Evidence",
        "goal": "Build correlations and evidence bundles from existing observations.",
        "category": TaskCategory.EVIDENCE_CORRELATION,
        "required_specialists": [],
        "metadata": {},
        "expected_outputs": ["Correlations", "Evidence Bundles"],
        "dependencies": [],
        "estimated_duration_minutes": 5,
    },
    TaskCategory.INVESTIGATION_REVIEW: {
        "title": "Review Pending Investigations",
        "goal": "Re-evaluate pending investigations with new evidence.",
        "category": TaskCategory.INVESTIGATION_REVIEW,
        "required_specialists": [],
        "metadata": {},
        "expected_outputs": ["Updated Investigations"],
        "dependencies": [],
        "estimated_duration_minutes": 5,
    },
    TaskCategory.COVERAGE_IMPROVEMENT: {
        "title": "Improve Coverage",
        "goal": "Fill coverage gaps identified by the coverage tracker.",
        "category": TaskCategory.COVERAGE_IMPROVEMENT,
        "required_specialists": [],
        "metadata": {},
        "expected_outputs": ["Additional Observations"],
        "dependencies": [],
        "estimated_duration_minutes": 10,
    },
}


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
            return _SPECIALIST_TEMPLATES[TaskCategory.AUTHENTICATION_ANALYSIS]

        if area_lower in ("authorization", "authorization graph"):
            if "oauth" in gap_desc_lower or "oidc" in gap_desc_lower or "jwt" in gap_desc_lower or "token" in gap_desc_lower:
                return _RECON_TEMPLATES["oauth"]
            return _SPECIALIST_TEMPLATES[TaskCategory.AUTHORIZATION_ANALYSIS]

        if area_lower in ("business logic", "business logic workflows"):
            return _SPECIALIST_TEMPLATES[TaskCategory.BUSINESS_LOGIC_ANALYSIS]

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
            if "oauth" in gap_desc_lower or "oidc" in gap_desc_lower or "jwt" in gap_desc_lower or "token" in gap_desc_lower or "session" in gap_desc_lower:
                return _RECON_TEMPLATES["oauth"]
            return _SPECIALIST_TEMPLATES[TaskCategory.AUTHENTICATION_ANALYSIS]

        if gap.category == TaskCategory.AUTHORIZATION_ANALYSIS:
            if "oauth" in gap_desc_lower or "oidc" in gap_desc_lower or "jwt" in gap_desc_lower or "token" in gap_desc_lower:
                return _RECON_TEMPLATES["oauth"]
            if "idor" in gap_desc_lower or "access control" in gap_desc_lower or "escalation" in gap_desc_lower or "bypass" in gap_desc_lower:
                return _RECON_TEMPLATES["access_control"]
            return _SPECIALIST_TEMPLATES[TaskCategory.AUTHORIZATION_ANALYSIS]

        if gap.category == TaskCategory.EVIDENCE_CORRELATION:
            if "oauth" in gap_desc_lower or "oidc" in gap_desc_lower or "jwt" in gap_desc_lower or "token" in gap_desc_lower:
                return _RECON_TEMPLATES["oauth"]
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
                elif tool_id in ("katana_crawler", "nuclei", "info_disclosure", "access_control", "path_traversal", "sql_injection", "xss", "command_injection", "ssrf", "oauth"):
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
