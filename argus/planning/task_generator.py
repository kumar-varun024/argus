"""
Task Generator.

Converts coverage gaps and mission context into concrete, dependency-aware ResearchTask objects.
Each task describes a recommended action for the runtime with explicit metadata.tool_id routing.
Never executes anything itself.
"""
from typing import List, Any, Dict
from argus.planning.models import ResearchTask, CoverageGap, TaskCategory  # TaskCategory: re-exported, several tests import it from here

# Task templates live in argus.planning.templates (single source of truth,
# shared with argus.scanning.dag). Imported here under their historical name.
from argus.planning.templates import _RECON_TEMPLATES

# Gap-resolution rule table: extracted as data since rule order is
# semantically load-bearing (see gapTemplateRules module docstring).
from argus.planning.gapTemplateRules import resolveTemplateForGap


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
        """Resolve the appropriate task template for a given CoverageGap.

        The area/keyword rule table lives in argus.planning.gapTemplateRules
        (data, not code) since rule order there is semantically load-bearing --
        see that module's docstring.
        """
        return resolveTemplateForGap(self, gap)

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
