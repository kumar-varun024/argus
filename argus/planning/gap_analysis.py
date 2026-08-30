"""
Gap Analysis Engine.

Continuously inspects the mission state to identify areas where information
is missing or incomplete, distinguishing between distinct recon states
(subdomains, live hosts, endpoints, vulnerability scanning) as well as
higher-level analysis gaps (APIs, GraphQL, Auth, Authz, BL, JS, Correlation).
"""
from typing import List, Any
from argus.planning.models import CoverageGap, TaskCategory


def _extract_tech_names(technologies: Any) -> set:
    if not technologies:
        return set()
    names = set()
    for t in technologies:
        if t is None:
            continue
        if isinstance(t, str):
            names.add(t.lower())
        elif isinstance(t, dict):
            val = t.get("name") or t.get("technology") or t.get("tech") or t.get("value")
            if val:
                names.add(str(val).lower())
        else:
            names.add(str(t).lower())
    return names


class GapAnalyzer:
    """Identifies missing information in the current mission state."""

    def __init__(self, mission: Any):
        self.mission = mission

    def analyze(self) -> List[CoverageGap]:
        """Run all gap detection heuristics and return discovered gaps."""
        gaps: List[CoverageGap] = []
        gaps.extend(self._check_recon_gaps())
        gaps.extend(self._check_technology_gaps())
        gaps.extend(self._check_api_gaps())
        gaps.extend(self._check_graphql_gaps())
        gaps.extend(self._check_authentication_gaps())
        gaps.extend(self._check_authorization_gaps())
        gaps.extend(self._check_business_logic_gaps())
        gaps.extend(self._check_javascript_gaps())
        gaps.extend(self._check_correlation_gaps())
        return gaps

    def _check_recon_gaps(self) -> List[CoverageGap]:
        """
        Inspects recon state and returns gaps for missing recon phases:
        1. No subdomains -> Subdomain discovery gap (subfinder)
        2. Subdomains present, no live hosts -> Live host detection gap (httpx)
        3. Live hosts present, no endpoints -> Endpoint crawling gap (katana)
        4. Live hosts present, no vuln scan -> Vulnerability scanning gap (nuclei)
        """
        gaps = []
        subdomains = list(getattr(self.mission, 'subdomains', []) or [])
        live_hosts = list(getattr(self.mission, 'live_hosts', []) or [])
        endpoints = list(getattr(self.mission, 'endpoints', []) or [])
        target = str(getattr(self.mission, 'target', '') or '')

        # Check evidence store if present
        if not subdomains and hasattr(self.mission, 'evidence') and self.mission.evidence and hasattr(self.mission.evidence, 'all'):
            try:
                subdomains = [e.value for e in self.mission.evidence.all() if getattr(e, 'category', None) == 'subdomain']
            except Exception:
                pass
        if not live_hosts and hasattr(self.mission, 'evidence') and self.mission.evidence and hasattr(self.mission.evidence, 'all'):
            try:
                live_hosts = [e.value for e in self.mission.evidence.all() if getattr(e, 'category', None) == 'live_host']
            except Exception:
                pass
        if not endpoints and hasattr(self.mission, 'evidence') and self.mission.evidence and hasattr(self.mission.evidence, 'all'):
            try:
                endpoints = [e.value for e in self.mission.evidence.all() if getattr(e, 'category', None) == 'endpoint']
            except Exception:
                pass

        # Check attack surface graph
        graph = getattr(self.mission, 'attack_surface_graph', None) or getattr(self.mission, 'graph', None)
        graph_live_hosts = []
        if graph and hasattr(graph, 'nodes_by_type') and hasattr(graph, 'get_hosts_without_endpoints'):
            graph_live_hosts = graph.nodes_by_type("live_host")

        # If no live hosts yet:
        if not live_hosts and not graph_live_hosts:
            if not subdomains:
                # State 1: No subdomains
                gaps.append(CoverageGap(
                    area="Subdomains",
                    description="No subdomains have been discovered for this mission.",
                    severity=0.95,
                    category=TaskCategory.TECHNOLOGY_DISCOVERY,
                    related_assets=[target] if target else []
                ))
            else:
                # State 2: Subdomains exist, but no live hosts
                gaps.append(CoverageGap(
                    area="Live Hosts",
                    description="Subdomains discovered but no live hosts have been fingerprinted.",
                    severity=0.9,
                    category=TaskCategory.TECHNOLOGY_DISCOVERY,
                    related_assets=[str(s) for s in subdomains[:10] if s is not None]
                ))
        else:
            if graph_live_hosts:
                # State 3: Check graph for hosts without endpoints
                uncrawled = graph.get_hosts_without_endpoints()
                if uncrawled:
                    gaps.append(CoverageGap(
                        area="Endpoints",
                        description="Live hosts fingerprinted but no endpoints crawled.",
                        severity=0.85,
                        category=TaskCategory.API_DISCOVERY,
                        related_assets=[str(n.value) for n in uncrawled[:10]]
                    ))

                # State 4: Check graph for hosts without vulnerabilities
                if not self._has_vulnerability_scan():
                    unscanned = graph.get_hosts_without_vulnerabilities()
                    vuln_assets = [str(n.value) for n in unscanned[:10]] if unscanned else [str(n.value) for n in graph_live_hosts[:10]]
                    gaps.append(CoverageGap(
                        area="Vulnerability Scanning",
                        description="Live hosts discovered but vulnerability scan has not been performed.",
                        severity=0.8,
                        category=TaskCategory.EVIDENCE_CORRELATION,
                        related_assets=vuln_assets
                    ))

                # State 5: Check graph for information disclosure scan
                if not self._has_information_disclosure_scan():
                    host_assets = [str(n.value) for n in graph_live_hosts[:10]]
                    gaps.append(CoverageGap(
                        area="Information Disclosure",
                        description="Live hosts discovered but sensitive files and information disclosure probing has not been performed.",
                        severity=0.82,
                        category=TaskCategory.EVIDENCE_CORRELATION,
                        related_assets=host_assets
                    ))
            else:
                # Fallback to bare mission lists
                host_assets = [str(h.get('url', h)) if isinstance(h, dict) else str(h) for h in live_hosts[:10] if h is not None]

                # State 3: Live hosts exist, but no endpoints crawled
                if not endpoints:
                    gaps.append(CoverageGap(
                        area="Endpoints",
                        description="Live hosts fingerprinted but no endpoints crawled.",
                        severity=0.85,
                        category=TaskCategory.API_DISCOVERY,
                        related_assets=host_assets
                    ))

                # State 4: Live hosts exist, but vulnerability scan not performed
                if not self._has_vulnerability_scan():
                    gaps.append(CoverageGap(
                        area="Vulnerability Scanning",
                        description="Live hosts discovered but vulnerability scan has not been performed.",
                        severity=0.8,
                        category=TaskCategory.EVIDENCE_CORRELATION,
                        related_assets=host_assets
                    ))

                # State 5: Live hosts exist, but information disclosure scan not performed
                if not self._has_information_disclosure_scan():
                    gaps.append(CoverageGap(
                        area="Information Disclosure",
                        description="Live hosts discovered but sensitive files and information disclosure probing has not been performed.",
                        severity=0.82,
                        category=TaskCategory.EVIDENCE_CORRELATION,
                        related_assets=host_assets
                    ))

        return gaps

    def _has_information_disclosure_scan(self) -> bool:
        """Check if information disclosure probing has already been performed or scheduled."""
        # 1. Mission vulnerabilities list with information disclosure
        vulns = getattr(self.mission, 'vulnerabilities', None)
        if vulns and isinstance(vulns, list):
            for v in vulns:
                if isinstance(v, dict):
                    t_id = str(v.get('template_id', '')).lower()
                    name = str(v.get('name', '')).lower()
                    if "info-disclosure" in t_id or "information disclosure" in name:
                        return True

        # 2. Evidence in evidence store
        if hasattr(self.mission, 'evidence') and self.mission.evidence and hasattr(self.mission.evidence, 'all'):
            try:
                for ev in self.mission.evidence.all():
                    if getattr(ev, 'category', None) == 'information_disclosure':
                        return True
            except Exception:
                pass

        # 3. Check tool runs
        if hasattr(self.mission, 'tool_runs') and isinstance(self.mission.tool_runs, dict):
            for run_task_id, run_info in self.mission.tool_runs.items():
                if isinstance(run_info, dict):
                    tool_id = run_info.get('tool_id')
                    status = str(run_info.get('status', '')).upper()
                    if tool_id in ('info_disclosure', 'information_disclosure') and status in ('COMPLETED', 'RUNNING', 'SCHEDULED', 'SUCCESS', 'SUCCEEDED'):
                        return True

        # 4. Check execution history
        if hasattr(self.mission, 'execution_history') and self.mission.execution_history:
            for entry in self.mission.execution_history:
                if isinstance(entry, dict):
                    if entry.get('tool_id') in ('info_disclosure', 'information_disclosure') or entry.get('task_title') == 'Probe Information Disclosure':
                        return True
                    details = entry.get('details', {})
                    if isinstance(details, dict) and (details.get('tool_id') in ('info_disclosure', 'information_disclosure') or details.get('task_title') == 'Probe Information Disclosure'):
                        return True
                elif hasattr(entry, 'details') and isinstance(entry.details, dict):
                    if entry.details.get('tool_id') in ('info_disclosure', 'information_disclosure') or entry.details.get('task_title') == 'Probe Information Disclosure':
                        return True

        # 5. Check completed/running/scheduled tasks
        if hasattr(self.mission, 'research_tasks') and self.mission.research_tasks:
            for t in self.mission.research_tasks:
                metadata = getattr(t, 'metadata', {}) or {}
                tool_id = metadata.get('tool_id') if isinstance(metadata, dict) else None
                title = getattr(t, 'title', '')
                if tool_id in ('info_disclosure', 'information_disclosure') or title == 'Probe Information Disclosure':
                    status = str(getattr(t, 'status', '')).upper()
                    if status in ('COMPLETED', 'RUNNING', 'SCHEDULED', 'SUCCESS', 'SUCCEEDED'):
                        return True

        # 6. Check task states mapping
        if hasattr(self.mission, 'task_states') and self.mission.task_states:
            for task_id, state in self.mission.task_states.items():
                state_str = str(state).upper() if state else ''
                if state_str in ('COMPLETED', 'RUNNING', 'SCHEDULED', 'SUCCESS', 'SUCCEEDED'):
                    if hasattr(self.mission, 'research_tasks') and self.mission.research_tasks:
                        for t in self.mission.research_tasks:
                            if getattr(t, 'id', None) == task_id:
                                metadata = getattr(t, 'metadata', {}) or {}
                                tool_id = metadata.get('tool_id') if isinstance(metadata, dict) else None
                                title = getattr(t, 'title', '')
                                if tool_id in ('info_disclosure', 'information_disclosure') or title == 'Probe Information Disclosure':
                                    return True

        return False


    def _has_vulnerability_scan(self) -> bool:
        """Check if vulnerability scanning has already been performed or scheduled."""
        # 1. Mission vulnerabilities list
        vulns = getattr(self.mission, 'vulnerabilities', None)
        if vulns and len(vulns) > 0:
            return True

        # 2. Vulnerability evidence in evidence store
        if hasattr(self.mission, 'evidence') and self.mission.evidence and hasattr(self.mission.evidence, 'all'):
            try:
                for ev in self.mission.evidence.all():
                    if getattr(ev, 'category', None) == 'vulnerability' or getattr(ev, 'source', None) == 'nuclei':
                        return True
            except Exception:
                pass

        # 3. Check tool runs
        if hasattr(self.mission, 'tool_runs') and isinstance(self.mission.tool_runs, dict):
            for run_task_id, run_info in self.mission.tool_runs.items():
                if isinstance(run_info, dict):
                    tool_id = run_info.get('tool_id')
                    status = str(run_info.get('status', '')).upper()
                    if tool_id == 'nuclei' and status in ('COMPLETED', 'RUNNING', 'SCHEDULED', 'SUCCESS', 'SUCCEEDED'):
                        return True

        # 4. Check execution history
        if hasattr(self.mission, 'execution_history') and self.mission.execution_history:
            for entry in self.mission.execution_history:
                if isinstance(entry, dict):
                    if entry.get('tool_id') == 'nuclei' or entry.get('task_title') == 'Scan Live Hosts':
                        return True
                    details = entry.get('details', {})
                    if isinstance(details, dict) and (details.get('tool_id') == 'nuclei' or details.get('task_title') == 'Scan Live Hosts'):
                        return True
                elif hasattr(entry, 'details') and isinstance(entry.details, dict):
                    if entry.details.get('tool_id') == 'nuclei' or entry.details.get('task_title') == 'Scan Live Hosts':
                        return True

        # 5. Check completed/running/scheduled tasks
        if hasattr(self.mission, 'research_tasks') and self.mission.research_tasks:
            for t in self.mission.research_tasks:
                metadata = getattr(t, 'metadata', {}) or {}
                tool_id = metadata.get('tool_id') if isinstance(metadata, dict) else None
                title = getattr(t, 'title', '')
                if tool_id == 'nuclei' or title == 'Scan Live Hosts':
                    status = str(getattr(t, 'status', '')).upper()
                    if status in ('COMPLETED', 'RUNNING', 'SCHEDULED', 'SUCCESS', 'SUCCEEDED'):
                        return True

        # 6. Check task states mapping
        if hasattr(self.mission, 'task_states') and self.mission.task_states:
            for task_id, state in self.mission.task_states.items():
                state_str = str(state).upper() if state else ''
                if state_str in ('COMPLETED', 'RUNNING', 'SCHEDULED', 'SUCCESS', 'SUCCEEDED'):
                    if hasattr(self.mission, 'research_tasks') and self.mission.research_tasks:
                        for t in self.mission.research_tasks:
                            if getattr(t, 'id', None) == task_id:
                                metadata = getattr(t, 'metadata', {}) or {}
                                tool_id = metadata.get('tool_id') if isinstance(metadata, dict) else None
                                title = getattr(t, 'title', '')
                                if tool_id == 'nuclei' or title == 'Scan Live Hosts':
                                    return True

        return False

    def _check_technology_gaps(self) -> List[CoverageGap]:
        gaps = []
        technologies = list(getattr(self.mission, 'technologies', []) or [])
        if not technologies or not _extract_tech_names(technologies):
            gaps.append(CoverageGap(
                area="Technologies",
                description="No technologies have been fingerprinted for this mission.",
                severity=0.9,
                category=TaskCategory.TECHNOLOGY_DISCOVERY
            ))
        return gaps

    def _check_api_gaps(self) -> List[CoverageGap]:
        gaps = []
        endpoints = list(getattr(self.mission, 'endpoints', []) or [])
        observations = getattr(self.mission, 'observations', None)

        # If we have endpoints but no observations about them, flag a gap
        if endpoints and observations is not None:
            obs_list = list(observations.get_all()) if hasattr(observations, 'get_all') else []
            api_obs = [o for o in obs_list if hasattr(o, 'category') and getattr(o.category, 'value', str(o.category)).upper() == 'API']
            if len(api_obs) < len(endpoints):
                gaps.append(CoverageGap(
                    area="API Endpoints",
                    description=f"{len(endpoints)} endpoints discovered but only {len(api_obs)} analyzed.",
                    severity=0.7,
                    category=TaskCategory.API_DISCOVERY,
                    related_assets=[str(e.get('url', e)) if isinstance(e, dict) else str(e) for e in endpoints[:10] if e is not None]
                ))
        return gaps

    def _check_graphql_gaps(self) -> List[CoverageGap]:
        gaps = []
        technologies = _extract_tech_names(getattr(self.mission, 'technologies', []))
        graphql_state = getattr(self.mission, 'graphql', None)

        if 'graphql' in technologies:
            if graphql_state is None or not getattr(graphql_state, 'schemas', []):
                gaps.append(CoverageGap(
                    area="GraphQL Schema",
                    description="GraphQL technology detected but schema has not been analyzed.",
                    severity=0.8,
                    category=TaskCategory.GRAPHQL_ANALYSIS
                ))
        return gaps

    def _check_authentication_gaps(self) -> List[CoverageGap]:
        gaps = []
        auth = getattr(self.mission, 'authentication', None)
        auth_workflows = list(getattr(self.mission, 'authentication_workflows', []) or [])

        # Only emit gap if auth model is meaningfully populated (confidence > 0 or observations present)
        is_populated_auth = False
        if auth is not None:
            conf = getattr(auth, 'confidence', 0) or 0
            obs = getattr(auth, 'observations', []) or []
            if conf > 0 or len(obs) > 0:
                is_populated_auth = True
            elif isinstance(auth, dict) and (auth.get('confidence', 0) > 0 or len(auth.get('observations', [])) > 0):
                is_populated_auth = True

        if is_populated_auth and not auth_workflows:
            gaps.append(CoverageGap(
                area="Authentication Workflows",
                description="Authentication model exists but no authentication workflows have been analyzed.",
                severity=0.7,
                category=TaskCategory.AUTHENTICATION_ANALYSIS
            ))
        return gaps

    def _check_authorization_gaps(self) -> List[CoverageGap]:
        gaps = []
        auth_graph = getattr(self.mission, 'authorization_graph', None)
        auth_investigations = list(getattr(self.mission, 'authorization_investigations', []) or [])
        auth_workflows = list(getattr(self.mission, 'authentication_workflows', []) or [])

        # Only emit authorization gap if authentication workflows or authorization structures exist
        has_auth_context = bool(auth_workflows) or (auth_graph is not None)
        if has_auth_context and auth_graph is None and not auth_investigations:
            gaps.append(CoverageGap(
                area="Authorization",
                description="No authorization graph or authorization investigations have been generated.",
                severity=0.6,
                category=TaskCategory.AUTHORIZATION_ANALYSIS
            ))
        return gaps

    def _check_business_logic_gaps(self) -> List[CoverageGap]:
        gaps = []
        workflows = list(getattr(self.mission, 'workflows', []) or [])
        bl = list(getattr(self.mission, 'business_logic', []) or [])

        if workflows and not bl:
            gaps.append(CoverageGap(
                area="Business Logic",
                description=f"{len(workflows)} workflows discovered but no business logic analysis performed.",
                severity=0.6,
                category=TaskCategory.BUSINESS_LOGIC_ANALYSIS,
                related_assets=[str(w) for w in workflows[:5] if w is not None]
            ))
        return gaps

    def _check_javascript_gaps(self) -> List[CoverageGap]:
        gaps = []
        technologies = _extract_tech_names(getattr(self.mission, 'technologies', []))
        js_state = getattr(self.mission, 'javascript', None)

        js_techs = {'react', 'angular', 'vue', 'next.js', 'nuxt', 'svelte', 'javascript'}
        if technologies & js_techs:
            if js_state is None or not getattr(js_state, 'files', []):
                gaps.append(CoverageGap(
                    area="JavaScript Analysis",
                    description="JavaScript framework detected but no JS bundles have been analyzed.",
                    severity=0.5,
                    category=TaskCategory.JAVASCRIPT_ANALYSIS
                ))
        return gaps

    def _check_correlation_gaps(self) -> List[CoverageGap]:
        gaps = []
        observations = getattr(self.mission, 'observations', None)
        correlations = getattr(self.mission, 'correlations', None)

        if observations is not None and correlations is not None:
            obs_count = len(list(observations.get_all())) if hasattr(observations, 'get_all') else 0
            corr_count = len(list(correlations.get_all())) if hasattr(correlations, 'get_all') else 0

            if obs_count > 0 and corr_count == 0:
                gaps.append(CoverageGap(
                    area="Evidence Correlation",
                    description=f"{obs_count} observations exist but no correlations have been built.",
                    severity=0.8,
                    category=TaskCategory.EVIDENCE_CORRELATION
                ))
        return gaps
