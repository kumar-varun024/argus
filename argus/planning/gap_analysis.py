"""
Gap Analysis Engine.

Continuously inspects the mission state to identify areas where information
is missing or incomplete, and recommends research tasks to fill those gaps.
"""
from typing import List, Any
from argus.planning.models import CoverageGap, TaskCategory


class GapAnalyzer:
    """Identifies missing information in the current mission state."""

    def __init__(self, mission: Any):
        self.mission = mission

    def analyze(self) -> List[CoverageGap]:
        """Run all gap detection heuristics and return discovered gaps."""
        gaps: List[CoverageGap] = []
        gaps.extend(self._check_technology_gaps())
        gaps.extend(self._check_api_gaps())
        gaps.extend(self._check_graphql_gaps())
        gaps.extend(self._check_authentication_gaps())
        gaps.extend(self._check_authorization_gaps())
        gaps.extend(self._check_business_logic_gaps())
        gaps.extend(self._check_javascript_gaps())
        gaps.extend(self._check_correlation_gaps())
        return gaps

    def _check_technology_gaps(self) -> List[CoverageGap]:
        gaps = []
        technologies = getattr(self.mission, 'technologies', [])
        if not technologies:
            gaps.append(CoverageGap(
                area="Technologies",
                description="No technologies have been fingerprinted for this mission.",
                severity=0.9,
                category=TaskCategory.TECHNOLOGY_DISCOVERY
            ))
        return gaps

    def _check_api_gaps(self) -> List[CoverageGap]:
        gaps = []
        endpoints = getattr(self.mission, 'endpoints', [])
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
                    related_assets=[str(e.get('url', e)) if isinstance(e, dict) else str(e) for e in endpoints[:10]]
                ))
        return gaps

    def _check_graphql_gaps(self) -> List[CoverageGap]:
        gaps = []
        technologies = set(t.lower() for t in getattr(self.mission, 'technologies', []))
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
        auth_workflows = getattr(self.mission, 'authentication_workflows', [])
        
        if auth is not None and not auth_workflows:
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
        auth_investigations = getattr(self.mission, 'authorization_investigations', [])
        
        if auth_graph is None and not auth_investigations:
            gaps.append(CoverageGap(
                area="Authorization",
                description="No authorization graph or authorization investigations have been generated.",
                severity=0.6,
                category=TaskCategory.AUTHORIZATION_ANALYSIS
            ))
        return gaps

    def _check_business_logic_gaps(self) -> List[CoverageGap]:
        gaps = []
        workflows = getattr(self.mission, 'workflows', [])
        bl = getattr(self.mission, 'business_logic', [])
        
        if workflows and not bl:
            gaps.append(CoverageGap(
                area="Business Logic",
                description=f"{len(workflows)} workflows discovered but no business logic analysis performed.",
                severity=0.6,
                category=TaskCategory.BUSINESS_LOGIC_ANALYSIS,
                related_assets=[str(w) for w in workflows[:5]]
            ))
        return gaps

    def _check_javascript_gaps(self) -> List[CoverageGap]:
        gaps = []
        technologies = set(t.lower() for t in getattr(self.mission, 'technologies', []))
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
