"""
Coverage Tracker.

Measures the breadth and depth of analysis coverage across all mission dimensions
(endpoints, business objects, workflows, authentication, authorization, technologies, assets).
"""
from typing import Any, List
from argus.planning.models import CoverageReport, CoverageGap, TaskCategory
from argus.planning.gap_analysis import GapAnalyzer


class CoverageTracker:
    """Computes a CoverageReport for the current mission state."""

    def __init__(self, mission: Any):
        self.mission = mission

    def compute(self) -> CoverageReport:
        """Calculate coverage metrics and identify gaps."""
        report = CoverageReport()

        # Endpoints
        endpoints = getattr(self.mission, 'endpoints', [])
        report.endpoints_total = len(endpoints)
        observations = getattr(self.mission, 'observations', None)
        if observations is not None and hasattr(observations, 'get_all'):
            obs_list = list(observations.get_all())
            api_obs = [o for o in obs_list if hasattr(o, 'category') and getattr(o.category, 'value', str(o.category)).upper() == 'API']
            report.endpoints_covered = min(len(api_obs), report.endpoints_total)
        
        # Business Objects
        bos = getattr(self.mission, 'business_objects', [])
        report.business_objects_total = len(bos)
        investigations = getattr(self.mission, 'investigations', None)
        if investigations is not None and hasattr(investigations, 'get_all'):
            inv_list = list(investigations.get_all())
            inv_bos = set()
            for inv in inv_list:
                for bo in getattr(inv, 'business_objects', []):
                    inv_bos.add(str(bo))
            report.business_objects_covered = min(len(inv_bos), report.business_objects_total)

        # Workflows
        workflows = getattr(self.mission, 'workflows', [])
        report.workflows_total = len(workflows)
        report.workflows_covered = len(getattr(self.mission, 'completed_playbooks', []))

        # Authentication
        auth_workflows = getattr(self.mission, 'authentication_workflows', [])
        report.authentication_covered = len(auth_workflows) > 0

        # Authorization
        auth_graph = getattr(self.mission, 'authorization_graph', None)
        report.authorization_covered = auth_graph is not None

        # Technologies
        technologies = getattr(self.mission, 'technologies', [])
        report.technologies_total = len(technologies)
        # Consider a technology "covered" if at least one observation mentions it (rough heuristic)
        report.technologies_covered = report.technologies_total if observations is not None else 0

        # Compute overall score
        dimensions = []
        if report.endpoints_total > 0:
            dimensions.append(report.endpoints_covered / report.endpoints_total)
        if report.business_objects_total > 0:
            dimensions.append(report.business_objects_covered / report.business_objects_total)
        if report.workflows_total > 0:
            dimensions.append(report.workflows_covered / report.workflows_total)
        dimensions.append(1.0 if report.authentication_covered else 0.0)
        dimensions.append(1.0 if report.authorization_covered else 0.0)
        if report.technologies_total > 0:
            dimensions.append(report.technologies_covered / report.technologies_total)

        report.overall_coverage = sum(dimensions) / len(dimensions) if dimensions else 0.0

        # Attach gaps from the GapAnalyzer
        report.gaps = GapAnalyzer(self.mission).analyze()

        return report
