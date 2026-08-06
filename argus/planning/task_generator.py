"""
Task Generator.

Converts coverage gaps and mission context into concrete ResearchTask objects.
Each task describes a recommended action for the runtime — never executes anything itself.
"""
from typing import List, Any
from argus.planning.models import ResearchTask, CoverageGap, TaskCategory


# Maps gap categories to task templates
_TASK_TEMPLATES = {
    TaskCategory.TECHNOLOGY_DISCOVERY: {
        "title": "Discover Technologies",
        "goal": "Fingerprint all technologies in scope.",
        "required_specialists": ["ReconAgent"],
        "expected_outputs": ["Technologies", "Frameworks"],
        "estimated_duration_minutes": 5,
    },
    TaskCategory.API_DISCOVERY: {
        "title": "Analyze API Endpoints",
        "goal": "Enumerate and analyze API endpoints for security issues.",
        "required_specialists": ["APISpecialist"],
        "expected_outputs": ["API Observations", "API Inventory"],
        "estimated_duration_minutes": 10,
    },
    TaskCategory.GRAPHQL_ANALYSIS: {
        "title": "Analyze GraphQL Schema",
        "goal": "Introspect and analyze the GraphQL schema for vulnerabilities.",
        "required_specialists": ["GraphQLSpecialist"],
        "expected_outputs": ["GraphQL Schema", "GraphQL Observations"],
        "estimated_duration_minutes": 10,
    },
    TaskCategory.AUTHENTICATION_ANALYSIS: {
        "title": "Analyze Authentication Workflows",
        "goal": "Evaluate authentication mechanisms and session management.",
        "required_specialists": ["AuthenticationSpecialist"],
        "expected_outputs": ["Authentication Context", "Session Analysis"],
        "estimated_duration_minutes": 10,
    },
    TaskCategory.AUTHORIZATION_ANALYSIS: {
        "title": "Analyze Authorization Relationships",
        "goal": "Build authorization graph and detect access control issues.",
        "required_specialists": ["AuthorizationSpecialist"],
        "expected_outputs": ["Authorization Graph", "Access Control Matrix"],
        "dependencies": ["Analyze Authentication Workflows"],
        "estimated_duration_minutes": 15,
    },
    TaskCategory.BUSINESS_LOGIC_ANALYSIS: {
        "title": "Analyze Business Logic Workflows",
        "goal": "Identify flaws in application-specific workflows.",
        "required_specialists": ["BusinessLogicSpecialist"],
        "expected_outputs": ["Business Logic Flaws", "Workflow Graph"],
        "estimated_duration_minutes": 15,
    },
    TaskCategory.JAVASCRIPT_ANALYSIS: {
        "title": "Analyze JavaScript Bundles",
        "goal": "Parse and analyze JavaScript bundles for secrets and endpoints.",
        "required_specialists": ["JavaScriptSpecialist"],
        "expected_outputs": ["JS Observations", "Endpoints from JS"],
        "estimated_duration_minutes": 10,
    },
    TaskCategory.EVIDENCE_CORRELATION: {
        "title": "Correlate Evidence",
        "goal": "Build correlations and evidence bundles from existing observations.",
        "required_specialists": [],
        "expected_outputs": ["Correlations", "Evidence Bundles"],
        "estimated_duration_minutes": 5,
    },
    TaskCategory.INVESTIGATION_REVIEW: {
        "title": "Review Pending Investigations",
        "goal": "Re-evaluate pending investigations with new evidence.",
        "required_specialists": [],
        "expected_outputs": ["Updated Investigations"],
        "estimated_duration_minutes": 5,
    },
    TaskCategory.COVERAGE_IMPROVEMENT: {
        "title": "Improve Coverage",
        "goal": "Fill coverage gaps identified by the coverage tracker.",
        "required_specialists": [],
        "expected_outputs": ["Additional Observations"],
        "estimated_duration_minutes": 10,
    },
}


class TaskGenerator:
    """Generates ResearchTask objects from coverage gaps and mission context."""

    def __init__(self, mission: Any):
        self.mission = mission

    def from_gaps(self, gaps: List[CoverageGap]) -> List[ResearchTask]:
        """Convert a list of CoverageGaps into ResearchTasks."""
        tasks: List[ResearchTask] = []
        seen_categories = set()

        for gap in gaps:
            # Avoid duplicating tasks for the same category
            if gap.category in seen_categories:
                continue
            seen_categories.add(gap.category)

            template = _TASK_TEMPLATES.get(gap.category, _TASK_TEMPLATES[TaskCategory.COVERAGE_IMPROVEMENT])
            task = ResearchTask(
                title=template["title"],
                description=gap.description,
                goal=template["goal"],
                category=gap.category,
                required_inputs=gap.related_assets,
                expected_outputs=template.get("expected_outputs", []),
                priority=gap.severity,
                confidence=0.8,
                dependencies=template.get("dependencies", []),
                required_specialists=template.get("required_specialists", []),
                estimated_duration_minutes=template.get("estimated_duration_minutes", 5),
                reason=f"Gap detected: {gap.description}",
                supporting_evidence=gap.related_assets,
            )
            tasks.append(task)

        return tasks
