from argus.planning.models import PlanStep

def build_discover_technologies_step() -> PlanStep:
    return PlanStep(
        name="Discover Technologies",
        description="Identify underlying technologies and frameworks.",
        outputs=["Technologies", "Frameworks"],
        expected_artifacts=["Technology Fingerprints"]
    )

def build_discover_apis_step() -> PlanStep:
    return PlanStep(
        name="Discover APIs",
        description="Enumerate API endpoints and parameters.",
        dependencies=["Discover Technologies"],
        outputs=["API Endpoints"],
        expected_artifacts=["API Inventory"]
    )

def build_discover_graphql_step() -> PlanStep:
    return PlanStep(
        name="Discover GraphQL",
        description="Identify and introspect GraphQL schemas.",
        dependencies=["Discover Technologies"],
        outputs=["GraphQL Schemas", "GraphQL Operations"],
        expected_artifacts=["Schema Definition"],
        specialist_assigned="GraphQLSpecialist"
    )

def build_analyze_authentication_step() -> PlanStep:
    return PlanStep(
        name="Analyze Authentication",
        description="Evaluate authentication mechanisms and flows.",
        dependencies=["Discover APIs"],
        outputs=["Authentication Context"],
        expected_artifacts=["Session Analysis"]
    )

def build_analyze_authorization_step() -> PlanStep:
    return PlanStep(
        name="Analyze Authorization",
        description="Check for broken access control and privilege escalation.",
        dependencies=["Analyze Authentication", "Discover APIs", "Discover GraphQL"],
        outputs=["Authorization Context"],
        expected_artifacts=["Access Control Matrix"]
    )

def build_analyze_business_logic_step() -> PlanStep:
    return PlanStep(
        name="Analyze Business Logic",
        description="Identify flaws in application specific workflows.",
        dependencies=["Analyze Authorization", "Discover APIs"],
        outputs=["Business Logic Flaws"],
        expected_artifacts=["Workflow Graph"],
        specialist_assigned="BusinessLogicSpecialist"
    )

def build_correlate_evidence_step() -> PlanStep:
    return PlanStep(
        name="Correlate Evidence",
        description="Correlate observations into evidence bundles.",
        dependencies=["Analyze Authorization", "Analyze Business Logic"],
        outputs=["Evidence Bundles", "Correlations"],
        expected_artifacts=["Correlation Graph"]
    )

def build_generate_investigations_step() -> PlanStep:
    return PlanStep(
        name="Generate Investigations",
        description="Create actionable investigations from evidence.",
        dependencies=["Correlate Evidence"],
        outputs=["Investigations"],
        expected_artifacts=["Investigation Reports"]
    )

def build_prioritize_step() -> PlanStep:
    return PlanStep(
        name="Prioritize",
        description="Score and prioritize generated investigations.",
        dependencies=["Generate Investigations"],
        outputs=["Priority Scores"],
        expected_artifacts=["Ranked Queue"]
    )

def build_explain_step() -> PlanStep:
    return PlanStep(
        name="Explain",
        description="Generate evidence-backed explanations for investigations.",
        dependencies=["Prioritize"],
        outputs=["Explanations", "Reasoning Chains"],
        expected_artifacts=["Explanation Graph"]
    )

def build_probe_information_disclosure_step() -> PlanStep:
    return PlanStep(
        name="Probe Information Disclosure",
        description="Probe live hosts and endpoints for exposed sensitive files and secrets.",
        dependencies=["Discover APIs"],
        outputs=["Information Disclosure Findings", "Exposed Secrets"],
        expected_artifacts=["Information Disclosure Inventory"]
    )

ALL_STEPS_BUILDERS = [
    build_discover_technologies_step,
    build_discover_apis_step,
    build_discover_graphql_step,
    build_probe_information_disclosure_step,
    build_analyze_authentication_step,
    build_analyze_authorization_step,
    build_analyze_business_logic_step,
    build_correlate_evidence_step,
    build_generate_investigations_step,
    build_prioritize_step,
    build_explain_step
]

