from argus.methodology.models import Playbook, PlaybookStep

def get_default_playbooks() -> list[Playbook]:
    """Returns the default set of Playbooks built into Argus."""
    return [
        Playbook(
            id="pb_authz_review",
            name="Authorization Review",
            category="Authorization",
            description="Methodical review of authorization controls and boundaries.",
            steps=[
                PlaybookStep(
                    id="step_authz_1",
                    title="Map Roles",
                    description="Identify all roles and permissions within the application.",
                    expected_results=["Complete role matrix"]
                ),
                PlaybookStep(
                    id="step_authz_2",
                    title="Test Vertical Privilege Escalation",
                    description="Attempt to access administrative functions from a standard user role.",
                    required_workflows=["Admin Functions"],
                    expected_results=["Confirmed vertical boundaries"]
                )
            ]
        ),
        Playbook(
            id="pb_business_logic",
            name="Business Logic Review",
            category="Business Logic",
            description="Analysis of workflow manipulation and logic flaws.",
            steps=[
                PlaybookStep(
                    id="step_logic_1",
                    title="Identify Critical Workflows",
                    description="Extract the main state machines of the application.",
                )
            ]
        ),
        Playbook(
            id="pb_authentication",
            name="Authentication Review",
            category="Authentication",
            description="Testing password policies, MFA, and OAuth flows.",
        ),
        Playbook(
            id="pb_session_mgmt",
            name="Session Management Review",
            category="Session",
            description="Analysis of cookie security, token generation, and expiry.",
        ),
        Playbook(
            id="pb_api_review",
            name="API Review",
            category="API",
            description="REST/GraphQL endpoint enumeration and manipulation.",
        ),
        Playbook(
            id="pb_file_upload",
            name="File Upload Review",
            category="File Upload",
            description="Testing for RCE and XSS via file uploads.",
        ),
        Playbook(
            id="pb_workflow",
            name="Workflow Review",
            category="Workflow",
            description="Analysis of multi-step business transactions.",
        ),
        Playbook(
            id="pb_info_disclosure",
            name="Information Disclosure Review",
            category="Information Disclosure",
            description="Hunting for sensitive data leaks in responses.",
        ),
    ]
