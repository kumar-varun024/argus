from typing import Optional
from argus.intelligence.models import APIEndpoint
from argus.workflows.models import WorkflowStep

def create_step_from_endpoint(endpoint: APIEndpoint, order: int = 0) -> WorkflowStep:
    """Create a WorkflowStep from an APIEndpoint."""
    state = ""
    # Very basic lifecycle inference based on HTTP method and operation
    op = endpoint.operation.lower() if endpoint.operation else ""
    path = endpoint.path.lower()
    
    if endpoint.method == "POST":
        if "login" in path or "auth" in path or "token" in path:
            state = "Authenticated"
        elif "invite" in path:
            state = "Pending"
        else:
            state = "Created"
    elif endpoint.method in ("PUT", "PATCH"):
        if "accept" in path:
            state = "Accepted"
        else:
            state = "Updated"
    elif endpoint.method == "DELETE":
        state = "Deleted"
        if "revoke" in path:
            state = "Revoked"
    elif endpoint.method == "GET":
        state = "Read"

    return WorkflowStep(
        title=f"{endpoint.method} {endpoint.path}",
        endpoint=endpoint.path,
        http_method=endpoint.method,
        order=order,
        business_object=endpoint.business_object or "",
        expected_state=state,
        evidence=endpoint.evidence or []
    )
