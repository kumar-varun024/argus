from typing import List, Dict
from argus.workflows.models import Workflow

def build_workflow_graph(workflows: List[Workflow]) -> None:
    """Builds a dependency graph by linking workflow IDs in the dependencies list.
    Also handles step ordering within the workflows.
    """
    # Create a quick lookup for workflows by name (case-insensitive partial match)
    wf_by_name = {w.name.lower(): w for w in workflows}
    
    # Define common logical dependencies (parent -> child)
    # The child will depend on the parent.
    dependency_rules = [
        ("registration", ["authentication"]),
        ("authentication", [
            "organization management", 
            "billing", 
            "api keys", 
            "settings", 
            "profile management"
        ]),
        ("organization management", [
            "project creation", 
            "repository management", 
            "invitation", 
            "role management",
            "billing"
        ]),
        ("project creation", ["repository management"]),
        ("billing", ["payments", "invoices"]),
    ]
    
    for parent_key, children_keys in dependency_rules:
        parent_wf = next((w for k, w in wf_by_name.items() if parent_key in k), None)
        if parent_wf:
            for child_key in children_keys:
                child_wf = next((w for k, w in wf_by_name.items() if child_key in k), None)
                if child_wf and child_wf.id != parent_wf.id and parent_wf.id not in child_wf.dependencies:
                    # Prevent cycles
                    if child_wf.id not in parent_wf.dependencies:
                        child_wf.dependencies.append(parent_wf.id)

    # Order steps inside workflows
    for wf in workflows:
        _order_workflow_steps(wf)

def _order_workflow_steps(workflow: Workflow) -> None:
    """Order steps logically (POST -> GET -> PUT -> DELETE)."""
    # Very basic DAG generation for steps:
    # 1. POST/Create
    # 2. GET/Read
    # 3. PUT/PATCH/Update
    # 4. DELETE/Delete
    
    def get_method_weight(method: str) -> int:
        m = method.upper()
        if m == "POST":
            return 1
        elif m == "GET":
            return 2
        elif m in ("PUT", "PATCH"):
            return 3
        elif m == "DELETE":
            return 4
        return 5
        
    workflow.steps.sort(key=lambda x: get_method_weight(x.http_method))
    
    # Assign order and link previous/next
    for i, step in enumerate(workflow.steps):
        step.order = i + 1
        if i > 0:
            step.previous_steps = [workflow.steps[i-1].id]
        if i < len(workflow.steps) - 1:
            step.next_steps = [workflow.steps[i+1].id]
