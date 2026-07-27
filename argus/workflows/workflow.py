# General workflow business logic or aggregation can go here
from .models import Workflow, WorkflowStep

def get_workflow_by_id(workflows: list[Workflow], wf_id: str) -> Workflow | None:
    for w in workflows:
        if w.id == wf_id:
            return w
    return None
