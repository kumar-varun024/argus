from argus.workflows.models import Workflow
from argus.authorization.models import AuthNodeType, AuthEdgeType

def get_role_hierarchy_rules():
    # Simplistic heuristic for roles based on names
    return {
        "Owner": ["Admin"],
        "Admin": ["Manager", "Member"],
        "Manager": ["Member"],
        "Member": ["Guest"],
    }

def get_ownership_rules():
    # Heuristics for ownership
    return {
        "Organization": ["Project", "Team", "Workspace", "Repository"],
        "Project": ["Repository", "Task"],
        "Repository": ["Secret", "File"],
    }

def infer_permission_from_method(method: str) -> AuthEdgeType:
    method = method.upper()
    if method == "GET":
        return AuthEdgeType.CAN_READ
    elif method == "POST":
        return AuthEdgeType.CAN_CREATE
    elif method in ["PUT", "PATCH"]:
        return AuthEdgeType.CAN_UPDATE
    elif method == "DELETE":
        return AuthEdgeType.CAN_DELETE
    return AuthEdgeType.CAN_READ

def infer_node_type_for_business_object(bo_name: str) -> AuthNodeType:
    bo = bo_name.lower()
    if bo in ["organization", "org"]:
        return AuthNodeType.ORGANIZATION
    elif bo == "project":
        return AuthNodeType.PROJECT
    elif bo == "repository":
        return AuthNodeType.REPOSITORY
    elif bo == "workspace":
        return AuthNodeType.WORKSPACE
    return AuthNodeType.BUSINESS_OBJECT
