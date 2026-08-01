from abc import ABC, abstractmethod
from typing import List
from argus.agents.authorization.models import AuthzContext, AuthzHeuristicResult
from argus.intelligence.models import Investigation
from argus.agents.authorization.graph import GraphHelper
from argus.agents.authorization.ownership import OwnershipAnalyzer
from argus.agents.authorization.roles import RoleAnalyzer
from argus.agents.authorization.permissions import PermissionAnalyzer

class BaseAuthzHeuristic(ABC):
    @property
    @abstractmethod
    def id(self) -> str: pass
    
    @abstractmethod
    def run(self, context: AuthzContext) -> List[AuthzHeuristicResult]: pass

class CrossTenantObjectHeuristic(BaseAuthzHeuristic):
    @property
    def id(self) -> str: return "cross_tenant_object"
    
    def run(self, context: AuthzContext) -> List[AuthzHeuristicResult]:
        results = []
        analyzer = OwnershipAnalyzer()
        findings = analyzer.get_cross_tenant_objects(context)
        
        for obj_name in findings:
            inv = Investigation(
                title=f"Potential Cross-Tenant Access to {obj_name}",
                category="Object-Level Authorization Review",
                affected_objects=[obj_name],
                reasoning=f"The object {obj_name} lacks a direct or indirect ownership link to a tenant, suggesting it may be globally accessible or improperly scoped.",
                supporting_evidence=[f"Graph node {obj_name} missing tenant path"],
                manual_validation_steps=[
                    f"1. Authenticate as Tenant A.",
                    f"2. Attempt to fetch/modify {obj_name} belonging to Tenant B.",
                    "3. Verify if the server enforces tenant separation."
                ],
                workflow="Object Access"
            )
            results.append(AuthzHeuristicResult(investigation=inv, matched_nodes=[obj_name], heuristic_id=self.id))
            
        return results

class MultiRoleResourceHeuristic(BaseAuthzHeuristic):
    @property
    def id(self) -> str: return "multi_role_resource"
    
    def run(self, context: AuthzContext) -> List[AuthzHeuristicResult]:
        results = []
        if not context.graph:
            return results
            
        helper = GraphHelper(context.graph)
        findings = helper.get_multi_role_resources()
        
        for res_name in findings:
            inv = Investigation(
                title=f"Vertical Privilege Escalation risk on {res_name}",
                category="Privilege Boundary Review",
                affected_objects=[res_name],
                reasoning=f"The resource {res_name} is accessed by multiple distinct roles. There may be overlapping permissions allowing lower-privileged users to perform administrative actions.",
                supporting_evidence=[f"Graph node {res_name} connected to >1 Role"],
                manual_validation_steps=[
                    f"1. Identify actions on {res_name} restricted to Admin.",
                    f"2. Attempt to perform those actions using a standard user token.",
                    "3. Observe if the action is blocked (403 Forbidden)."
                ],
                workflow="Resource Management"
            )
            results.append(AuthzHeuristicResult(investigation=inv, matched_nodes=[res_name], heuristic_id=self.id))
            
        return results

class AdministrativeEndpointHeuristic(BaseAuthzHeuristic):
    @property
    def id(self) -> str: return "administrative_endpoint"
    
    def run(self, context: AuthzContext) -> List[AuthzHeuristicResult]:
        results = []
        analyzer = RoleAnalyzer()
        admin_roles = analyzer.get_admin_roles(context)
        # Identify endpoints that might be administrative
        for ep in context.endpoints:
            path = ep.get("path", "").lower()
            if any(k in path for k in ["/admin", "/manage", "/system"]):
                # If these endpoints don't explicitly require an admin role in context, flag them
                inv = Investigation(
                    title=f"Potential unprotected administrative endpoint {ep.get('path')}",
                    category="Function-Level Authorization Review",
                    affected_objects=[ep.get("path", "unknown")],
                    reasoning="The endpoint path suggests administrative functionality, but its authorization enforcement requires manual review to ensure non-admin roles cannot access it.",
                    supporting_evidence=[f"Endpoint path: {ep.get('path')}"],
                    manual_validation_steps=[
                        "1. Authenticate as a standard, non-administrative user.",
                        f"2. Send a request to {ep.get('path')} using the expected method.",
                        "3. Verify if the server rejects the request (403 Forbidden)."
                    ],
                    workflow="Administrative Access"
                )
                results.append(AuthzHeuristicResult(investigation=inv, matched_nodes=[ep.get("path")], heuristic_id=self.id))
        return results

class OwnerAdminWorkflowHeuristic(BaseAuthzHeuristic):
    @property
    def id(self) -> str: return "owner_admin_workflow"
    
    def run(self, context: AuthzContext) -> List[AuthzHeuristicResult]:
        results = []
        for wf in context.workflows:
            wf_name = wf.get("name", "Unknown")
            if "admin" in wf_name.lower() or "owner" in wf_name.lower():
                inv = Investigation(
                    title=f"Privilege boundary review for workflow: {wf_name}",
                    category="Administrative Workflow Review",
                    affected_objects=[wf_name],
                    reasoning=f"The workflow {wf_name} appears to be restricted to owners or admins. The transition steps must be validated to ensure standard users cannot bypass UI checks to execute them.",
                    supporting_evidence=[f"Workflow name implies high privilege: {wf_name}"],
                    manual_validation_steps=[
                        "1. Identify the API requests involved in this workflow.",
                        "2. Attempt to replay these requests as a lower-privileged user.",
                        "3. Verify the backend enforces authorization for each step."
                    ],
                    workflow=wf_name
                )
                results.append(AuthzHeuristicResult(investigation=inv, matched_nodes=[wf_name], heuristic_id=self.id))
        return results

class ObjectUpdateEndpointHeuristic(BaseAuthzHeuristic):
    @property
    def id(self) -> str: return "object_update_endpoint"
    
    def run(self, context: AuthzContext) -> List[AuthzHeuristicResult]:
        results = []
        analyzer = PermissionAnalyzer()
        findings = analyzer.get_unprotected_mutations(context)
        for ep in findings:
            if ep.get("method", "").upper() in ["PUT", "PATCH"]:
                path = ep.get("path", "unknown")
                inv = Investigation(
                    title=f"Authorization review for update endpoint {path}",
                    category="Object-Level Authorization Review",
                    affected_objects=[path],
                    reasoning=f"The endpoint {path} modifies state but its authorization constraints are not fully modeled. Ensure users can only update objects they own.",
                    supporting_evidence=[f"Update endpoint: {ep.get('method')} {path}"],
                    manual_validation_steps=[
                        "1. Identify an object belonging to Tenant A.",
                        "2. Attempt to update it using a token for Tenant B.",
                        "3. Check if the update succeeds (indicating BOLA/IDOR)."
                    ],
                    workflow="Object Mutation"
                )
                results.append(AuthzHeuristicResult(investigation=inv, matched_nodes=[path], heuristic_id=self.id))
        return results

class DeleteOperationHeuristic(BaseAuthzHeuristic):
    @property
    def id(self) -> str: return "delete_operation"
    
    def run(self, context: AuthzContext) -> List[AuthzHeuristicResult]:
        results = []
        analyzer = PermissionAnalyzer()
        findings = analyzer.get_unprotected_mutations(context)
        for ep in findings:
            if ep.get("method", "").upper() == "DELETE":
                path = ep.get("path", "unknown")
                inv = Investigation(
                    title=f"Authorization review for delete endpoint {path}",
                    category="Object-Level Authorization Review",
                    affected_objects=[path],
                    reasoning=f"The endpoint {path} performs a destructive operation. Robust ownership checks must be verified to prevent unauthorized deletion of resources.",
                    supporting_evidence=[f"Delete endpoint: {ep.get('method')} {path}"],
                    manual_validation_steps=[
                        "1. Identify an object belonging to Tenant A.",
                        "2. Attempt to delete it using a token for Tenant B.",
                        "3. Confirm the backend returns 403 Forbidden or 404 Not Found."
                    ],
                    workflow="Object Mutation"
                )
                results.append(AuthzHeuristicResult(investigation=inv, matched_nodes=[path], heuristic_id=self.id))
        return results

class NestedResourceHeuristic(BaseAuthzHeuristic):
    @property
    def id(self) -> str: return "nested_resource"
    
    def run(self, context: AuthzContext) -> List[AuthzHeuristicResult]:
        results = []
        for ep in context.endpoints:
            path = ep.get("path", "")
            # Look for patterns like /api/users/{id}/documents/{doc_id}
            if path.count("{") >= 2:
                inv = Investigation(
                    title=f"Nested resource authorization review: {path}",
                    category="Resource Relationship Review",
                    affected_objects=[path],
                    reasoning=f"The path {path} contains multiple resource identifiers. The backend might only authorize the parent resource and ignore the child resource ownership, or vice versa.",
                    supporting_evidence=[f"Nested path: {path}"],
                    manual_validation_steps=[
                        "1. Modify the parent ID in the request to one you do not own, but keep a valid child ID.",
                        "2. Alternatively, use a valid parent ID you own, but a child ID belonging to another user.",
                        "3. Verify if the backend correctly validates the relationship between the parent, the child, and the user."
                    ],
                    workflow="Resource Relationship"
                )
                results.append(AuthzHeuristicResult(investigation=inv, matched_nodes=[path], heuristic_id=self.id))
        return results

# Registry to hold all active heuristics
AUTHZ_HEURISTIC_REGISTRY: List[BaseAuthzHeuristic] = [
    CrossTenantObjectHeuristic(),
    MultiRoleResourceHeuristic(),
    AdministrativeEndpointHeuristic(),
    OwnerAdminWorkflowHeuristic(),
    ObjectUpdateEndpointHeuristic(),
    DeleteOperationHeuristic(),
    NestedResourceHeuristic()
]
