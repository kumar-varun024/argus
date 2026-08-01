from typing import List, Dict, Any
from argus.intelligence.models import Investigation
from argus.plugins.api.resource_model import APIResource
from argus.plugins.api.operations import APIOperation

class BaseAPIHeuristic:
    def run(self, context: Dict[str, Any]) -> List[Investigation]:
        pass

class AdministrativeAPIHeuristic(BaseAPIHeuristic):
    def run(self, context: Dict[str, Any]) -> List[Investigation]:
        invs = []
        resources = context.get('resources', {})
        for path, r in resources.items():
            if 'admin' in path.lower() or 'system' in path.lower():
                inv = Investigation(
                    title=f"Review Administrative API: {r.name}",
                    category="API Administrative Endpoint",
                    affected_objects=[r.name],
                    reasoning=f"The resource {r.name} appears to be administrative based on its path '{path}'. It requires careful authorization validation.",
                    supporting_evidence=[f"Path: {path}"],
                    manual_validation_steps=["1. Verify authentication requirements", "2. Attempt to access with standard user"]
                )
                invs.append(inv)
        return invs

class BulkModificationHeuristic(BaseAPIHeuristic):
    def run(self, context: Dict[str, Any]) -> List[Investigation]:
        invs = []
        operations = context.get('operations', [])
        for op in operations:
            if op.is_bulk:
                inv = Investigation(
                    title=f"Review Bulk Operation on {op.resource_name}",
                    category="API Bulk Operation",
                    affected_objects=[op.resource_name],
                    reasoning=f"Bulk modifications on {op.resource_name} ({op.path}) can lead to mass data manipulation or DOS if improperly restricted.",
                    supporting_evidence=[f"Bulk operation: {op.method} {op.path}"],
                    manual_validation_steps=["1. Check rate limiting", "2. Attempt to modify records belonging to other users in bulk"]
                )
                invs.append(inv)
        return invs

class HiddenResourceHeuristic(BaseAPIHeuristic):
    def run(self, context: Dict[str, Any]) -> List[Investigation]:
        invs = []
        # Mock logic: resources without typical CRUD ops or undocumented
        return invs

class IncompleteCRUDHeuristic(BaseAPIHeuristic):
    def run(self, context: Dict[str, Any]) -> List[Investigation]:
        invs = []
        resources = context.get('resources', {})
        operations = context.get('operations', [])
        
        ops_by_res = {}
        for op in operations:
            ops_by_res.setdefault(op.resource_name, set()).add(op.method)
            
        for path, r in resources.items():
            methods = ops_by_res.get(r.name, set())
            # For example, if it has POST, GET, PUT but missing DELETE
            if {"POST", "GET", "PUT"}.issubset(methods) and "DELETE" not in methods:
                inv = Investigation(
                    title=f"Check for hidden DELETE on {r.name}",
                    category="API Incomplete CRUD",
                    affected_objects=[r.name],
                    reasoning=f"Resource {r.name} supports creation and updates but no documented deletion. The DELETE method might still be active but hidden.",
                    supporting_evidence=[f"Methods found: {methods}"],
                    manual_validation_steps=[f"1. Attempt a DELETE request on {path}"]
                )
                invs.append(inv)
        return invs

API_HEURISTIC_REGISTRY = [
    AdministrativeAPIHeuristic(),
    BulkModificationHeuristic(),
    IncompleteCRUDHeuristic(),
    HiddenResourceHeuristic()
]
