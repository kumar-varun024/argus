from typing import List, Dict, Set
from argus.intelligence.workflow_models import Workflow, WorkflowStep
from argus.intelligence.models import APIEndpoint
from argus.intelligence.business_models import BusinessObject

class WorkflowBuilder:
    def __init__(self, endpoints: List[APIEndpoint], business_objects: List[BusinessObject]):
        self.endpoints = endpoints
        self.business_objects = business_objects
        
    def build(self) -> List[Workflow]:
        workflows: List[Workflow] = []
        
        # Heuristics for typical flows
        
        # 1. Authentication Flow
        auth_eps = [e for e in self.endpoints if 'login' in e.path.lower() or 'auth' in e.path.lower() or 'token' in e.path.lower()]
        if auth_eps:
            wf = Workflow(name="Authentication", description="User login and token generation flow")
            for ep in auth_eps:
                step = WorkflowStep(
                    name=f"Auth via {ep.path}", 
                    endpoint=ep.path, 
                    method=ep.method,
                    business_object=ep.business_object
                )
                wf.steps.append(step)
                wf.related_endpoints.add(ep.path)
            wf.confidence = 0.9
            wf.entry_points = [s.endpoint for s in wf.steps[:1]]
            workflows.append(wf)
            
        # 2. Registration Flow
        reg_eps = [e for e in self.endpoints if 'register' in e.path.lower() or 'signup' in e.path.lower()]
        if reg_eps:
            wf = Workflow(name="Registration", description="User sign up and onboarding process")
            for ep in reg_eps:
                step = WorkflowStep(
                    name=f"Register via {ep.path}", 
                    endpoint=ep.path, 
                    method=ep.method,
                    business_object=ep.business_object
                )
                wf.steps.append(step)
                wf.related_endpoints.add(ep.path)
            wf.confidence = 0.9
            wf.entry_points = [s.endpoint for s in wf.steps[:1]]
            workflows.append(wf)

        # 3. Organization Management
        org_eps = [e for e in self.endpoints if 'org' in e.resource.lower() or 'organization' in e.path.lower()]
        if org_eps:
            wf = Workflow(name="Organization Management", description="Manage organizations and workspaces")
            for ep in org_eps:
                step = WorkflowStep(
                    name=f"{ep.method} {ep.path}", 
                    endpoint=ep.path, 
                    method=ep.method, 
                    business_object=ep.business_object or "Organization"
                )
                wf.steps.append(step)
                wf.related_endpoints.add(ep.path)
            wf.confidence = 0.8
            workflows.append(wf)
            
        # 4. Billing & Payments
        bill_eps = [e for e in self.endpoints if 'billing' in e.path.lower() or 'invoice' in e.path.lower() or 'checkout' in e.path.lower()]
        if bill_eps:
            wf = Workflow(name="Billing", description="Payment and invoice management")
            for ep in bill_eps:
                step = WorkflowStep(
                    name=f"{ep.method} {ep.path}", 
                    endpoint=ep.path, 
                    method=ep.method, 
                    business_object=ep.business_object or "Billing"
                )
                wf.steps.append(step)
                wf.related_endpoints.add(ep.path)
            wf.confidence = 0.8
            workflows.append(wf)

        # Build dependencies
        wf_names = {w.name: w for w in workflows}
        
        if "Organization Management" in wf_names and "Authentication" in wf_names:
            wf_names["Organization Management"].dependencies.append(wf_names["Authentication"].id)
            
        if "Billing" in wf_names and "Organization Management" in wf_names:
            wf_names["Billing"].dependencies.append(wf_names["Organization Management"].id)
            
        if "Authentication" in wf_names and "Registration" in wf_names:
            wf_names["Authentication"].dependencies.append(wf_names["Registration"].id)

        # Extract Business Objects
        for wf in workflows:
            for step in wf.steps:
                if step.business_object:
                    wf.business_objects.add(step.business_object)
                    
        return workflows
