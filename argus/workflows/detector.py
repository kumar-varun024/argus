from typing import List, Dict
from argus.intelligence.models import APIEndpoint
from argus.workflows.models import Workflow
from argus.workflows.step import create_step_from_endpoint

class WorkflowDetector:
    def __init__(self, endpoints: List[APIEndpoint]):
        self.endpoints = endpoints

    def detect_workflows(self) -> List[Workflow]:
        workflows = []
        workflows.extend(self._detect_authentication())
        workflows.extend(self._detect_organization())
        workflows.extend(self._detect_billing())
        workflows.extend(self._detect_api_keys())
        workflows.extend(self._detect_general_crud())
        
        # Merge by name if needed, but for now just return
        return workflows

    def _create_workflow(self, name: str, desc: str, eps: List[APIEndpoint]) -> Workflow:
        wf = Workflow(name=name, description=desc)
        for i, ep in enumerate(eps):
            step = create_step_from_endpoint(ep, order=i+1)
            wf.steps.append(step)
            if ep.business_object:
                wf.business_objects.add(ep.business_object)
            if ep.evidence:
                wf.evidence.extend(ep.evidence)
            
        wf.confidence = 0.8
        if wf.steps:
            wf.entry_points.append(wf.steps[0].endpoint)
            wf.exit_points.append(wf.steps[-1].endpoint)
        return wf

    def _detect_authentication(self) -> List[Workflow]:
        wfs = []
        auth_eps = [e for e in self.endpoints if any(x in e.path.lower() for x in ['login', 'auth', 'token', 'session'])]
        if auth_eps:
            wfs.append(self._create_workflow("Authentication", "User login and session management", auth_eps))
            
        reg_eps = [e for e in self.endpoints if any(x in e.path.lower() for x in ['register', 'signup'])]
        if reg_eps:
            wfs.append(self._create_workflow("Registration", "User sign up and onboarding", reg_eps))
            
        pw_eps = [e for e in self.endpoints if 'password' in e.path.lower() and ('reset' in e.path.lower() or 'forgot' in e.path.lower())]
        if pw_eps:
            wfs.append(self._create_workflow("Password Reset", "Password recovery flow", pw_eps))
            
        return wfs

    def _detect_organization(self) -> List[Workflow]:
        wfs = []
        org_eps = [e for e in self.endpoints if 'org' in e.path.lower() or 'workspace' in e.path.lower() or 'tenant' in e.path.lower()]
        if org_eps:
            wfs.append(self._create_workflow("Organization Management", "Manage organizations and workspaces", org_eps))
            
        inv_eps = [e for e in self.endpoints if 'invite' in e.path.lower() or 'invitation' in e.path.lower()]
        if inv_eps:
            wfs.append(self._create_workflow("Invitation", "Invite users to organization", inv_eps))
            
        proj_eps = [e for e in self.endpoints if 'project' in e.path.lower()]
        if proj_eps:
            wfs.append(self._create_workflow("Project Creation", "Manage projects", proj_eps))
            
        repo_eps = [e for e in self.endpoints if 'repo' in e.path.lower()]
        if repo_eps:
            wfs.append(self._create_workflow("Repository Management", "Manage repositories", repo_eps))
            
        return wfs

    def _detect_billing(self) -> List[Workflow]:
        wfs = []
        bill_eps = [e for e in self.endpoints if any(x in e.path.lower() for x in ['billing', 'invoice', 'payment', 'checkout', 'subscription'])]
        if bill_eps:
            wfs.append(self._create_workflow("Billing", "Payment and invoice management", bill_eps))
        return wfs

    def _detect_api_keys(self) -> List[Workflow]:
        wfs = []
        key_eps = [e for e in self.endpoints if 'api-key' in e.path.lower() or 'apikeys' in e.path.lower() or 'personal-access-token' in e.path.lower() or ('token' in e.path.lower() and 'generate' in e.path.lower())]
        if key_eps:
            wfs.append(self._create_workflow("API Keys", "Manage API keys and access tokens", key_eps))
        return wfs

    def _detect_general_crud(self) -> List[Workflow]:
        wfs = []
        # Group by business object for generic CRUD if they don't match specific ones
        grouped: Dict[str, List[APIEndpoint]] = {}
        for ep in self.endpoints:
            bo = ep.business_object
            if bo:
                grouped.setdefault(bo, []).append(ep)
                
        for bo, eps in grouped.items():
            if not any(w.name for w in wfs if bo in w.name) and len(eps) > 1:
                # Basic CRUD check (must have at least a POST or PUT/PATCH to be considered a workflow)
                if any(e.method in ["POST", "PUT", "PATCH", "DELETE"] for e in eps):
                    wfs.append(self._create_workflow(f"{bo.capitalize()} Management", f"Manage {bo} lifecycle", eps))
        return wfs
