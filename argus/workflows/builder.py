from typing import List, Any
from argus.workflows.models import Workflow
from argus.workflows.detector import WorkflowDetector
from argus.workflows.graph import build_workflow_graph
from argus.intelligence.models import APIEndpoint

class WorkflowBuilder:
    def __init__(self, mission: Any = None, knowledge_manager: Any = None, endpoints: List[Any] = None, business_objects: List[Any] = None):
        """
        Initialize the WorkflowBuilder.
        Accepts the Mission object and optional KnowledgeManager to tie nodes.
        """
        self.mission = mission
        self.knowledge_manager = knowledge_manager
        
        if mission and hasattr(mission, 'endpoints'):
            self.endpoints = mission.endpoints
            self.business_objects = mission.business_objects
        else:
            self.endpoints = endpoints or []
            self.business_objects = business_objects or []
            
    def _get_endpoints(self) -> List[APIEndpoint]:
        # Unpack dicts into APIEndpoints if necessary
        eps = []
        for e in self.endpoints:
            if isinstance(e, dict):
                eps.append(APIEndpoint(**e))
            else:
                eps.append(e)
        return eps

    def build(self) -> List[Workflow]:
        """
        Build workflows, generate the dependency graph, and link knowledge graph nodes.
        Returns the list of Workflows and sets it on the mission.
        """
        eps = self._get_endpoints()
        if not eps:
            return []

        # 1. Detection
        detector = WorkflowDetector(endpoints=eps)
        workflows = detector.detect_workflows()
        
        # 2. Graph and Ordering
        build_workflow_graph(workflows)
        
        # 3. Associate Authorization boundaries and Roles
        # Simplistic authorization boundaries based on 'admin' or 'owner' in endpoints
        for wf in workflows:
            if wf.business_objects:
                wf.risk_score = "MEDIUM" if len(wf.steps) > 2 else "LOW"
            for step in wf.steps:
                if 'admin' in step.endpoint.lower():
                    step.required_role = 'Admin'
                    wf.roles.add('Admin')
                elif 'owner' in step.endpoint.lower():
                    step.required_role = 'Owner'
                    wf.roles.add('Owner')
                elif 'member' in step.endpoint.lower():
                    step.required_role = 'Member'
                    wf.roles.add('Member')
                
                # Assign generic authenticated role if none specified but workflow is auth'd
                if not step.required_role and wf.name not in ["Authentication", "Registration"]:
                    step.required_role = 'Guest' # Default to guest, unless we have auth info

        # 4. Link Knowledge Graph Nodes
        if self.knowledge_manager:
            for wf in workflows:
                for bo in wf.business_objects:
                    # search knowledge graph for this BO
                    results = self.knowledge_manager.search(business_object=bo)
                    for r in results:
                        if r.id not in wf.graph_nodes:
                            wf.graph_nodes.append(r.id)

        # Update mission
        if hasattr(self.mission, 'workflows'):
            self.mission.workflows = workflows
            
        return workflows
