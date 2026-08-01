from __future__ import annotations
from dataclasses import dataclass, field
from uuid import uuid4
from datetime import datetime
from enum import Enum
import typing

from argus.evidence import EvidenceStore
from argus.facts import FactStore
from argus.models import AuthenticationModel
from argus.reporting.queue import ResearchQueue

if typing.TYPE_CHECKING:
    from argus.ai.models import AIResponse
    from argus.knowledge.manager import KnowledgeManager
    from argus.knowledge.models import KnowledgeEntry
    from argus.workflows.models import Workflow
    from argus.authorization.graph import AuthorizationGraph
    from argus.agents.results import AgentResult, AgentHealth, AgentMetric
    from argus.execution.results import ExecutionPlanResult

class MissionState(str, Enum):
    CREATED = "CREATED"
    VALIDATING = "VALIDATING"
    READY = "READY"
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    FAILED = "FAILED"
    COMPLETED = "COMPLETED"
    CANCELLED = "CANCELLED"

@dataclass
class GraphQLState:
    endpoints: list = field(default_factory=list)
    schemas: list = field(default_factory=list)
    types: dict = field(default_factory=dict)
    operations: list = field(default_factory=list)
    relationships: list = field(default_factory=list)
    workflows: list = field(default_factory=list)
    investigations: list = field(default_factory=list)

@dataclass
class Mission:
    target: str
    id: str = field(default_factory=lambda: str(uuid4()))
    name: str = ""
    workspace: str = "default"
    
    # Lifecycle
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    status: MissionState = MissionState.CREATED
    phase: str = "planning"
    
    # Config & Policy
    scope: list[str] = field(default_factory=list)
    policy: dict = field(default_factory=dict)
    credentials: list[dict] = field(default_factory=list)
    configuration: dict = field(default_factory=dict)
    
    # State & Graph
    subdomains: list[str] = field(default_factory=list)
    live_hosts: list[dict] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    endpoints: list[dict] = field(default_factory=list)
    parameters: list[str] = field(default_factory=list)
    javascript: list[dict] = field(default_factory=list)
    apis: list[str] = field(default_factory=list)
    cookies: list[str] = field(default_factory=list)
    tokens: list[str] = field(default_factory=list)
    
    findings: list[dict] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    hypotheses: list = field(default_factory=list)
    investigations: list = field(default_factory=list)
    priority_queue: list = field(default_factory=list)
    
    # Playbook Tracking
    playbooks: list[str] = field(default_factory=list)
    active_playbooks: list[str] = field(default_factory=list)
    completed_playbooks: list[str] = field(default_factory=list)
    playbook_results: dict = field(default_factory=dict)
    
    # Authorization Tracking
    authorization_investigations: list = field(default_factory=list)
    authorization_metrics: dict = field(default_factory=dict)
    
    # Business Logic Tracking
    business_logic: list = field(default_factory=list)
    state_machines: dict = field(default_factory=dict)
    workflow_rules: list = field(default_factory=list)
    
    authentication: AuthenticationModel = field(default_factory=AuthenticationModel)
    api_intelligence: list = field(default_factory=list)
    
    # API Intelligence Tracking
    api_inventory: list = field(default_factory=list)
    resources: dict = field(default_factory=dict)
    operations: list = field(default_factory=list)
    relationships: list = field(default_factory=list)
    
    # Authentication & Session Tracking
    identities: list = field(default_factory=list)
    sessions: list = field(default_factory=list)
    authentication_workflows: list = field(default_factory=list)
    identity_graph: dict = field(default_factory=dict)
    
    # File Upload Tracking
    file_inventory: list = field(default_factory=list)
    upload_workflows: list = field(default_factory=list)
    file_relationships: list = field(default_factory=list)
    
    # GraphQL Tracking
    graphql: GraphQLState = field(default_factory=GraphQLState)
    
    business_objects: list = field(default_factory=list)
    
    workflows: list['Workflow'] = field(default_factory=list)
    authorization_graph: 'AuthorizationGraph' = None
    ai_research: 'AIResponse' = None
    
    # Datastores
    evidence: EvidenceStore = field(default_factory=EvidenceStore)
    facts: FactStore = field(default_factory=FactStore)
    
    # Modules
    research_cards: ResearchQueue = field(default_factory=ResearchQueue)
    planner: dict = field(default_factory=dict) # Placeholder for investigation planner
    
    agent_results: dict[str, 'AgentResult'] = field(default_factory=dict)
    agent_health: dict[str, 'AgentHealth'] = field(default_factory=dict)
    agent_metrics: dict[str, 'AgentMetric'] = field(default_factory=dict)
    
    execution_history: list['ExecutionPlanResult'] = field(default_factory=list)
    execution_results: dict[str, 'ExecutionPlanResult'] = field(default_factory=dict)
    execution_metrics: dict[str, dict] = field(default_factory=dict)
    
    reports: list[str] = field(default_factory=list)
    metrics: dict = field(default_factory=dict)
    plugins: list[str] = field(default_factory=list)

    # Note: legacy start() and finish() are moved to argus.runtime.lifecycle.
    
    def get_relevant_knowledge(self, manager: 'KnowledgeManager') -> list['KnowledgeEntry']:
        """Queries the KnowledgeManager for knowledge relevant to this mission's context."""
        results = []
        for bo in self.business_objects:
            bo_name = bo.get('name') if isinstance(bo, dict) else getattr(bo, 'name', str(bo))
            results.extend(manager.search(business_object=bo_name))
            
        for tech in self.scope:
            results.extend(manager.search(technology=tech))
            
        seen = set()
        unique_results = []
        for r in results:
            if r.id not in seen:
                seen.add(r.id)
                unique_results.append(r)
                
        return unique_results
