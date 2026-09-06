from __future__ import annotations
from dataclasses import dataclass, field
from uuid import uuid4
from datetime import datetime
import typing
from typing import Any, Optional

from argus.evidence import EvidenceStore
from argus.facts import FactStore
from argus.models import AuthenticationModel, TestIdentity
from argus.reporting.queue import ResearchQueue
from argus.graph.graph import KnowledgeGraph
from argus.runtime.mission_state import MissionState, GraphQLState, JavaScriptState

if typing.TYPE_CHECKING:
    from argus.ai.models import AIResponse
    from argus.knowledge.manager import KnowledgeManager
    from argus.knowledge.models import KnowledgeEntry
    from argus.workflows.models import Workflow
    from argus.authorization.graph import AuthorizationGraph
    from argus.agents.results import AgentResult, AgentHealth, AgentMetric
    from argus.execution.results import ExecutionPlanResult


# Scope derivation now lives in argus.mission.scope (pure, unit-tested helper).
# Imported here under its historical name to preserve existing behavior/callers.
from argus.mission.scope import derive_default_scope as _derive_default_scope


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
    test_identities: list[TestIdentity] = field(default_factory=list)
    active_identity_id: Optional[str] = None
    environment: dict = field(default_factory=dict)
    
    # State & Graph
    subdomains: list[str] = field(default_factory=list)
    live_hosts: list[dict] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    endpoints: list[dict] = field(default_factory=list)
    vulnerabilities: list[dict] = field(default_factory=list)
    evidence: EvidenceStore = field(default_factory=EvidenceStore)
    attack_surface_graph: KnowledgeGraph = field(default_factory=KnowledgeGraph)
    plan: Optional[Any] = None
    plan_steps: list = field(default_factory=list)
    plan_dependencies: list = field(default_factory=list)
    
    # Research Planner
    research_tasks: list = field(default_factory=list)
    research_queue: list = field(default_factory=list)
    coverage: dict = field(default_factory=dict)
    coverage_gaps: list = field(default_factory=list)
    
    # Task Scheduler
    execution_queue: dict = field(default_factory=dict)
    execution_history: list = field(default_factory=list)
    task_states: dict = field(default_factory=dict)
    retry_history: list = field(default_factory=list)
    state_transitions: list = field(default_factory=list)
    
    # Existing lists/states
    findings: list = field(default_factory=list)
    api_inventory: list = field(default_factory=list)
    business_objects: list = field(default_factory=list)
    business_logic: list = field(default_factory=list)
    priority_queue: list = field(default_factory=list)
    priority_scores: dict = field(default_factory=dict)
    
    # Universal Observation Model
    observations: Any = field(default_factory=list)  # Replaced in __post_init__
    correlations: Any = field(default_factory=list)  # Replaced in __post_init__
    correlation_graph: Any = None                    # Replaced in __post_init__
    
    # Evidence Fusion Engine
    evidence_bundles: Any = field(default_factory=list) # Replaced in __post_init__
    evidence_strength: dict = field(default_factory=dict)
    
    # Investigation Builder
    investigations: Any = field(default_factory=list) # Replaced in __post_init__
    investigation_queue: list = field(default_factory=list)
    reasoning_tree: dict = field(default_factory=dict)
    explanations: dict = field(default_factory=dict)
    reasoning_chains: dict = field(default_factory=dict)
    explanation_graph: dict = field(default_factory=dict)

    # Hypothesis Engine (PR5)
    hypotheses: Any = field(default_factory=list)       # Replaced in __post_init__
    hypothesis_history: list = field(default_factory=list)
    hypothesis_queue: list = field(default_factory=list)

    # Learning & Feedback Engine (PR6)
    learning: Any = None                                # LearningRecord after process_mission()
    feedback: list = field(default_factory=list)        # List[FeedbackEntry]
    patterns: list = field(default_factory=list)        # List[Recommendation]
    
    def __post_init__(self):
        if not self.scope and self.target:
            self.scope = _derive_default_scope(self.target)

        from argus.correlation.registry import ObservationRegistry, CorrelationRegistry, EvidenceBundleRegistry
        from argus.correlation.graph import CorrelationGraph
        from argus.investigation.registry import InvestigationRegistry

        self.observations = ObservationRegistry()
        self.correlations = CorrelationRegistry()
        self.correlation_graph = CorrelationGraph()
        self.evidence_bundles = EvidenceBundleRegistry()
        self.investigations = InvestigationRegistry()

        if getattr(self, "attack_surface_graph", None) is None:
            self.attack_surface_graph = KnowledgeGraph()
        self.graph = self.attack_surface_graph

        # Hypothesis Engine registry (graceful if module not yet installed)
        try:
            from argus.hypothesis.registry import HypothesisRegistry
            self.hypotheses = HypothesisRegistry()
        except ImportError:
            pass  # Hypothesis engine not yet installed — field stays as []
    
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

    def add_test_identity(self, identity: TestIdentity) -> None:
        """Adds a TestIdentity to the mission and sets as active if active or first."""
        for idx, existing in enumerate(self.test_identities):
            if existing.id == identity.id:
                self.test_identities[idx] = identity
                if identity.is_active or self.active_identity_id == identity.id:
                    self.active_identity_id = identity.id
                return
        self.test_identities.append(identity)
        if self.active_identity_id is None or identity.is_active:
            self.active_identity_id = identity.id

    def get_test_identity(self, identity_id: str) -> Optional[TestIdentity]:
        """Finds a TestIdentity by ID or name."""
        for ident in self.test_identities:
            if ident.id == identity_id or ident.name == identity_id:
                return ident
        return None

    def get_active_identity(self) -> Optional[TestIdentity]:
        """Returns the currently active TestIdentity if set, or the first active one."""
        if self.active_identity_id:
            for ident in self.test_identities:
                if ident.id == self.active_identity_id:
                    return ident
        for ident in self.test_identities:
            if ident.is_active:
                return ident
        return self.test_identities[0] if self.test_identities else None

    def set_active_identity(self, identity_id: str) -> Optional[TestIdentity]:
        """Sets the active identity by ID or name and returns it."""
        ident = self.get_test_identity(identity_id)
        if ident:
            self.active_identity_id = ident.id
            ident.is_active = True
        return ident

    def clear_test_identities(self) -> None:
        """Clears all test identities from the mission."""
        self.test_identities.clear()
        self.active_identity_id = None

    def list_test_identities(self) -> list[TestIdentity]:
        """Returns a copy of all test identities."""
        return list(self.test_identities)

