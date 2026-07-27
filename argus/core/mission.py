from __future__ import annotations

from dataclasses import dataclass, field
from uuid import uuid4

from argus.evidence import EvidenceStore
from argus.facts import FactStore
from argus.models import AuthenticationModel
from argus.reporting.queue import ResearchQueue

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from argus.ai.models import AIResponse
    from argus.analyzers.models import AuthenticationIntelligence
    from argus.knowledge.manager import KnowledgeManager
    from argus.knowledge.models import KnowledgeEntry
    from argus.workflows.models import Workflow
    from argus.authorization.graph import AuthorizationGraph
    from argus.agents.results import AgentResult, AgentHealth, AgentMetric


@dataclass
class Mission:

    target: str

    id: str = field(default_factory=lambda: str(uuid4()))

    status: str = "created"

    phase: str = "planning"

    scope: list[str] = field(default_factory=list)

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

    evidence: EvidenceStore = field(default_factory=EvidenceStore)

    facts: FactStore = field(default_factory=FactStore)

    reports: list[str] = field(default_factory=list)

    notes: list[str] = field(default_factory=list)

    hypotheses: list = field(default_factory=list)

    authentication: AuthenticationModel = field(default_factory=AuthenticationModel)

    api_intelligence: list = field(default_factory=list)

    business_objects: list = field(default_factory=list)

    research_cards: ResearchQueue = field(default_factory=ResearchQueue)

    workflows: list['Workflow'] = field(default_factory=list)

    authorization_graph: 'AuthorizationGraph' = None

    ai_research: 'AIResponse' = None
    
    agent_results: dict[str, 'AgentResult'] = field(default_factory=dict)
    agent_health: dict[str, 'AgentHealth'] = field(default_factory=dict)
    agent_metrics: dict[str, 'AgentMetric'] = field(default_factory=dict)

    def start(self):

        self.status = "running"

        self.phase = "recon"

    def finish(self):

        self.status = "completed"

        self.phase = "finished"

    def get_relevant_knowledge(self, manager: 'KnowledgeManager') -> list['KnowledgeEntry']:
        """Queries the KnowledgeManager for knowledge relevant to this mission's context."""
        results = []
        for bo in self.business_objects:
            # We assume business objects might be simple dicts or objects with a name
            bo_name = bo.get('name') if isinstance(bo, dict) else getattr(bo, 'name', str(bo))
            results.extend(manager.search(business_object=bo_name))
            
        for tech in self.scope:
            results.extend(manager.search(technology=tech))
            
        # Deduplicate
        seen = set()
        unique_results = []
        for r in results:
            if r.id not in seen:
                seen.add(r.id)
                unique_results.append(r)
                
        return unique_results
