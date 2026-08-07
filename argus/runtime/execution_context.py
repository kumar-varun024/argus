import threading
from typing import Optional, Any
from argus.runtime.mission import Mission
from argus.runtime.context import MissionContext

class ExecutionContext:
    """Provides a safe abstraction over Mission state and configuration."""
    
    def __init__(self, mission: Mission):
        self.mission = mission
        self.lock = threading.RLock()
        
    @property
    def scope(self) -> list[str]:
        with self.lock:
            return self.mission.scope
        
    @property
    def policy(self) -> dict:
        with self.lock:
            return self.mission.policy
        
    @property
    def configuration(self) -> dict:
        with self.lock:
            return self.mission.configuration
        
    @property
    def knowledge_graph(self):
        with self.lock:
            # Future-proof for when KnowledgeManager is fully integrated in Mission
            return getattr(self.mission, 'knowledge_graph', None)
        
    @property
    def workflow_graph(self):
        with self.lock:
            return self.mission.workflows
        
    @property
    def observations(self):
        with self.lock:
            return self.mission.observations
        
    @property
    def correlations(self):
        with self.lock:
            return self.mission.correlations
        
    @property
    def evidence_bundles(self):
        with self.lock:
            return self.mission.evidence_bundles
        
    @property
    def investigations(self):
        with self.lock:
            return self.mission.investigations
        
    @property
    def hypotheses(self):
        with self.lock:
            return self.mission.hypotheses
        
    @property
    def learning_records(self):
        with self.lock:
            return self.mission.learning
        
    @property
    def execution_metrics(self) -> dict:
        with self.lock:
            return self.mission.metrics
        
    def activate(self):
        """Activates this context as the global thread-local active mission."""
        MissionContext.set_active_mission(self.mission)
        
    def deactivate(self):
        """Clears the global thread-local active mission."""
        MissionContext.clear()
