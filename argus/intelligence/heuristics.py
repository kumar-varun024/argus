from abc import ABC, abstractmethod
from typing import List
from argus.runtime.mission import Mission
from argus.intelligence.models import Investigation

class BaseHeuristic(ABC):
    
    @property
    @abstractmethod
    def id(self) -> str:
        pass
        
    @property
    @abstractmethod
    def name(self) -> str:
        pass
        
    @property
    @abstractmethod
    def description(self) -> str:
        pass
        
    @property
    @abstractmethod
    def category(self) -> str:
        pass
        
    @property
    @abstractmethod
    def required_inputs(self) -> List[str]:
        """e.g. ['authorization_graph', 'business_objects']"""
        pass
        
    @abstractmethod
    def run(self, mission: Mission) -> List[Investigation]:
        """Executes logic over the mission context to find investigation opportunities."""
        pass
        
    @abstractmethod
    def score(self, investigation: Investigation) -> float:
        """Returns a base heuristic confidence score (0.0 to 1.0) for a given investigation."""
        pass
