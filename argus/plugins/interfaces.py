from enum import Enum
from abc import ABC, abstractmethod
from typing import Any, Dict
from argus.plugins.manifest import PluginManifest

class PluginType(str, Enum):
    COLLECTOR = "Collector"
    ANALYZER = "Analyzer"
    AI = "AI"
    WORKFLOW = "Workflow"
    AUTHORIZATION = "Authorization"
    REPORTING = "Reporting"
    CLI = "CLI"
    KNOWLEDGE = "Knowledge"

class ControlledMission:
    """
    A read-only or strictly controlled interface to the Mission object.
    Plugins should interact with this instead of the raw Mission.
    """
    def __init__(self, mission: Any):
        self._mission = mission

    @property
    def target(self) -> str:
        return self._mission.target

    @property
    def evidence(self) -> Dict[str, Any]:
        return dict(self._mission.evidence)

    def publish_finding(self, key: str, data: Any):
        """Allows safe injection of findings."""
        if not hasattr(self._mission, 'plugin_findings'):
            self._mission.plugin_findings = {}
        self._mission.plugin_findings[key] = data


class BasePlugin(ABC):
    def __init__(self, manifest: PluginManifest):
        self.manifest = manifest

    @abstractmethod
    def initialize(self):
        """Called upon successful loading."""
        pass

    @abstractmethod
    def register(self):
        """Register specific hooks, analyzers, or agents."""
        pass

    @abstractmethod
    def execute(self, mission: ControlledMission):
        """Main execution logic (if applicable)."""
        pass

    @abstractmethod
    def shutdown(self):
        """Cleanup resources."""
        pass
