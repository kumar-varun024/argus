from abc import ABC, abstractmethod


class BaseAgent(ABC):
    """
    Base class for every Argus agent.
    """

    def __init__(self, name: str, description: str = "", dependencies: list[str] = None, supported_inputs: list[str] = None):
        self.name = name
        self.description = description
        self.dependencies = dependencies or []
        self.supported_inputs = supported_inputs or []

    def run(self, mission):
        """
        Standard lifecycle for every agent.
        """

        print(f"\n[{self.name}] Thinking...")
        self.think(mission)

        print(f"[{self.name}] Executing...")
        self.execute(mission)

        print(f"[{self.name}] Evaluating...")
        self.evaluate(mission)

        print(f"[{self.name}] Finished.\n")

    @abstractmethod
    def think(self, mission):
        pass

    @abstractmethod
    def execute(self, mission):
        pass

    @abstractmethod
    def evaluate(self, mission):
        pass

    def produce(self) -> list:
        return []

    def confidence(self) -> float:
        return 1.0

    def health(self) -> str:
        from argus.agents.results import AgentHealth
        return AgentHealth.HEALTHY
