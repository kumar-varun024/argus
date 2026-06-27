from abc import ABC, abstractmethod


class BaseAgent(ABC):
    """
    Base class for every Argus agent.
    """

    def __init__(self, name: str):
        self.name = name

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
