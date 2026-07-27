from argus.agents.base import BaseAgent

class RESTAPIAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            name="REST API Agent",
            description="Analyzes REST API patterns and endpoints.",
            dependencies=["API Intelligence", "Knowledge Graph"],
            supported_inputs=["api"]
        )
        self._recommendations = []

    def think(self, mission):
        pass

    def execute(self, mission):
        self._recommendations.append("Fuzz undocumented parameters")
        self._recommendations.append("Check for BOLA on ID endpoints")

    def evaluate(self, mission):
        pass

    def produce(self) -> list:
        return self._recommendations
