from argus.agents.base import BaseAgent

class FileUploadAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            name="File Upload Agent",
            description="Analyzes file upload endpoints.",
            dependencies=["API Intelligence"],
            supported_inputs=["file_upload"]
        )
        self._recommendations = []

    def think(self, mission):
        pass

    def execute(self, mission):
        self._recommendations.append("Test file extension bypasses")
        self._recommendations.append("Check for path traversal in upload destinations")

    def evaluate(self, mission):
        pass

    def produce(self) -> list:
        return self._recommendations
