from .parser import APIParser
from .ranking import APIRanker
from .research import ResearchGenerator


class APIIntelligence:

    def __init__(self):

        self.parser = APIParser()

        self.ranker = APIRanker()

        self.research = ResearchGenerator()

    def analyze(self, mission):

        print("\nAPI Intelligence...")

        mission.api_intelligence = []

        for endpoint in mission.endpoints:

            method = endpoint.get("method", "GET")

            path = endpoint.get("url", "")

            api = self.parser.parse(
                method,
                path,
            )

            api = self.ranker.score(api)

            api = self.research.generate(api)

            mission.api_intelligence.append(api)

        print(f"✓ Analysed {len(mission.api_intelligence)} endpoints")
