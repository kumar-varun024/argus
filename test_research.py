from argus.intelligence.parser import APIParser
from argus.intelligence.ranking import APIRanker
from argus.intelligence.research import ResearchGenerator

parser = APIParser()
ranker = APIRanker()
research = ResearchGenerator()

endpoint = parser.parse(
    "PATCH",
    "/api/v1/organizations/123"
)

endpoint = ranker.score(endpoint)
endpoint = research.generate(endpoint)

print(endpoint.reasoning)
print()
print(endpoint.manual_checks)
