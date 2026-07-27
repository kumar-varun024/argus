from argus.intelligence.parser import APIParser
from argus.intelligence.ranking import APIRanker

parser = APIParser()
ranker = APIRanker()

endpoint = parser.parse(
    "PATCH",
    "/api/v1/organizations/123"
)

endpoint = ranker.score(endpoint)

print(endpoint.priority)
print(endpoint.risk_score)
