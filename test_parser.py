from argus.intelligence.parser import APIParser

parser = APIParser()

endpoint = parser.parse(
    "POST",
    "/api/v1/organizations/123/users"
)

print(endpoint)
