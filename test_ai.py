from argus.ai.github_client import GitHubClient

client = GitHubClient()

response = client.research(
    """
Target:
https://hackerone.com

Technologies:
Cloudflare

Authentication:
OAuth2

APIs:
/api/v1/organizations
PATCH /api/v1/users/{id}
POST /api/v1/invitations
"""
)

print(response.summary)
