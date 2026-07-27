import pytest
from unittest.mock import MagicMock, patch

from argus.core.mission import Mission
from argus.ai.context import ContextBuilder
from argus.ai.prompts import build_research_prompt
from argus.ai.models import AIResponse
from argus.ai.github_client import GitHubClient
from argus.ai.researcher import Researcher

class DummyAuth:
    authentication_type = "OAuth2"
    token_type = "Bearer"

class DummyBO:
    name = "User"

class DummyEndpoint:
    priority = "HIGH"
    method = "POST"
    path = "/api/v1/users"

def test_context_builder():
    mission = Mission("https://hackerone.com")
    mission.technologies = ["Cloudflare"]
    mission.authentication = DummyAuth()
    mission.business_objects = [DummyBO()]
    mission.api_intelligence = [DummyEndpoint()]

    builder = ContextBuilder()
    context = builder.build(mission)

    assert context["Mission Target"] == "https://hackerone.com"
    assert "Cloudflare" in context["Technology Intelligence"]
    assert "User" in context["Business Objects"]
    assert "Auth Type: OAuth2" in context["Authentication Intelligence"]
    assert "POST /api/v1/users" in context["High-Risk APIs"]

def test_prompt_builder():
    mission = Mission("https://example.com")
    prompt = build_research_prompt(mission)
    
    assert "TARGET CONTEXT:" in prompt
    assert "Never claim a vulnerability." in prompt
    assert "https://example.com" in prompt
    assert "business_objects" in prompt

def test_github_client_parsing():
    # Mocking OpenAI response parsing
    client = GitHubClient()
    mock_response = MagicMock()
    mock_response.choices = [MagicMock()]
    mock_response.choices[0].message.content = '''{
        "executive_summary": "Test Summary",
        "business_objects": ["BO1", "BO2"],
        "confidence": "High"
    }'''
    
    with patch.object(client, "client") as mock_openai:
        mock_openai.chat.completions.create.return_value = mock_response
        response = client.research("test prompt")
        
        assert response.executive_summary == "Test Summary"
        assert "BO1" in response.business_objects
        assert response.confidence == "High"
        assert response.high_value_assets == []

@patch('argus.ai.researcher.get_ai_client')
def test_researcher_integration(mock_get_ai_client):
    mock_client = MagicMock()
    mock_client.research.return_value = AIResponse(executive_summary="Done")
    mock_get_ai_client.return_value = mock_client
    
    researcher = Researcher()
    mission = Mission("https://test.com")
    
    result = researcher.analyze(mission)
    assert result.executive_summary == "Done"
    mock_client.research.assert_called_once()
