import json
import pytest
from unittest.mock import MagicMock, patch

import httpx
from openai import OpenAIError

from argus.config import Config
from argus.core.mission import Mission
from argus.ai import (
    AIClient,
    NoOpAIClient,
    get_ai_client,
    GitHubClient,
    OpenAIClient,
    GeminiClient,
    Researcher,
    AIResponse,
    ResearchCard,
)


# ============================================================================
# OpenAIClient Tests
# ============================================================================

def test_openai_client_initialization_with_args():
    with patch("argus.ai.openai_client.OpenAI") as mock_openai_cls:
        client = OpenAIClient(
            api_key="test-sk-12345",
            model="gpt-4o",
            base_url="https://custom.openai.com/v1",
        )
        assert client.api_key == "test-sk-12345"
        assert client.model == "gpt-4o"
        assert client.base_url == "https://custom.openai.com/v1"
        mock_openai_cls.assert_called_once_with(
            api_key="test-sk-12345",
            base_url="https://custom.openai.com/v1",
        )


def test_openai_client_initialization_defaults():
    with patch("argus.ai.openai_client.OpenAI") as mock_openai_cls, \
         patch.object(Config, "OPENAI_API_KEY", "env-openai-key"):
        client = OpenAIClient()
        assert client.api_key == "env-openai-key"
        assert client.model == "gpt-4o-mini"
        mock_openai_cls.assert_called_once_with(api_key="env-openai-key")


def test_openai_client_research_success_json():
    client = OpenAIClient(api_key="test-key")
    mock_chat_completion = MagicMock()
    mock_choice = MagicMock()
    mock_choice.message.content = json.dumps({
        "executive_summary": "Security assessment completed.",
        "business_objects": ["User", "Invoice"],
        "business_workflows": ["Checkout flow", "Password reset"],
        "authorization_boundaries": ["Tenant isolation", "Role check"],
        "sensitive_operations": ["Transfer funds"],
        "high_value_assets": ["Database credentials"],
        "research_questions": ["Is MFA enforced?"],
        "missing_evidence": ["JWT validation logs"],
        "recommended_next_steps": ["Verify IDOR on /api/invoices"],
        "confidence": "High",
        "unknown_areas": ["Internal microservices"],
    })
    mock_chat_completion.choices = [mock_choice]

    with patch.object(client.client.chat.completions, "create", return_value=mock_chat_completion) as mock_create:
        response = client.research("Analyze target evidence")
        mock_create.assert_called_once()
        assert isinstance(response, AIResponse)
        assert response.executive_summary == "Security assessment completed."
        assert response.business_objects == ["User", "Invoice"]
        assert response.business_workflows == ["Checkout flow", "Password reset"]
        assert response.authorization_boundaries == ["Tenant isolation", "Role check"]
        assert response.sensitive_operations == ["Transfer funds"]
        assert response.high_value_assets == ["Database credentials"]
        assert response.research_questions == ["Is MFA enforced?"]
        assert response.missing_evidence == ["JWT validation logs"]
        assert response.recommended_next_steps == ["Verify IDOR on /api/invoices"]
        assert response.confidence == "High"
        assert response.unknown_areas == ["Internal microservices"]


def test_openai_client_research_markdown_json_fence():
    client = OpenAIClient(api_key="test-key")
    mock_chat_completion = MagicMock()
    mock_choice = MagicMock()
    mock_choice.message.content = """```json
{
    "executive_summary": "Summary in markdown fence",
    "business_objects": ["Account"],
    "confidence": "Medium"
}
```"""
    mock_chat_completion.choices = [mock_choice]

    with patch.object(client.client.chat.completions, "create", return_value=mock_chat_completion):
        response = client.research("Analyze target")
        assert response.executive_summary == "Summary in markdown fence"
        assert response.business_objects == ["Account"]
        assert response.confidence == "Medium"


def test_openai_client_research_malformed_json():
    client = OpenAIClient(api_key="test-key")
    mock_chat_completion = MagicMock()
    mock_choice = MagicMock()
    mock_choice.message.content = "Invalid non-JSON response from LLM"
    mock_chat_completion.choices = [mock_choice]

    with patch.object(client.client.chat.completions, "create", return_value=mock_chat_completion):
        response = client.research("Analyze target")
        assert isinstance(response, AIResponse)
        assert response.executive_summary == "No summary provided."
        assert response.business_objects == []


def test_openai_client_research_empty_content():
    client = OpenAIClient(api_key="test-key")
    mock_chat_completion = MagicMock()
    mock_choice = MagicMock()
    mock_choice.message.content = None
    mock_chat_completion.choices = [mock_choice]

    with patch.object(client.client.chat.completions, "create", return_value=mock_chat_completion):
        response = client.research("Analyze target")
        assert isinstance(response, AIResponse)
        assert response.executive_summary == "No summary provided."


def test_openai_client_research_openai_api_error():
    client = OpenAIClient(api_key="test-key")

    with patch.object(client.client.chat.completions, "create", side_effect=OpenAIError("Rate limit exceeded")):
        response = client.research("Analyze target")
        assert isinstance(response, AIResponse)
        assert "OpenAI API error" in response.executive_summary
        assert "Rate limit exceeded" in response.executive_summary
        assert response.confidence == "Low"


def test_openai_client_research_unexpected_error():
    client = OpenAIClient(api_key="test-key")

    with patch.object(client.client.chat.completions, "create", side_effect=RuntimeError("Unexpected crash")):
        response = client.research("Analyze target")
        assert isinstance(response, AIResponse)
        assert "OpenAI research error" in response.executive_summary
        assert "Unexpected crash" in response.executive_summary
        assert response.confidence == "Low"


# ============================================================================
# GeminiClient Tests
# ============================================================================

def test_gemini_client_initialization_with_args():
    client = GeminiClient(
        api_key="gemini-key-xyz",
        model="gemini-1.5-pro",
        base_url="https://custom.gemini.api/v1",
        timeout=45.0,
    )
    assert client.api_key == "gemini-key-xyz"
    assert client.model == "gemini-1.5-pro"
    assert client.base_url == "https://custom.gemini.api/v1"
    assert client.timeout == 45.0


def test_gemini_client_initialization_defaults():
    with patch.object(Config, "GEMINI_API_KEY", "env-gemini-key"):
        client = GeminiClient()
        assert client.api_key == "env-gemini-key"
        assert client.model == "gemini-1.5-flash"
        assert "generativelanguage.googleapis.com" in client.base_url
        assert client.timeout == 30.0


def test_gemini_client_research_missing_api_key():
    with patch.object(Config, "GEMINI_API_KEY", None), \
         patch.dict("os.environ", {}, clear=True):
        client = GeminiClient(api_key=None)
        response = client.research("Analyze target")
        assert isinstance(response, AIResponse)
        assert "Gemini API key not configured" in response.executive_summary
        assert response.confidence == "Low"


def test_gemini_client_research_success_json():
    client = GeminiClient(api_key="valid-gemini-key")
    gemini_api_payload = {
        "candidates": [
            {
                "content": {
                    "parts": [
                        {
                            "text": json.dumps({
                                "executive_summary": "Gemini security analysis complete.",
                                "business_objects": ["PaymentGateway", "Merchant"],
                                "business_workflows": ["Refund processing"],
                                "authorization_boundaries": ["Admin role required"],
                                "sensitive_operations": ["Issue refund"],
                                "high_value_assets": ["Payment private keys"],
                                "research_questions": ["Can refund amount be negative?"],
                                "missing_evidence": ["Refund endpoint response body"],
                                "recommended_next_steps": ["Probe /api/refunds for race conditions"],
                                "confidence": "High",
                                "unknown_areas": ["Settlement worker"],
                            })
                        }
                    ]
                }
            }
        ]
    }

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = gemini_api_payload

    with patch("httpx.Client.post", return_value=mock_resp) as mock_post:
        response = client.research("Analyze mission target")
        mock_post.assert_called_once()
        assert isinstance(response, AIResponse)
        assert response.executive_summary == "Gemini security analysis complete."
        assert response.business_objects == ["PaymentGateway", "Merchant"]
        assert response.business_workflows == ["Refund processing"]
        assert response.authorization_boundaries == ["Admin role required"]
        assert response.sensitive_operations == ["Issue refund"]
        assert response.high_value_assets == ["Payment private keys"]
        assert response.research_questions == ["Can refund amount be negative?"]
        assert response.missing_evidence == ["Refund endpoint response body"]
        assert response.recommended_next_steps == ["Probe /api/refunds for race conditions"]
        assert response.confidence == "High"
        assert response.unknown_areas == ["Settlement worker"]


def test_gemini_client_research_markdown_fence():
    client = GeminiClient(api_key="valid-gemini-key")
    gemini_api_payload = {
        "candidates": [
            {
                "content": {
                    "parts": [
                        {
                            "text": """```json
{
    "executive_summary": "Gemini fenced analysis",
    "business_objects": ["UserSession"],
    "confidence": "Medium"
}
```"""
                        }
                    ]
                }
            }
        ]
    }

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = gemini_api_payload

    with patch("httpx.Client.post", return_value=mock_resp):
        response = client.research("Analyze mission target")
        assert response.executive_summary == "Gemini fenced analysis"
        assert response.business_objects == ["UserSession"]
        assert response.confidence == "Medium"


def test_gemini_client_research_no_candidates():
    client = GeminiClient(api_key="valid-gemini-key")
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"candidates": []}

    with patch("httpx.Client.post", return_value=mock_resp):
        response = client.research("Analyze mission target")
        assert isinstance(response, AIResponse)
        assert "Gemini API returned no candidates" in response.executive_summary
        assert response.confidence == "Low"


def test_gemini_client_research_http_error_response():
    client = GeminiClient(api_key="valid-gemini-key")
    mock_resp = MagicMock()
    mock_resp.status_code = 403
    mock_resp.text = "Forbidden: Invalid API key"

    with patch("httpx.Client.post", return_value=mock_resp):
        response = client.research("Analyze mission target")
        assert isinstance(response, AIResponse)
        assert "Gemini API error (HTTP 403)" in response.executive_summary
        assert "Forbidden: Invalid API key" in response.executive_summary
        assert response.confidence == "Low"


def test_gemini_client_research_httpx_request_error():
    client = GeminiClient(api_key="valid-gemini-key")

    with patch("httpx.Client.post", side_effect=httpx.ConnectTimeout("Connection timed out")):
        response = client.research("Analyze mission target")
        assert isinstance(response, AIResponse)
        assert "Gemini HTTP error" in response.executive_summary
        assert "Connection timed out" in response.executive_summary
        assert response.confidence == "Low"


def test_gemini_client_research_unexpected_error():
    client = GeminiClient(api_key="valid-gemini-key")

    with patch("httpx.Client.post", side_effect=ValueError("Invalid JSON in transport")):
        response = client.research("Analyze mission target")
        assert isinstance(response, AIResponse)
        assert "Gemini research error" in response.executive_summary
        assert "Invalid JSON in transport" in response.executive_summary
        assert response.confidence == "Low"


# ============================================================================
# get_ai_client & Provider Resolution Tests
# ============================================================================

def test_get_ai_client_openai():
    with patch("argus.ai.openai_client.OpenAI"):
        client = get_ai_client("openai")
        assert isinstance(client, OpenAIClient)


def test_get_ai_client_gemini():
    client = get_ai_client("gemini")
    assert isinstance(client, GeminiClient)


def test_get_ai_client_github():
    with patch("argus.ai.github_client.OpenAI"):
        client = get_ai_client("github")
        assert isinstance(client, GitHubClient)


@pytest.mark.parametrize("provider_name", ["none", "NONE", "", "disabled", "null"])
def test_get_ai_client_none_and_disabled(provider_name):
    client = get_ai_client(provider_name)
    assert isinstance(client, NoOpAIClient)
    assert isinstance(client, AIClient)
    response = client.research("Test prompt")
    assert isinstance(response, AIResponse)
    assert "provider is set to 'none'" in response.executive_summary


def test_get_ai_client_default_from_config():
    with patch.object(Config, "AI_PROVIDER", "none"):
        client = get_ai_client()
        assert isinstance(client, NoOpAIClient)


def test_get_ai_client_unknown_provider_raises():
    with pytest.raises(ValueError, match="Unknown AI provider: unsupported_provider"):
        get_ai_client("unsupported_provider")


# ============================================================================
# Module Exports and Researcher Integration Tests
# ============================================================================

def test_argus_ai_module_exports():
    import argus.ai as ai_mod
    assert hasattr(ai_mod, "AIClient")
    assert hasattr(ai_mod, "NoOpAIClient")
    assert hasattr(ai_mod, "get_ai_client")
    assert hasattr(ai_mod, "GitHubClient")
    assert hasattr(ai_mod, "OpenAIClient")
    assert hasattr(ai_mod, "GeminiClient")
    assert hasattr(ai_mod, "Researcher")
    assert hasattr(ai_mod, "AIResponse")
    assert hasattr(ai_mod, "ResearchCard")


@patch("argus.ai.researcher.get_ai_client")
def test_researcher_with_openai_client(mock_get_client):
    mock_openai = MagicMock(spec=OpenAIClient)
    mock_openai.research.return_value = AIResponse(executive_summary="OpenAI Summary")
    mock_get_client.return_value = mock_openai

    researcher = Researcher()
    mission = Mission("https://example.com")
    result = researcher.analyze(mission)

    assert result.executive_summary == "OpenAI Summary"
    mock_openai.research.assert_called_once()


@patch("argus.ai.researcher.get_ai_client")
def test_researcher_with_gemini_client(mock_get_client):
    mock_gemini = MagicMock(spec=GeminiClient)
    mock_gemini.research.return_value = AIResponse(executive_summary="Gemini Summary")
    mock_get_client.return_value = mock_gemini

    researcher = Researcher()
    mission = Mission("https://example.com")
    result = researcher.analyze(mission)

    assert result.executive_summary == "Gemini Summary"
    mock_gemini.research.assert_called_once()


@patch("argus.ai.researcher.get_ai_client")
def test_researcher_with_noop_client(mock_get_client):
    mock_noop = NoOpAIClient()
    mock_get_client.return_value = mock_noop

    researcher = Researcher()
    mission = Mission("https://example.com")
    result = researcher.analyze(mission)

    assert "provider is set to 'none'" in result.executive_summary
