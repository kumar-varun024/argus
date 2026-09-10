import os
import pytest
import asyncio
from unittest.mock import patch, MagicMock
from argus.workspace.provider import ProviderError, Message, MockModelProvider
from argus.workspace.provider_router import get_default_provider, ProviderRouter

@pytest.fixture
def mock_env(monkeypatch):
    vars_to_clear = [
        "OPENAI_API_KEY", "OPENAI_MODEL_NAME", "OPENAI_API_BASE",
        "DEEPSEEK_API_KEY", "DEEPSEEK_MODEL_NAME", "DEEPSEEK_API_BASE",
        "GEMINI_API_KEY", "GEMINI_MODEL_NAME",
        "GITHUB_API_KEY", "GITHUB_TOKEN", "GITHUB_MODEL", "GITHUB_MODEL_NAME", "GITHUB_API_BASE",
        "NVIDIA_API_KEY", "NVIDIA_MODEL_NAME", "NVIDIA_API_BASE",
        "NVIDIA_ULTRA_API_KEY", "NVIDIA_ULTRA_MODEL_NAME", "NVIDIA_ULTRA_API_BASE",
        "OPENROUTER_API_KEY", "OPENROUTER_MODEL_NAME", "OPENROUTER_API_BASE",
        "GROQ_API_KEY", "GROQ_MODEL_NAME", "GROQ_API_BASE", "GROQ_VISION_MODEL",
        "LOCAL_API_KEY", "LOCAL_MODEL_NAME", "LOCAL_API_BASE",
        "ARGUS_PRIMARY_PROVIDER", "ARGUS_PRIMARY_MODEL", "ARGUS_PROVIDER_ORDER", "ARGUS_LLM_PROVIDER"
    ]
    for var in vars_to_clear:
        monkeypatch.delenv(var, raising=False)
    
def test_single_provider_success(mock_env, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    router = get_default_provider()
    assert isinstance(router, ProviderRouter)
    assert len(router.routes) == 1
    assert router.routes[0].provider_name == "openai"

def test_github_provider_route(mock_env, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "gh-test-token")
    monkeypatch.setenv("GITHUB_MODEL", "gpt-4-test")
    router = get_default_provider()
    assert len(router.routes) == 1
    assert router.routes[0].provider_name == "github"
    assert router.routes[0].api_key == "gh-test-token"
    assert router.routes[0].model_name == "gpt-4-test"
    assert router.routes[0].api_base == "https://models.github.ai/inference"
    
def test_primary_provider_priority(mock_env, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "test-key-2")
    monkeypatch.setenv("NVIDIA_API_KEY", "test-key-3")
    monkeypatch.setenv("GITHUB_API_KEY", "test-key-4")
    monkeypatch.setenv("ARGUS_PRIMARY_PROVIDER", "nvidia")
    monkeypatch.setenv("ARGUS_PRIMARY_MODEL", "nvidia-custom")
    monkeypatch.setenv("ARGUS_PROVIDER_ORDER", "github, openai")
    
    router = get_default_provider()
    routes = router.routes
    assert len(routes) == 4
    assert routes[0].provider_name == "nvidia"
    assert routes[0].model_name == "nvidia-custom"
    
    assert routes[1].provider_name == "github"
    assert routes[2].provider_name == "openai"
    assert routes[3].provider_name == "deepseek"

def test_failover_429(mock_env, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "test-key-2")
    
    router = get_default_provider()
    
    with patch.object(router.routes[0].provider_instance, 'generate') as mock_1, \
         patch.object(router.routes[1].provider_instance, 'generate') as mock_2:
         
        mock_1.side_effect = ProviderError("429 Too Many Requests", retryable=True)
        mock_2.return_value = "Success from DeepSeek"
        
        result = router.generate([Message(role="user", text="hello")])
        assert result == "Success from DeepSeek"
        assert mock_1.call_count == 1
        assert mock_2.call_count == 1
        assert not router.routes[0].is_healthy()
        assert router.routes[1].is_healthy()

def test_per_provider_error_fails_over(mock_env, monkeypatch):
    """A per-provider non-retryable error (e.g. 402 Payment Required, a dead
    quota on ONE provider) must fail over to the next route -- it says nothing
    about the other providers. This is the router's whole purpose."""
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "test-key-2")

    router = get_default_provider()

    with patch.object(router.routes[0].provider_instance, 'generate') as mock_1, \
         patch.object(router.routes[1].provider_instance, 'generate') as mock_2:

        mock_1.side_effect = ProviderError("402 Payment Required", retryable=False, status_code=402)
        mock_2.return_value = "Success from second provider"

        result = router.generate([Message(role="user", text="hello")])
        assert result == "Success from second provider"
        assert mock_1.call_count == 1
        assert mock_2.call_count == 1


def test_dead_credential_disables_route_then_fails_over(mock_env, monkeypatch):
    """A 401/403 disables that route for the session (dead credential) but still
    fails over to the next healthy route."""
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "test-key-2")

    router = get_default_provider()

    with patch.object(router.routes[0].provider_instance, 'generate') as mock_1, \
         patch.object(router.routes[1].provider_instance, 'generate') as mock_2:

        mock_1.side_effect = ProviderError("401 Unauthorized", retryable=False, status_code=401)
        mock_2.return_value = "Success from second provider"

        result = router.generate([Message(role="user", text="hello")])
        assert result == "Success from second provider"
        assert router.routes[0].enabled is False
        assert mock_2.call_count == 1


def test_malformed_request_400_is_fatal(mock_env, monkeypatch):
    """A 400 is our own malformed request -- it would fail identically on every
    provider, so it aborts the chain immediately without trying the next one."""
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "test-key-2")

    router = get_default_provider()

    with patch.object(router.routes[0].provider_instance, 'generate') as mock_1, \
         patch.object(router.routes[1].provider_instance, 'generate') as mock_2:

        mock_1.side_effect = ProviderError("400 Bad Request", retryable=False, status_code=400)

        with pytest.raises(ProviderError):
            router.generate([Message(role="user", text="hello")])

        assert mock_1.call_count == 1
        assert mock_2.call_count == 0

def test_multimodal_uses_only_vision_routes(mock_env, monkeypatch):
    """An image request must never be sent to a text-only route (e.g. nvidia
    nemotron); it should skip straight to a vision-capable route."""
    monkeypatch.setenv("NVIDIA_API_KEY", "k1")
    monkeypatch.setenv("GEMINI_API_KEY", "k2")
    router = get_default_provider()
    nvidia = next(r for r in router.routes if r.provider_name == "nvidia")
    gemini = next(r for r in router.routes if r.provider_name == "gemini")
    assert nvidia.supports_vision is False
    assert gemini.supports_vision is True

    with patch.object(nvidia.provider_instance, 'multimodal_generate') as mm_nvidia, \
         patch.object(gemini.provider_instance, 'multimodal_generate') as mm_gemini:
        mm_gemini.return_value = "saw the image"
        result = router.multimodal_generate([Message(role="user", text="hi")], [])
        assert result == "saw the image"
        mm_nvidia.assert_not_called()
        mm_gemini.assert_called_once()


def test_multimodal_no_vision_route_errors_clearly(mock_env, monkeypatch):
    """With only text-only routes, an image request must fail with a clear
    'no vision-capable provider' message, not a confusing downstream 400."""
    monkeypatch.setenv("NVIDIA_API_KEY", "k1")
    router = get_default_provider()
    assert all(not r.supports_vision for r in router.routes)
    with pytest.raises(ProviderError, match="vision-capable"):
        router.multimodal_generate([Message(role="user", text="hi")], [])


def test_openrouter_route_is_vision_capable(mock_env, monkeypatch):
    """The OpenRouter slot is built as a vision-capable route so it can back up
    Gemini for image requests."""
    monkeypatch.setenv("OPENROUTER_API_KEY", "or-key")
    router = get_default_provider()
    orr = next(r for r in router.routes if r.provider_name == "openrouter")
    assert orr.supports_vision is True
    assert "openrouter.ai" in orr.api_base


def test_groq_route_built_as_text_fallback(mock_env, monkeypatch):
    """Groq is wired as a fast OpenAI-compatible TEXT fallback (replacing the
    unreliable NVIDIA endpoint); it is not marked vision-capable."""
    monkeypatch.setenv("GROQ_API_KEY", "gq-key")
    router = get_default_provider()
    groq = next(r for r in router.routes if r.provider_name == "groq")
    assert "api.groq.com" in groq.api_base
    assert groq.supports_vision is False


def test_groq_provides_a_vision_route(mock_env, monkeypatch):
    """The Groq key also builds a vision-capable route (Qwen) so attach-image
    chat has a reliable fallback when the free Gemini/OpenRouter tiers throttle."""
    monkeypatch.setenv("GROQ_API_KEY", "gq-key")
    router = get_default_provider()
    gv = next((r for r in router.routes if r.provider_name == "groq_vision"), None)
    assert gv is not None
    assert gv.supports_vision is True
    assert "api.groq.com" in gv.api_base
    # and it participates in the vision-only multimodal path
    with patch.object(gv.provider_instance, "multimodal_generate") as mm:
        mm.return_value = "groq saw it"
        assert router.multimodal_generate([Message(role="user", text="hi")], []) == "groq saw it"


def test_multimodal_fails_over_between_vision_routes(mock_env, monkeypatch):
    """When the primary vision route (Gemini) throttles, the image request fails
    over to the OpenRouter vision route rather than aborting."""
    monkeypatch.setenv("GEMINI_API_KEY", "k2")
    monkeypatch.setenv("OPENROUTER_API_KEY", "or-key")
    monkeypatch.setenv("ARGUS_PRIMARY_PROVIDER", "gemini")
    router = get_default_provider()
    gemini = next(r for r in router.routes if r.provider_name == "gemini")
    orr = next(r for r in router.routes if r.provider_name == "openrouter")

    with patch.object(gemini.provider_instance, 'multimodal_generate') as mm_gemini, \
         patch.object(orr.provider_instance, 'multimodal_generate') as mm_or:
        mm_gemini.side_effect = ProviderError("throttled", retryable=True, status_code=429)
        mm_or.return_value = "openrouter saw it"
        result = router.multimodal_generate([Message(role="user", text="hi")], [])
        assert result == "openrouter saw it"
        mm_gemini.assert_called_once()
        mm_or.assert_called_once()


def test_cooldown_behavior(mock_env, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    router = get_default_provider()
    router.cooldown_seconds = -1.0 # Immediately recovers
    
    with patch.object(router.routes[0].provider_instance, 'generate') as mock_1:
        mock_1.side_effect = ProviderError("429", retryable=True)
        
        with pytest.raises(ProviderError, match="All providers exhausted"):
            router.generate([Message(role="user", text="hello")])
            
        assert router.routes[0].is_healthy() # should have recovered due to -1s cooldown

def test_all_providers_fail(mock_env, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "test-key-2")
    
    router = get_default_provider()
    
    with patch.object(router.routes[0].provider_instance, 'generate') as mock_1, \
         patch.object(router.routes[1].provider_instance, 'generate') as mock_2:
         
        mock_1.side_effect = ProviderError("429", retryable=True)
        mock_2.side_effect = ProviderError("500", retryable=True)
        
        with pytest.raises(ProviderError, match="All providers exhausted"):
            router.generate([Message(role="user", text="hello")])
            
def test_disabled_or_missing_credentials(mock_env, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    # Missing deepseek key
    router = get_default_provider()
    assert len(router.routes) == 1
    assert router.routes[0].provider_name == "openai"
    
def test_streaming_success(mock_env, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    router = get_default_provider()
    
    async def mock_stream(*args, **kwargs):
        yield "hello "
        yield "world"
        
    with patch.object(router.routes[0].provider_instance, 'stream') as mock_1:
        mock_1.side_effect = mock_stream
        
        async def run_test():
            result = []
            async for chunk in router.stream([Message(role="user", text="hi")]):
                result.append(chunk)
            return "".join(result)
            
        assert asyncio.run(run_test()) == "hello world"

def test_streaming_failure_before_tokens(mock_env, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "test-key-2")
    
    router = get_default_provider()
    
    async def fail_stream(*args, **kwargs):
        raise ProviderError("429", retryable=True)
        yield ""
        
    async def succ_stream(*args, **kwargs):
        yield "deepseek rocks"
        
    with patch.object(router.routes[0].provider_instance, 'stream') as mock_1, \
         patch.object(router.routes[1].provider_instance, 'stream') as mock_2:
         
        mock_1.side_effect = fail_stream
        mock_2.side_effect = succ_stream
        
        async def run_test():
            result = []
            async for chunk in router.stream([Message(role="user", text="hi")]):
                result.append(chunk)
            return "".join(result)
            
        assert asyncio.run(run_test()) == "deepseek rocks"
        
def test_streaming_failure_after_tokens(mock_env, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "test-key-2")
    
    router = get_default_provider()
    
    async def fail_stream(*args, **kwargs):
        yield "token1"
        raise ProviderError("500", retryable=True)
        
    with patch.object(router.routes[0].provider_instance, 'stream') as mock_1:
        mock_1.side_effect = fail_stream
        
        async def run_test():
            result = []
            async for chunk in router.stream([Message(role="user", text="hi")]):
                result.append(chunk)
            return "".join(result)
            
        with pytest.raises(ProviderError, match="500"):
            asyncio.run(run_test())

def test_mock_fallback(mock_env):
    router = get_default_provider()
    assert len(router.routes) == 1
    assert router.routes[0].provider_name == "mock"
    assert isinstance(router.routes[0].provider_instance, MockModelProvider)
