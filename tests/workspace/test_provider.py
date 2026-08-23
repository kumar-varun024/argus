import pytest
import os
import httpx
from unittest.mock import patch, MagicMock, AsyncMock

from argus.workspace.provider import (
     
    MockModelProvider, 
    OpenAICompatibleProvider,
    ProviderError
)
from argus.workspace.models import Message

@pytest.fixture
def mock_env():
    # Store original
    old_env = dict(os.environ)
    yield
    # Restore original
    os.environ.clear()
    os.environ.update(old_env)

def test_mock_completion():
    provider = MockModelProvider()
    resp = provider.generate([Message(role="user", text="hello")])
    assert "mocked response" in resp

import asyncio

def test_mock_streaming():
    provider = MockModelProvider()
    chunks = []
    
    async def run_test():
        async for chunk in provider.stream([Message(role="user", text="hello")]):
            chunks.append(chunk)
            
    asyncio.run(run_test())
    
    assert len(chunks) > 0
    assert "".join(chunks) == "This is a mocked streamed response."

@patch("httpx.Client.post")
def test_openai_completion_success(mock_post):
    mock_resp = MagicMock()
    mock_resp.json.return_value = {
        "choices": [{"message": {"content": "Hello from OpenAI!"}}]
    }
    mock_post.return_value = mock_resp
    
    provider = OpenAICompatibleProvider("http://base", "key", "model")
    res = provider.generate([Message(role="user", text="hi")])
    assert res == "Hello from OpenAI!"
    
@patch("httpx.Client.post")
def test_openai_completion_error(mock_post):
    mock_post.side_effect = httpx.HTTPStatusError("401 Unauthorized", request=MagicMock(), response=MagicMock(status_code=500))
    
    provider = OpenAICompatibleProvider("http://base", "key", "model")
    with pytest.raises(ProviderError):
        provider.generate([Message(role="user", text="hi")])

@patch("httpx.AsyncClient.stream")
def test_openai_streaming_success(mock_stream):
    class AsyncContextManagerMock:
        async def __aenter__(self):
            resp_mock = MagicMock()
            
            async def aiter_lines():
                yield 'data: {"choices": [{"delta": {"content": "Hello"}}]}'
                yield 'data: {"choices": [{"delta": {"content": " stream!"}}]}'
                yield 'data: [DONE]'
            
            resp_mock.aiter_lines = aiter_lines
            return resp_mock
            
        async def __aexit__(self, exc_type, exc, tb):
            pass

    mock_stream.return_value = AsyncContextManagerMock()
    
    provider = OpenAICompatibleProvider("http://base", "key", "model")
    chunks = []
    
    async def run_test():
        async for chunk in provider.stream([Message(role="user", text="hi")]):
            chunks.append(chunk)
            
    asyncio.run(run_test())
        
    assert "".join(chunks) == "Hello stream!"

@patch("httpx.AsyncClient.stream")
def test_openai_streaming_error(mock_stream):
    class AsyncContextManagerMock:
        async def __aenter__(self):
            resp_mock = MagicMock()
            resp_mock.raise_for_status.side_effect = httpx.HTTPStatusError("500 Error", request=MagicMock(), response=MagicMock(status_code=500))
            return resp_mock
            
        async def __aexit__(self, exc_type, exc, tb):
            pass
            
    mock_stream.return_value = AsyncContextManagerMock()
    
    provider = OpenAICompatibleProvider("http://base", "key", "model")
    
    async def run_test():
        async for _ in provider.stream([Message(role="user", text="hi")]):
            pass
            
    with pytest.raises(ProviderError):
        asyncio.run(run_test())

@patch("httpx.Client.post")
def test_gemini_completion(mock_post):
    from argus.workspace.provider import GeminiProvider
    mock_resp = MagicMock()
    mock_resp.json.return_value = {
        "candidates": [
            {"content": {"parts": [{"text": "Hello from Gemini"}]}}
        ]
    }
    mock_post.return_value = mock_resp
    
    provider = GeminiProvider("key", "model")
    res = provider.generate([Message(role="user", text="hi")])
    assert res == "Hello from Gemini"

@patch("httpx.AsyncClient.stream")
def test_gemini_streaming(mock_stream):
    from argus.workspace.provider import GeminiProvider
    class AsyncContextManagerMock:
        async def __aenter__(self):
            resp_mock = MagicMock()
            
            async def aiter_lines():
                yield 'data: {"candidates": [{"content": {"parts": [{"text": "Hello "}]}}]}'
                yield 'data: {"candidates": [{"content": {"parts": [{"text": "Gemini!"}]}}]}'
                yield 'data: '
            
            resp_mock.aiter_lines = aiter_lines
            return resp_mock
            
        async def __aexit__(self, exc_type, exc, tb):
            pass

    mock_stream.return_value = AsyncContextManagerMock()
    
    provider = GeminiProvider("key", "model")
    chunks = []
    
    async def run_test():
        async for chunk in provider.stream([Message(role="user", text="hi")]):
            chunks.append(chunk)
            
    asyncio.run(run_test())
    assert "".join(chunks) == "Hello Gemini!"

@patch("argus.workspace.provider.Path")
def test_multimodal_request_translation(mock_path):
    # Mock file reading
    mock_file = MagicMock()
    mock_file.exists.return_value = True
    mock_file.read_bytes.return_value = b"fake-image-data"
    mock_path.return_value = mock_file
    
    from argus.workspace.models import ImageAttachment
    from argus.workspace.provider import GeminiProvider
    
    provider = GeminiProvider("key", "model")
    msg = Message(role="user", text="Look at this")
    att = ImageAttachment(filename="test.png", mime_type="image/png", storage_reference="/tmp/test.png")
    msg.attachments = [att]
    
    payload = provider._format_messages([msg], "", [att])
    
    # Verify the structure matches Gemini's expected format with inline_data
    parts = payload["contents"][0]["parts"]
    assert parts[0]["text"] == "Look at this"
    assert "inline_data" in parts[1]
    assert parts[1]["inline_data"]["mime_type"] == "image/png"
    import base64
    assert parts[1]["inline_data"]["data"] == base64.b64encode(b"fake-image-data").decode("utf-8")

