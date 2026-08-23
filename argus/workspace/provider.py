import os
import json
import httpx
import base64
import time
from pathlib import Path
from abc import ABC, abstractmethod
from typing import List, Dict, Any, AsyncGenerator, Optional
from argus.workspace.models import Message, ImageAttachment

class ProviderError(Exception):
    """Exception raised for provider-specific failures."""
    def __init__(self, message: str, retryable: bool = False, status_code: Optional[int] = None):
        super().__init__(message)
        self.retryable = retryable
        self.status_code = status_code

def _is_retryable_httpx_error(e: httpx.HTTPError) -> bool:
    if isinstance(e, httpx.HTTPStatusError):
        code = e.response.status_code
        if code in (400, 404):
            return False
        return code in (401, 403, 429) or 500 <= code < 600
    if isinstance(e, httpx.RequestError):
        return True
    return False

class AIModelProvider(ABC):
    """Abstract base class for all AI models (OpenAI, Anthropic, Local)."""
    
    @abstractmethod
    def model_name(self) -> str:
        """Returns the name of the model being used."""
        pass
    
    @abstractmethod
    def capabilities(self) -> Dict[str, bool]:
        """Returns the capabilities of this provider (e.g., {'vision': True, 'streaming': True})."""
        pass
        
    @abstractmethod
    def count_tokens(self, text: str) -> int:
        """Estimates the number of tokens in the given text."""
        pass
        
    @abstractmethod
    def generate(self, messages: List[Message], system_prompt: str = "", **kwargs) -> str:
        """Generates a text response synchronously."""
        pass
        
    @abstractmethod
    async def stream(self, messages: List[Message], system_prompt: str = "", **kwargs) -> AsyncGenerator[str, None]:
        """Generates a text response asynchronously, yielding tokens."""
        pass
        
    @abstractmethod
    def multimodal_generate(self, messages: List[Message], images: List[ImageAttachment], system_prompt: str = "", **kwargs) -> str:
        """Generates a response considering both text messages and images."""
        pass


class MockModelProvider(AIModelProvider):
    """A mock provider used for the foundation PR and testing."""
    
    def model_name(self) -> str:
        return "mock-model-v1"
    
    def capabilities(self) -> Dict[str, bool]:
        return {"vision": True, "streaming": True}
        
    def count_tokens(self, text: str) -> int:
        return len(text.split())
        
    def generate(self, messages: List[Message], system_prompt: str = "", **kwargs) -> str:
        self.last_system_prompt = system_prompt
        base_resp = "This is a mocked response from the Argus MockModelProvider."
        if "CITATIONS" in system_prompt:
            base_resp += " Here is an evidence reference: [Evidence #test-id]"
        return base_resp
        
    async def stream(self, messages: List[Message], system_prompt: str = "", **kwargs) -> AsyncGenerator[str, None]:
        words = ["This", " is", " a", " mocked", " streamed", " response."]
        for w in words:
            yield w
            
    def multimodal_generate(self, messages: List[Message], images: List[ImageAttachment], system_prompt: str = "", **kwargs) -> str:
        base_resp = f"I have analyzed {len(images)} images and conclude that there might be something interesting. (Mocked)"
        if "CITATIONS" in system_prompt:
            base_resp += " [Screenshot Test]"
        return base_resp

class OpenAICompatibleProvider(AIModelProvider):
    def __init__(self, api_base: str, api_key: str, model: str):
        self.api_base = api_base.rstrip("/")
        self.api_key = api_key
        self.model = model
        
    def model_name(self) -> str:
        return self.model
        
    def capabilities(self) -> Dict[str, bool]:
        return {"vision": True, "streaming": True}
        
    def count_tokens(self, text: str) -> int:
        return len(text.split())
        
    def _format_messages(self, messages: List[Message], system_prompt: str = "", images: List[ImageAttachment] = None) -> List[Dict[str, Any]]:
        formatted = []
        if system_prompt:
            formatted.append({"role": "system", "content": system_prompt})
            
        for msg in messages:
            if msg.role == "user" and msg.attachments and images:
                content = [{"type": "text", "text": msg.text}]
                for att in msg.attachments:
                    try:
                        path = Path(att.storage_reference)
                        if path.exists():
                            b64 = base64.b64encode(path.read_bytes()).decode('utf-8')
                            content.append({"type": "image_url", "image_url": {"url": f"data:{att.mime_type};base64,{b64}"}})
                        else:
                            content.append({"type": "text", "text": f"[Missing image: {att.filename}]"})
                    except Exception:
                        content.append({"type": "text", "text": f"[Error reading image: {att.filename}]"})
                formatted.append({"role": msg.role, "content": content})
            else:
                formatted.append({"role": msg.role, "content": msg.text})
        return formatted
        
    def generate(self, messages: List[Message], system_prompt: str = "", **kwargs) -> str:
        url = f"{self.api_base}/chat/completions"
        headers = {"Authorization": f"Bearer {self.api_key}"}
        payload = {
            "model": self.model,
            "messages": self._format_messages(messages, system_prompt)
        }
        try:
            with httpx.Client(timeout=30.0) as client:
                resp = client.post(url, headers=headers, json=payload)
                resp.raise_for_status()
                data = resp.json()
                return data["choices"][0]["message"]["content"]
        except httpx.HTTPError as e:
            status = getattr(getattr(e, "response", None), "status_code", None)
            raise ProviderError(f"Provider request failed: {e}", retryable=_is_retryable_httpx_error(e), status_code=status)
        except (KeyError, IndexError) as e:
            raise ProviderError(f"Unexpected provider response format: {e}")

    async def stream(self, messages: List[Message], system_prompt: str = "", **kwargs) -> AsyncGenerator[str, None]:
        url = f"{self.api_base}/chat/completions"
        headers = {"Authorization": f"Bearer {self.api_key}", "Accept": "text/event-stream"}
        payload = {
            "model": self.model,
            "messages": self._format_messages(messages, system_prompt),
            "stream": True
        }
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                async with client.stream("POST", url, headers=headers, json=payload) as resp:
                    resp.raise_for_status()
                    async for line in resp.aiter_lines():
                        if line.startswith("data: "):
                            data_str = line[6:]
                            if data_str.strip() == "[DONE]":
                                break
                            try:
                                data = json.loads(data_str)
                                delta = data["choices"][0].get("delta", {})
                                if "content" in delta:
                                    content = delta["content"]
                                    if content:
                                        yield content
                            except (json.JSONDecodeError, KeyError, IndexError):
                                pass
        except httpx.HTTPError as e:
            status = getattr(getattr(e, "response", None), "status_code", None)
            raise ProviderError(f"Provider streaming failed: {e}", retryable=_is_retryable_httpx_error(e), status_code=status)

    def multimodal_generate(self, messages: List[Message], images: List[ImageAttachment], system_prompt: str = "", **kwargs) -> str:
        url = f"{self.api_base}/chat/completions"
        headers = {"Authorization": f"Bearer {self.api_key}"}
        payload = {
            "model": self.model,
            "messages": self._format_messages(messages, system_prompt, images)
        }
        try:
            with httpx.Client(timeout=30.0) as client:
                resp = client.post(url, headers=headers, json=payload)
                resp.raise_for_status()
                data = resp.json()
                return data["choices"][0]["message"]["content"]
        except httpx.HTTPError as e:
            status = getattr(getattr(e, "response", None), "status_code", None)
            raise ProviderError(f"Provider request failed: {e}", retryable=_is_retryable_httpx_error(e), status_code=status)
        except (KeyError, IndexError) as e:
            raise ProviderError(f"Unexpected provider response format: {e}")

class GeminiProvider(AIModelProvider):
    def __init__(self, api_key: str, model: str):
        self.api_key = api_key
        self.model = model
        self.api_base = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}"
        
    def model_name(self) -> str:
        return self.model
        
    def capabilities(self) -> Dict[str, bool]:
        return {"vision": True, "streaming": True}
        
    def count_tokens(self, text: str) -> int:
        return len(text.split())
        
    def _format_messages(self, messages: List[Message], system_prompt: str = "", images: List[ImageAttachment] = None) -> Dict[str, Any]:
        payload = {"contents": []}
        
        if system_prompt:
            payload["system_instruction"] = {"parts": [{"text": system_prompt}]}
            
        for msg in messages:
            role = "user" if msg.role == "user" else "model"
            parts = []
            
            if msg.role == "user" and msg.attachments and images:
                parts.append({"text": msg.text})
                for att in msg.attachments:
                    try:
                        path = Path(att.storage_reference)
                        if path.exists():
                            b64 = base64.b64encode(path.read_bytes()).decode('utf-8')
                            parts.append({
                                "inline_data": {
                                    "mime_type": att.mime_type,
                                    "data": b64
                                }
                            })
                        else:
                            parts.append({"text": f"[Missing image: {att.filename}]"})
                    except Exception:
                        parts.append({"text": f"[Error reading image: {att.filename}]"})
            else:
                parts.append({"text": msg.text})
                
            payload["contents"].append({"role": role, "parts": parts})
            
        return payload
        
    def generate(self, messages: List[Message], system_prompt: str = "", **kwargs) -> str:
        url = f"{self.api_base}:generateContent?key={self.api_key}"
        payload = self._format_messages(messages, system_prompt)
        try:
            with httpx.Client(timeout=30.0) as client:
                resp = client.post(url, json=payload)
                resp.raise_for_status()
                data = resp.json()
                return data["candidates"][0]["content"]["parts"][0]["text"]
        except httpx.HTTPError as e:
            status = getattr(getattr(e, "response", None), "status_code", None)
            raise ProviderError(f"Provider request failed: {e}", retryable=_is_retryable_httpx_error(e), status_code=status)
        except (KeyError, IndexError) as e:
            raise ProviderError(f"Unexpected provider response format: {e}")

    async def stream(self, messages: List[Message], system_prompt: str = "", **kwargs) -> AsyncGenerator[str, None]:
        url = f"{self.api_base}:streamGenerateContent?alt=sse&key={self.api_key}"
        payload = self._format_messages(messages, system_prompt)
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                async with client.stream("POST", url, json=payload) as resp:
                    resp.raise_for_status()
                    async for line in resp.aiter_lines():
                        if line.startswith("data: "):
                            data_str = line[6:]
                            if data_str.strip() == "":
                                continue
                            try:
                                data = json.loads(data_str)
                                if "candidates" in data and len(data["candidates"]) > 0:
                                    parts = data["candidates"][0].get("content", {}).get("parts", [])
                                    if parts and "text" in parts[0]:
                                        yield parts[0]["text"]
                            except (json.JSONDecodeError, KeyError, IndexError):
                                pass
        except httpx.HTTPError as e:
            status = getattr(getattr(e, "response", None), "status_code", None)
            raise ProviderError(f"Provider streaming failed: {e}", retryable=_is_retryable_httpx_error(e), status_code=status)

    def multimodal_generate(self, messages: List[Message], images: List[ImageAttachment], system_prompt: str = "", **kwargs) -> str:
        url = f"{self.api_base}:generateContent?key={self.api_key}"
        payload = self._format_messages(messages, system_prompt, images)
        try:
            with httpx.Client(timeout=30.0) as client:
                resp = client.post(url, json=payload)
                resp.raise_for_status()
                data = resp.json()
                return data["candidates"][0]["content"]["parts"][0]["text"]
        except httpx.HTTPError as e:
            raise ProviderError(f"Provider request failed: {e}", retryable=_is_retryable_httpx_error(e))
        except (KeyError, IndexError) as e:
            raise ProviderError(f"Unexpected provider response format: {e}")


