from abc import ABC, abstractmethod
from typing import List, Dict, Any, AsyncGenerator
from argus.workspace.models import Message, ImageAttachment

class AIModelProvider(ABC):
    """Abstract base class for all AI models (OpenAI, Anthropic, Local)."""
    
    @abstractmethod
    def capabilities(self) -> Dict[str, bool]:
        """Returns the capabilities of this provider (e.g., {'vision': True, 'streaming': True})."""
        pass
        
    @abstractmethod
    def count_tokens(self, text: str) -> int:
        """Estimates the number of tokens in the given text."""
        pass
        
    @abstractmethod
    def generate(self, messages: List[Message], **kwargs) -> str:
        """Generates a text response synchronously."""
        pass
        
    @abstractmethod
    async def stream(self, messages: List[Message], **kwargs) -> AsyncGenerator[str, None]:
        """Generates a text response asynchronously, yielding tokens."""
        pass
        
    @abstractmethod
    def multimodal_generate(self, messages: List[Message], images: List[ImageAttachment], **kwargs) -> str:
        """Generates a response considering both text messages and images."""
        pass


class MockModelProvider(AIModelProvider):
    """A mock provider used for the foundation PR and testing."""
    
    def capabilities(self) -> Dict[str, bool]:
        return {"vision": True, "streaming": True}
        
    def count_tokens(self, text: str) -> int:
        return len(text.split())
        
    def generate(self, messages: List[Message], **kwargs) -> str:
        return "This is a mocked response from the Argus MockModelProvider."
        
    async def stream(self, messages: List[Message], **kwargs) -> AsyncGenerator[str, None]:
        words = ["This", " is", " a", " mocked", " streamed", " response."]
        for w in words:
            yield w
            
    def multimodal_generate(self, messages: List[Message], images: List[ImageAttachment], **kwargs) -> str:
        return f"I have analyzed {len(images)} images and conclude that there might be something interesting. (Mocked)"
