from abc import ABC, abstractmethod

from argus.config import Config

from .models import AIResponse


class AIClient(ABC):

    @abstractmethod
    def research(self, prompt: str) -> AIResponse:
        raise NotImplementedError


def get_ai_client():

    provider = Config.AI_PROVIDER.lower()

    if provider == "github":
        from .github_client import GitHubClient

        return GitHubClient()

    if provider == "gemini":
        # pyrefly: ignore [missing-import]
        from .gemini_client import GeminiClient

        return GeminiClient()

    if provider == "openai":
        from .openai_client import OpenAIClient

        return OpenAIClient()

    raise ValueError(
        f"Unknown AI provider: {provider}"
    )