from abc import ABC, abstractmethod
from typing import Optional

from argus.config import Config

from .models import AIResponse


class AIClient(ABC):

    @abstractmethod
    def research(self, prompt: str) -> AIResponse:
        raise NotImplementedError


class NoOpAIClient(AIClient):
    """Fallback client when AI provider is disabled or set to 'none'."""

    def research(self, prompt: str) -> AIResponse:
        return AIResponse(
            executive_summary="AI analysis skipped: provider is set to 'none'.",
            confidence="N/A",
        )


def get_ai_client(provider: Optional[str] = None) -> AIClient:
    if provider is None:
        provider = getattr(Config, "AI_PROVIDER", "none") or "none"

    provider = str(provider).lower().strip()

    if provider == "github":
        from .github_client import GitHubClient

        return GitHubClient()

    if provider == "gemini":
        from .gemini_client import GeminiClient

        return GeminiClient()

    if provider == "openai":
        from .openai_client import OpenAIClient

        return OpenAIClient()

    if provider in ("none", "", "disabled", "null"):
        return NoOpAIClient()

    raise ValueError(f"Unknown AI provider: {provider}")