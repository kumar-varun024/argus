import json
import os
from typing import Optional

from loguru import logger
from openai import OpenAI, OpenAIError

from argus.config import Config

from .client import AIClient
from .models import AIResponse

SYSTEM_PROMPT = (
    "You are assisting with an authorized security assessment. "
    "Analyze the supplied reconnaissance evidence. "
    "Do not claim vulnerabilities. "
    "Prioritize investigation opportunities, explain your reasoning, "
    "and recommend manual verification steps. "
    "You MUST output valid JSON exactly matching the requested structure."
)


def _parse_json_content(content: str) -> dict:
    if not content:
        return {}
    content = content.strip()
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        if "```json" in content:
            extracted = content.split("```json")[1].split("```")[0].strip()
            try:
                return json.loads(extracted)
            except json.JSONDecodeError:
                pass
        elif "```" in content:
            extracted = content.split("```")[1].split("```")[0].strip()
            try:
                return json.loads(extracted)
            except json.JSONDecodeError:
                pass
    return {}


def _build_ai_response(data: dict) -> AIResponse:
    return AIResponse(
        executive_summary=data.get("executive_summary", "No summary provided."),
        business_objects=data.get("business_objects", []) if isinstance(data.get("business_objects"), list) else [],
        business_workflows=data.get("business_workflows", []) if isinstance(data.get("business_workflows"), list) else [],
        authorization_boundaries=data.get("authorization_boundaries", []) if isinstance(data.get("authorization_boundaries"), list) else [],
        sensitive_operations=data.get("sensitive_operations", []) if isinstance(data.get("sensitive_operations"), list) else [],
        high_value_assets=data.get("high_value_assets", []) if isinstance(data.get("high_value_assets"), list) else [],
        research_questions=data.get("research_questions", []) if isinstance(data.get("research_questions"), list) else [],
        missing_evidence=data.get("missing_evidence", []) if isinstance(data.get("missing_evidence"), list) else [],
        recommended_next_steps=data.get("recommended_next_steps", []) if isinstance(data.get("recommended_next_steps"), list) else [],
        confidence=str(data.get("confidence", "Unknown")),
        unknown_areas=data.get("unknown_areas", []) if isinstance(data.get("unknown_areas"), list) else [],
    )


class OpenAIClient(AIClient):
    """Functional AIClient implementation interfacing with OpenAI API."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        base_url: Optional[str] = None,
    ):
        self.api_key = api_key or getattr(Config, "OPENAI_API_KEY", None) or os.getenv("OPENAI_API_KEY")
        self.model = model or getattr(Config, "OPENAI_MODEL", None) or os.getenv("OPENAI_MODEL", "gpt-4o-mini")
        self.base_url = base_url or getattr(Config, "OPENAI_BASE_URL", None) or os.getenv("OPENAI_BASE_URL")

        client_kwargs = {}
        if self.api_key:
            client_kwargs["api_key"] = self.api_key
        if self.base_url:
            client_kwargs["base_url"] = self.base_url

        self.client = OpenAI(**client_kwargs)

    def research(self, prompt: str) -> AIResponse:
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": SYSTEM_PROMPT,
                    },
                    {
                        "role": "user",
                        "content": prompt,
                    },
                ],
                temperature=0.2,
                response_format={"type": "json_object"},
            )

            content = response.choices[0].message.content or ""
            data = _parse_json_content(content)
            return _build_ai_response(data)
        except OpenAIError as e:
            logger.error(f"OpenAI API error during research: {e}")
            return AIResponse(
                executive_summary=f"OpenAI API error: {e}",
                confidence="Low",
            )
        except Exception as e:
            logger.error(f"Unexpected error during OpenAI research: {e}")
            return AIResponse(
                executive_summary=f"OpenAI research error: {e}",
                confidence="Low",
            )
