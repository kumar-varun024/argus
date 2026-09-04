import json
import os
from typing import Optional

import httpx
from loguru import logger

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


class GeminiClient(AIClient):
    """Functional AIClient implementation interfacing with Google Gemini REST API."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        base_url: Optional[str] = None,
        timeout: float = 30.0,
    ):
        self.api_key = api_key or getattr(Config, "GEMINI_API_KEY", None) or os.getenv("GEMINI_API_KEY")
        self.model = model or getattr(Config, "GEMINI_MODEL", None) or os.getenv("GEMINI_MODEL", "gemini-1.5-flash")
        self.base_url = (
            base_url
            or getattr(Config, "GEMINI_BASE_URL", None)
            or os.getenv("GEMINI_BASE_URL", "https://generativelanguage.googleapis.com/v1beta/models")
        )
        self.timeout = timeout

    def research(self, prompt: str) -> AIResponse:
        if not self.api_key:
            logger.error("Gemini API key is not configured.")
            return AIResponse(
                executive_summary="Gemini API key not configured.",
                confidence="Low",
            )

        url = f"{self.base_url.rstrip('/')}/{self.model}:generateContent"
        params = {"key": self.api_key}
        headers = {"Content-Type": "application/json"}
        payload = {
            "system_instruction": {
                "parts": [{"text": SYSTEM_PROMPT}],
            },
            "contents": [
                {
                    "role": "user",
                    "parts": [{"text": prompt}],
                }
            ],
            "generationConfig": {
                "response_mime_type": "application/json",
                "temperature": 0.2,
            },
        }

        try:
            with httpx.Client(timeout=self.timeout) as client:
                response = client.post(
                    url,
                    params=params,
                    headers=headers,
                    json=payload,
                )

            if response.status_code != 200:
                logger.error(
                    f"Gemini API returned status code {response.status_code}: {response.text}"
                )
                return AIResponse(
                    executive_summary=f"Gemini API error (HTTP {response.status_code}): {response.text}",
                    confidence="Low",
                )

            resp_json = response.json()
            candidates = resp_json.get("candidates", [])
            if not candidates:
                logger.warning("Gemini API returned no candidates in response.")
                return AIResponse(
                    executive_summary="Gemini API returned no candidates.",
                    confidence="Low",
                )

            candidate_parts = candidates[0].get("content", {}).get("parts", [])
            content_text = candidate_parts[0].get("text", "") if candidate_parts else ""

            data = _parse_json_content(content_text)
            return _build_ai_response(data)
        except httpx.HTTPError as e:
            logger.error(f"HTTP error during Gemini API request: {e}")
            return AIResponse(
                executive_summary=f"Gemini HTTP error: {e}",
                confidence="Low",
            )
        except Exception as e:
            logger.error(f"Unexpected error during Gemini research: {e}")
            return AIResponse(
                executive_summary=f"Gemini research error: {e}",
                confidence="Low",
            )
