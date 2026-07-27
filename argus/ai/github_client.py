import json
from openai import OpenAI

from argus.config import Config

from .client import AIClient
from .models import AIResponse


class GitHubClient(AIClient):

    def __init__(self):

        self.client = OpenAI(
            api_key=Config.GITHUB_TOKEN,
            base_url=Config.GITHUB_BASE_URL,
        )

    def research(self, prompt: str) -> AIResponse:

        response = self.client.chat.completions.create(
            model=Config.GITHUB_MODEL,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are assisting with an authorized security assessment. "
                        "Analyze the supplied reconnaissance evidence. "
                        "Do not claim vulnerabilities. "
                        "Prioritize investigation opportunities, explain your reasoning, "
                        "and recommend manual verification steps. "
                        "You MUST output valid JSON exactly matching the requested structure."
                    ),
                },
                {
                    "role": "user",
                    "content": prompt,
                },
            ],
            temperature=0.2,
            response_format={"type": "json_object"},
        )

        content = response.choices[0].message.content
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0]
                try:
                    data = json.loads(content)
                except json.JSONDecodeError:
                    data = {}
            else:
                data = {}

        return AIResponse(
            executive_summary=data.get("executive_summary", "No summary provided."),
            business_objects=data.get("business_objects", []),
            business_workflows=data.get("business_workflows", []),
            authorization_boundaries=data.get("authorization_boundaries", []),
            sensitive_operations=data.get("sensitive_operations", []),
            high_value_assets=data.get("high_value_assets", []),
            research_questions=data.get("research_questions", []),
            missing_evidence=data.get("missing_evidence", []),
            recommended_next_steps=data.get("recommended_next_steps", []),
            confidence=data.get("confidence", "Unknown"),
            unknown_areas=data.get("unknown_areas", [])
        )