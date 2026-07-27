from .prompts import build_research_prompt
from .client import get_ai_client

class Researcher:

    def __init__(self):
        self.client = get_ai_client()

    def analyze(self, mission):
        prompt = build_research_prompt(mission)
        return self.client.research(prompt)
