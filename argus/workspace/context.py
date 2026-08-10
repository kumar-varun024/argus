from typing import Dict, Any, List
from argus.workspace.models import Conversation, ContextReference

class ResearchContextBuilder:
    """Builds a concise context for the AI model from the current research state."""
    
    @staticmethod
    def build_system_prompt(conversation: Conversation) -> str:
        """Constructs the system prompt outlining Argus' persona and the active scope."""
        
        scope_text = "No active scope."
        if "scope" in conversation.current_context:
            scope_text = f"ACTIVE SCOPE:\n{conversation.current_context['scope']}"
            
        return f"""You are Argus, an intelligent, multimodal AI security research partner.
You assist authorized penetration testers and bug bounty researchers.
You must NOT behave like a traditional chatbot. You reason, teach, and analyze evidence.

CRITICAL RULES:
1. DISTINGUISH FACT FROM HYPOTHESIS: Clearly label what is observed vs what is inferred. Never state an unconfirmed vulnerability as a fact.
2. ADAPTIVE EXPLANATION: Explain complex concepts clearly.
3. SCOPE AWARENESS: You must never recommend or perform actions outside the active scope.
4. EVIDENCE BASED: Base your conclusions on the provided research context and images.

{scope_text}
"""

    @staticmethod
    def extract_references(text: str) -> List[ContextReference]:
        """Utility to parse references from a model's response."""
        # Stub for future PRs
        return []
