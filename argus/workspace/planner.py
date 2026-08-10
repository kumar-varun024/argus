from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from argus.workspace.models import Conversation, Message
from argus.workspace.context.models import ContextResult, ContextSource

@dataclass
class AnswerPlan:
    question_type: str = "GENERAL"
    explanation_level: str = "STANDARD"
    evidence_status: str = "SUFFICIENT"
    missing_evidence: List[str] = field(default_factory=list)
    contradictions: List[str] = field(default_factory=list)
    system_instructions: str = ""

class EvidenceAwareAnswerPlanner:
    def plan_answer(self, conversation: Conversation, current_msg: Message, context_result: ContextResult) -> AnswerPlan:
        # 1. Identify question type & explanation level
        text = current_msg.text.lower()
        q_type = "GENERAL"
        
        if "beginner" in text or "simple" in text or "explain like i'm 5" in text:
            explanation_level = "BEGINNER"
        elif "technical" in text or "deep" in text or "advanced" in text:
            explanation_level = "ADVANCED"
        else:
            explanation_level = "STANDARD"
            
        if "summarize" in text or "summary" in text:
            q_type = "SUMMARY"
        elif "missing" in text or "don't we have" in text:
            q_type = "MISSING_EVIDENCE"
        elif "contradict" in text or "conflict" in text:
            q_type = "CONTRADICTION"
        elif "evidence" in text or "support" in text:
            q_type = "EVIDENCE_REQUEST"
        elif "why" in text or "reason" in text:
            q_type = "REASONING"
        elif "next" in text or "should i do" in text:
            q_type = "RECOMMENDATION"
            
        plan = AnswerPlan(question_type=q_type, explanation_level=explanation_level)
        
        # 2. Evaluate Evidence
        for source in context_result.sources:
            # Mocking contradiction detection based on source metadata or content
            if source.metadata.get("relationship") == "CONTRADICTS" or "contradict" in source.content.lower():
                plan.contradictions.append(f"Source {source.source_id} ({source.title}) presents contradictory information.")
                
            # Evidence strength/status
            if source.metadata.get("strength") == "WEAK":
                plan.missing_evidence.append(f"Evidence {source.source_id} is weak, needs corroboration.")

        if context_result.context_status == "INSUFFICIENT_CONTEXT" or len(context_result.sources) == 0:
            plan.evidence_status = "INSUFFICIENT"
            plan.missing_evidence.append("No relevant evidence found for this context.")
        elif plan.contradictions:
            plan.evidence_status = "CONTRADICTORY"
        
        # 3. Build instructions
        plan.system_instructions = self._build_instructions(plan)
        return plan

    def _build_instructions(self, plan: AnswerPlan) -> str:
        instructions = [
            "=========================================================",
            "EVIDENCE-AWARE Q&A INSTRUCTIONS",
            "=========================================================",
            "1. Ground every claim in the provided evidence. DO NOT manufacture evidence.",
            "2. Distinguish clearly between FACT, OBSERVATION, HYPOTHESIS, and CONFIRMED FINDING.",
            "3. If evidence is insufficient, explicitly say so.",
            "4. Never use unrelated project evidence to answer a question."
        ]
        
        if plan.explanation_level == "BEGINNER":
            instructions.append("5. MODE: Beginner. Avoid unnecessary jargon, explain terminology, and use simple analogies. Break complex reasoning into steps. Do not remove important security nuance.")
        elif plan.explanation_level == "ADVANCED":
            instructions.append("5. MODE: Advanced. Provide deep technical reasoning including request/response relationships, authentication context, authorization boundaries, etc.")
        else:
            instructions.append("5. MODE: Standard. Answer conversationally, clearly, and directly.")
            
        if plan.evidence_status == "INSUFFICIENT":
            instructions.append("6. CURRENT STATUS: INSUFFICIENT EVIDENCE. You must explicitly state that we do not have enough evidence yet to reach a definitive conclusion.")
            
        if plan.contradictions:
            instructions.append("7. CURRENT STATUS: CONTRADICTORY EVIDENCE. You must acknowledge this conflict in the evidence. Explain the contradiction instead of hiding it.")
            
        if plan.question_type == "RECOMMENDATION":
            instructions.append("8. RECOMMENDATION REQUESTED. Provide evidence-driven, minimal, targeted recommendations for next research steps. Clearly label them as recommendations.")
            
        instructions.append("9. CITATIONS: Use internal evidence references like [Evidence #<id>] or [Screenshot <title>] when referring to evidence.")
        
        return "\n".join(instructions)
