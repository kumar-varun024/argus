from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from argus.workspace.models import Conversation, Message
from argus.workspace.context.models import ContextResult, ContextSource

@dataclass
class AnswerPlan:
    question_type: str = "GENERAL"
    explanation_level: str = "STANDARD"
    evidence_status: str = "SUFFICIENT"
    action_intent: str = "READ"
    requires_confirmation: bool = False
    missing_evidence: List[str] = field(default_factory=list)
    contradictions: List[str] = field(default_factory=list)
    system_instructions: str = ""

class EvidenceAwareAnswerPlanner:
    def plan_answer(self, conversation: Conversation, current_msg: Message, context_result: ContextResult) -> AnswerPlan:
        # 1. Identify question type & explanation level
        text = current_msg.text.lower()
        q_type = "GENERAL"
        action_intent = "READ"
        requires_confirmation = False
        
        # Determine intent
        if any(verb in text for verb in ["create", "delete", "remove", "update", "change", "modify", "start", "link", "mark"]):
            action_intent = "WRITE"
            requires_confirmation = True
            
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
            
        plan = AnswerPlan(
            question_type=q_type, 
            explanation_level=explanation_level,
            action_intent=action_intent,
            requires_confirmation=requires_confirmation
        )
        
        # 2. Evaluate Evidence
        for source in context_result.sources:
            if source.metadata.get("relationship") == "CONTRADICTS" or "contradict" in source.content.lower():
                plan.contradictions.append(f"Source {source.source_id} ({source.title}) presents contradictory information.")
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
        
        # Scope Enforcement & Permissions
        instructions.append("5. SCOPE & AUTHORIZATION ENFORCEMENT:")
        instructions.append("   - NEVER assume authorization. A target being mentioned or in a graph DOES NOT mean it is authorized for action.")
        instructions.append("   - Treat UNKNOWN or OUT_OF_SCOPE targets as strictly unauthorized for any action/testing.")
        instructions.append("   - Distinguish what is observed (e.g. in a screenshot or evidence) from what is an authorized research target.")
        instructions.append("   - If the user asks to investigate or act on a target not in the active mission scope, refuse explicitly and explain the scope boundary.")
        instructions.append("   - Never override application-level permission decisions. If the context states you lack permission, obey it.")
        
        # Action Intent & Confirmation
        if plan.action_intent == "WRITE":
            instructions.append("6. ACTION INTENT [WRITE]: The user requested a state mutation or active scan. You MUST NOT silently perform this action. You MUST check the scope and ask for explicit confirmation (e.g., 'This target is authorized. Do you want me to proceed?').")
        else:
            instructions.append("6. ACTION INTENT [READ]: Answer based on the current context. Do not invent missing data.")
            
        if plan.explanation_level == "BEGINNER":
            instructions.append("7. MODE: Beginner. Avoid unnecessary jargon, explain terminology, and use simple analogies. Break complex reasoning into steps.")
        elif plan.explanation_level == "ADVANCED":
            instructions.append("7. MODE: Advanced. Provide deep technical reasoning including request/response relationships, authentication context, authorization boundaries, etc.")
        else:
            instructions.append("7. MODE: Standard. Answer conversationally, clearly, and directly.")
            
        if plan.evidence_status == "INSUFFICIENT":
            instructions.append("8. CURRENT STATUS: INSUFFICIENT EVIDENCE. You must explicitly state that we do not have enough evidence yet to reach a definitive conclusion.")
            
        if plan.contradictions:
            instructions.append("9. CURRENT STATUS: CONTRADICTORY EVIDENCE. You must acknowledge this conflict in the evidence. Explain the contradiction instead of hiding it.")
            
        if plan.question_type == "RECOMMENDATION":
            instructions.append("10. RECOMMENDATION REQUESTED. Provide evidence-driven, minimal, targeted recommendations for next research steps. Clearly label them as recommendations.")
            
        instructions.append("11. CITATIONS: Use internal evidence references like [Evidence #<id>] or [Screenshot <title>] when referring to evidence.")
        
        # Graph reasoning
        instructions.append("12. KNOWLEDGE GRAPH REASONING: When answering relationship-based questions (e.g., 'How is this connected?'), trace the provided graph relationships. Explain the path connecting the requested entities. DO NOT invent relationships that are not in the graph.")
        if plan.explanation_level == "BEGINNER":
            instructions.append("13. GRAPH MODE (BEGINNER): Explain the path naturally without unnecessary graph jargon (e.g. avoid 'nodes', 'edges', 'OBSERVED_IN'). Explain it like a chain of events.")
        elif plan.explanation_level == "ADVANCED":
            instructions.append("13. GRAPH MODE (ADVANCED): Expose entity types, relationship types, path, provenance, and verification state (e.g., AI_INFERRED vs USER_CONFIRMED).")
        else:
            instructions.append("13. GRAPH MODE (STANDARD): Provide a concise relationship explanation.")
        
        return "\n".join(instructions)
