import pytest
from argus.workspace.planner import EvidenceAwareAnswerPlanner
from argus.workspace.models import Conversation, Message
from argus.workspace.context.models import ContextResult, ContextSource

def test_identify_beginner_mode():
    planner = EvidenceAwareAnswerPlanner()
    msg = Message(text="Explain this to me like I'm a beginner")
    plan = planner.plan_answer(Conversation(), msg, ContextResult(sources=[]))
    assert plan.explanation_level == "BEGINNER"
    assert "Avoid unnecessary jargon" in plan.system_instructions

def test_identify_advanced_mode():
    planner = EvidenceAwareAnswerPlanner()
    msg = Message(text="Give me the technical details")
    plan = planner.plan_answer(Conversation(), msg, ContextResult(sources=[]))
    assert plan.explanation_level == "ADVANCED"
    assert "Provide deep technical reasoning" in plan.system_instructions

def test_identify_contradictions():
    planner = EvidenceAwareAnswerPlanner()
    msg = Message(text="Does this make sense?")
    
    source = ContextSource(
        source_id="123",
        source_type="evidence",
        title="Test Evidence",
        content="This contradicts previous evidence.",
        semantic_status="EVIDENCE",
        metadata={"relationship": "CONTRADICTS"}
    )
    
    plan = planner.plan_answer(Conversation(), msg, ContextResult(sources=[source], context_status="OK"))
    assert plan.evidence_status == "CONTRADICTORY"
    assert len(plan.contradictions) == 1
    assert "CONTRADICTORY EVIDENCE" in plan.system_instructions

def test_insufficient_evidence():
    planner = EvidenceAwareAnswerPlanner()
    msg = Message(text="Why did you flag this?")
    
    plan = planner.plan_answer(Conversation(), msg, ContextResult(sources=[], context_status="INSUFFICIENT_CONTEXT"))
    assert plan.evidence_status == "INSUFFICIENT"
    assert "INSUFFICIENT EVIDENCE" in plan.system_instructions
    assert "we do not have enough evidence" in plan.system_instructions
