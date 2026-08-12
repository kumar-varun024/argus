import pytest
from argus.workspace.copilot import ResearchCopilot, ResearchOpportunity
from argus.workspace.context.models import ContextResult, ContextSource
from argus.workspace.planner import EvidenceAwareAnswerPlanner
from argus.workspace.models import Conversation, Message

def test_copilot_identifies_authorization_gap():
    copilot = ResearchCopilot()
    
    # Simulate context containing "Account A" but missing "Account B"
    source = ContextSource(
        source_id="ev_1",
        source_type="evidence",
        title="Account A request",
        content="I requested the object using account a's token.",
        semantic_status="EVIDENCE"
    )
    result = ContextResult(sources=[source], context_status="OK")
    
    opportunities = copilot.evaluate(result)
    
    assert len(opportunities) == 1
    assert opportunities[0].title == "Cross-Account Authorization Check"
    assert "account b" in opportunities[0].explanation.lower()
    assert opportunities[0].priority == "High"

def test_copilot_identifies_duplicate_work():
    copilot = ResearchCopilot()
    
    # Simulate multiple 403s on the same endpoint
    sources = [
        ContextSource(source_id="ev_1", source_type="evidence", title="Test 1", content="Got 403 forbidden.", semantic_status="EVIDENCE"),
        ContextSource(source_id="ev_2", source_type="evidence", title="Test 2", content="Received a 403 error.", semantic_status="EVIDENCE"),
        ContextSource(source_id="ev_3", source_type="evidence", title="Test 3", content="Access forbidden 403.", semantic_status="EVIDENCE")
    ]
    result = ContextResult(sources=sources, context_status="OK")
    
    opportunities = copilot.evaluate(result)
    
    assert len(opportunities) == 1
    assert opportunities[0].title == "Deprioritize Current Path"
    assert opportunities[0].status == "DEPRIORITIZED"
    assert opportunities[0].priority == "Low"

def test_copilot_identifies_graphql():
    copilot = ResearchCopilot()
    
    source = ContextSource(
        source_id="ev_1",
        source_type="evidence",
        title="Endpoint",
        content="We found a graphql endpoint running on /api/graphql",
        semantic_status="EVIDENCE"
    )
    result = ContextResult(sources=[source], context_status="OK")
    
    opportunities = copilot.evaluate(result)
    
    assert len(opportunities) == 1
    assert opportunities[0].title == "GraphQL Schema Extraction"

def test_planner_embeds_copilot_instructions():
    planner = EvidenceAwareAnswerPlanner()
    
    source = ContextSource(
        source_id="ev_1",
        source_type="evidence",
        title="Endpoint",
        content="We found a graphql endpoint running on /api/graphql",
        semantic_status="EVIDENCE"
    )
    result = ContextResult(sources=[source], context_status="OK")
    
    conv = Conversation()
    msg = Message(role="user", text="What should I test next?")
    
    plan = planner.plan_answer(conv, msg, result)
    
    assert plan.question_type == "RECOMMENDATION"
    assert len(plan.opportunities) == 1
    assert "AVAILABLE RESEARCH OPPORTUNITIES:" in plan.system_instructions
    assert "GraphQL Schema Extraction" in plan.system_instructions
    assert "OBSERVATION -> HYPOTHESIS -> VERIFICATION" in plan.system_instructions
