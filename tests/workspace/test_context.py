import pytest
from argus.workspace.context.models import ContextQuery, ContextSource, ContextResult
from argus.workspace.context.ranker import ContextRanker
from argus.workspace.context.policy import ContextPolicy
from argus.workspace.context.assembler import ContextAssembler
from argus.workspace.context.engine import ResearchContextEngine

def test_context_policy():
    policy = ContextPolicy()
    query = ContextQuery(conversation_id="c1", query="test", mission_id="m1")
    
    sources = [
        ContextSource(source_id="1", source_type="ev", title="T1", content="C1", semantic_status="EVIDENCE", mission_id="m1"),
        ContextSource(source_id="2", source_type="ev", title="T2", content="C2", semantic_status="EVIDENCE", mission_id="m2")
    ]
    
    allowed = policy.apply(query, sources)
    assert len(allowed) == 1
    assert allowed[0].mission_id == "m1"
    
def test_context_ranker():
    ranker = ContextRanker()
    query = ContextQuery(conversation_id="c1", query="admin token bypass", mission_id="m1")
    
    sources = [
        ContextSource(source_id="1", source_type="ev", title="Irrelevant", content="Some logs", semantic_status="OBSERVATION", mission_id="m1"),
        ContextSource(source_id="2", source_type="ev", title="Admin Token Bypass", content="The token was bypassed.", semantic_status="EVIDENCE", mission_id="m1")
    ]
    
    ranked = ranker.rank(query, sources)
    assert len(ranked) == 2
    assert ranked[0].source_id == "2"
    assert ranked[0].relevance_score in ["High", "Critical"]
    
def test_context_assembler():
    assembler = ContextAssembler()
    result = ContextResult(
        context_status="OK",
        sources=[
            ContextSource(source_id="1", source_type="ev", title="Admin Bypass", content="Details", semantic_status="EVIDENCE")
        ]
    )
    
    output = assembler.assemble(result)
    assert "RELEVANT EVIDENCE" in output
    assert "Admin Bypass" in output
    assert "CONTEXT STATUS: OK" in output
    
def test_research_context_engine():
    engine = ResearchContextEngine()
    query = ContextQuery(conversation_id="c1", query="admin token bypass", mission_id="m1")
    
    final_prompt = engine.resolve_context(query)
    assert "Admin Token Bypass" in final_prompt
    assert "Unrelated DB Leak" not in final_prompt # Should be filtered out by policy because it's m2
