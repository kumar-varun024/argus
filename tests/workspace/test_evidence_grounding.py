import pytest
from fastapi.testclient import TestClient
from fastapi import FastAPI
from argus.workspace.api import router, repository, evidence_manager
from argus.workspace.models import Conversation, Message, ImageAttachment
from argus.workspace.context.models import ContextQuery
from argus.workspace.context.engine import ResearchContextEngine

@pytest.fixture
def test_app() -> FastAPI:
    app = FastAPI()
    app.include_router(router)
    return app

@pytest.fixture
def client(test_app) -> TestClient:
    repository._cache.clear()
    
    # Clean up evidence files
    import shutil
    from pathlib import Path
    import os
    ev_dir = Path(os.path.expanduser("~/.argus/workspace/evidence"))
    if ev_dir.exists():
        shutil.rmtree(ev_dir)
    ev_dir.mkdir(parents=True, exist_ok=True)
    
    with TestClient(test_app) as c:
        yield c

def test_explicit_evidence_creation(client):
    headers = {"x-user-id": "test_user"}
    
    # 1. Create a conversation
    conv = Conversation(
        title="Test Conversation",
        user_id="test_user",
        investigation_id="inv_123"
    )
    repository.save(conv)
    
    # 2. Add an attachment
    att = ImageAttachment(
        image_id="img_001",
        filename="test.png",
        mime_type="image/png",
        size=1024,
        storage_reference="/tmp/test.png",
        analysis_result="I see a test.",
        analysis_status="COMPLETED"
    )
    msg = Message(role="user", text="Look at this", attachments=[att])
    conv.messages.append(msg)
    repository.save(conv)
    
    # 3. Call explicitly save as evidence
    res = client.post(f"/api/attachments/img_001/evidence?cid={conv.conversation_id}", headers=headers)
    assert res.status_code == 200
    
    ev_id = res.json()["evidence_id"]
    
    # 4. Verify Evidence
    evidences = evidence_manager.get_by_investigation("inv_123")
    assert len(evidences) == 1
    ev = evidences[0]
    
    assert ev.evidence_id == ev_id
    assert ev.source_type == "SCREENSHOT"
    assert ev.status == "OBSERVATION"
    assert ev.created_by == "user-uploaded screenshot"
    assert ev.provenance.image_id == "img_001"
    assert ev.provenance.conversation_id == conv.conversation_id
    assert "test.png" in ev.title

def test_evidence_grounding_context_limits():
    from argus.evidence.model import Evidence
    
    # Populate a lot of evidence
    for i in range(20):
        ev = Evidence(
            title=f"Evidence {i}",
            description="A piece of evidence",
            investigation_id="inv_abc",
            status="OBSERVATION"
        )
        evidence_manager.save(ev)
        
    engine = ResearchContextEngine()
    query = ContextQuery(conversation_id="conv_abc", query="evidence", investigation_id="inv_abc")
    
    context_str = engine.resolve_context(query)
    
    # Because of context limiting (top 15), we should not see 20 evidence sources.
    # We can check how many sources were retrieved by looking at the _retrieve_sources directly
    raw = engine._retrieve_sources(query)
    assert len(raw) == 20
    
    # And rank should limit
    ranked = engine.ranker.rank(query, raw)
    assert len(ranked) == 15

def test_cross_user_evidence_denied(client):
    headers_B = {"x-user-id": "user_B"}
    
    conv = Conversation(
        title="Test Conversation",
        user_id="user_A",
        investigation_id="inv_A"
    )
    
    att = ImageAttachment(image_id="img_002", filename="test2.png", mime_type="image/png", size=1024, storage_reference="/tmp/test2.png")
    msg = Message(role="user", text="Look at this", attachments=[att])
    conv.messages.append(msg)
    repository.save(conv)
    
    # User B tries to save User A's attachment as evidence
    res = client.post(f"/api/attachments/img_002/evidence?cid={conv.conversation_id}", headers=headers_B)
    assert res.status_code == 403

def test_planner_conflict_resolution():
    from argus.workspace.planner import EvidenceAwareAnswerPlanner, AnswerPlan
    from argus.workspace.context.models import ContextResult, ContextSource
    
    planner = EvidenceAwareAnswerPlanner()
    
    source1 = ContextSource(source_id="1", source_type="EVIDENCE", title="S1", content="It's a vulnerability.", semantic_status="EVIDENCE")
    source2 = ContextSource(source_id="2", source_type="OBSERVATION", title="S2", content="This contradicts the vulnerability.", semantic_status="OBSERVATION", metadata={"relationship": "CONTRADICTS"})
    
    result = ContextResult(sources=[source1, source2], context_status="OK")
    
    msg = Message(role="user", text="What is this?")
    conv = Conversation(user_id="test")
    
    plan = planner.plan_answer(conv, msg, result)
    
    assert plan.evidence_status == "CONTRADICTORY"
    assert "Source 2" in plan.contradictions[0]
    assert "CONTRADICTORY EVIDENCE" in plan.system_instructions
