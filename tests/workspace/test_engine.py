import pytest
from argus.workspace.models import Conversation, ImageAttachment
from argus.workspace.engine import ConversationEngine
from argus.workspace.provider import MockModelProvider

def test_add_user_message():
    engine = ConversationEngine()
    conv = Conversation()
    
    msg = engine.add_user_message(conv, "test text")
    assert msg.role == "user"
    assert msg.text == "test text"
    assert len(conv.messages) == 1
    
def test_generate_response():
    engine = ConversationEngine(provider=MockModelProvider())
    conv = Conversation()
    
    engine.add_user_message(conv, "test text")
    resp = engine.generate_response(conv)
    
    assert resp.role == "assistant"
    assert "mocked response" in resp.text
    
def test_generate_multimodal_response():
    engine = ConversationEngine(provider=MockModelProvider())
    conv = Conversation()
    
    engine.add_user_message(conv, "test text", attachments=[ImageAttachment()])
    resp = engine.generate_response(conv)
    
    assert resp.role == "assistant"
    assert "analyzed 1 images" in resp.text

def test_evidence_citations_extracted():
    engine = ConversationEngine(provider=MockModelProvider())
    conv = Conversation()
    
    # Send a message that will trigger a response with a mock citation
    # Note: MockModelProvider was updated to include [Evidence #test-id] if "CITATIONS" is in system_prompt
    engine.add_user_message(conv, "test text")
    resp = engine.generate_response(conv)
    
    assert resp.role == "assistant"
    # The planner injects CITATIONS instruction, so the mock provider should include it
    assert len(resp.references) == 1
    assert resp.references[0].ref_id == "test-id"
    assert resp.references[0].ref_type == "evidence"
