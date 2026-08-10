import pytest
from argus.workspace.models import Conversation, ImageAttachment
from argus.workspace.engine import ConversationEngine
from argus.workspace.provider import MockModelProvider
from argus.workspace.context import ResearchContextBuilder

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
    
def test_build_system_prompt():
    conv = Conversation(current_context={"scope": "Only test target.com"})
    prompt = ResearchContextBuilder.build_system_prompt(conv)
    
    assert "ACTIVE SCOPE:" in prompt
    assert "Only test target.com" in prompt
