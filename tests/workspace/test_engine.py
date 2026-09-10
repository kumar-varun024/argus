import asyncio
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

def test_streaming_response_routes_images_to_multimodal():
    """Regression: the streaming path (the one the browser uses) must send an
    attached image through the multimodal path, not the text-only stream. The
    MockModelProvider returns "analyzed N images" from multimodal_generate and a
    plain "mocked streamed response" from stream(), so the streamed output for a
    message WITH an attachment must be the multimodal one. Fails against the old
    code that called provider.stream() and silently dropped the image."""
    engine = ConversationEngine(provider=MockModelProvider())
    conv = Conversation()
    engine.add_user_message(conv, "what is in this screenshot?", attachments=[ImageAttachment()])

    async def _collect():
        return "".join([chunk async for chunk in engine.generate_response_stream(conv)])

    streamed = asyncio.run(_collect())
    assert "analyzed 1 images" in streamed
    assert "mocked streamed response" not in streamed


def test_streaming_response_without_image_uses_text_stream():
    """A text-only message must still use the streaming text path (unchanged)."""
    engine = ConversationEngine(provider=MockModelProvider())
    conv = Conversation()
    engine.add_user_message(conv, "hello")

    async def _collect():
        return "".join([chunk async for chunk in engine.generate_response_stream(conv)])

    streamed = asyncio.run(_collect())
    assert "mocked streamed response" in streamed


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

def test_mission_context_integration():
    from argus.runtime.manager import mission_manager
    mission = mission_manager.create_mission("test_target.com")
    mission.name = "Integration Test Mission"
    mission.scope = ["test_target.com"]
    
    engine = ConversationEngine(provider=MockModelProvider())
    conv = Conversation(mission_id=mission.id, title="Integration Test")
    
    # We want to intercept the context assembly or rely on the MockModelProvider
    # MockModelProvider stores the last system prompt. We can check if "Integration Test Mission" is in it.
    engine.add_user_message(conv, "what is the mission?")
    engine.generate_response(conv)
    
    # Check that the provider received the mission name in the context
    last_prompt = engine.provider.last_system_prompt
    assert "Integration Test Mission" in last_prompt
    assert "test_target.com" in last_prompt
