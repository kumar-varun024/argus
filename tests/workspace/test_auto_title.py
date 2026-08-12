import pytest
from argus.workspace.models import Conversation, Message
from argus.workspace.engine import ConversationEngine

def test_auto_title_generation():
    """Verify that a new conversation gets automatically titled based on the first user message."""
    engine = ConversationEngine()
    
    # Initialize a new conversation with the default title
    conv = Conversation(title="New Conversation", user_id="test_user")
    
    # Add first user message
    engine.add_user_message(conv, "Can you explain how IDOR works in this context?")
    
    # Generate AI response
    engine.generate_response(conv)
    
    # The title should have been updated by the engine using the provider
    assert conv.title != "New Conversation"
    assert len(conv.title) > 0
    
    # A subsequent message should not overwrite the new title
    original_new_title = conv.title
    
    engine.add_user_message(conv, "Thanks. What about CSRF?")
    engine.generate_response(conv)
    
    assert conv.title == original_new_title
