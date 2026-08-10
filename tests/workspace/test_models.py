from argus.workspace.models import Conversation, Message, ImageAttachment, ContextReference

def test_models_creation():
    att = ImageAttachment(filename="test.png")
    msg = Message(role="user", text="Hello", attachments=[att])
    conv = Conversation(title="Test", messages=[msg])
    
    assert conv.title == "Test"
    assert len(conv.messages) == 1
    assert conv.messages[0].text == "Hello"
    assert conv.messages[0].attachments[0].filename == "test.png"
