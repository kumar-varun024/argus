import pytest
from argus.workspace.repository import ConversationRepository
from argus.workspace.models import Conversation, Message

def test_repository_crud(tmp_path):
    repo = ConversationRepository(data_dir=str(tmp_path))
    
    # Create
    conv = Conversation(title="Test Search", user_id="u1", mission_id="m1")
    msg = Message(text="hello authorization issue")
    conv.messages.append(msg)
    
    repo.save(conv)
    assert len(repo._cache) == 1
    
    # Read
    fetched = repo.get(conv.conversation_id)
    assert fetched.title == "Test Search"
    assert len(fetched.messages) == 1
    
    # Search by Title
    results = repo.search(query="search")
    assert len(results) == 1
    
    # Search by Message Content
    results2 = repo.search(query="authorization")
    assert len(results2) == 1
    
    # Search by Index
    assert len(repo.search(mission_id="m1")) == 1
    assert len(repo.search(mission_id="m2")) == 0
    
    # Delete
    repo.delete(conv.conversation_id)
    assert repo.get(conv.conversation_id) is None
    assert len(repo.search(mission_id="m1")) == 0
    
def test_archived_conversations(tmp_path):
    repo = ConversationRepository(data_dir=str(tmp_path))
    conv = Conversation(title="Archived Conv", status="archived")
    repo.save(conv)
    
    assert len(repo.search()) == 0
    assert len(repo.search(include_archived=True)) == 1
