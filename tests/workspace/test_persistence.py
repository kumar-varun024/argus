import pytest
from fastapi.testclient import TestClient
from argus.workspace.web.app import app
from argus.workspace.api import repository
from argus.workspace.models import Conversation

client = TestClient(app)

@pytest.fixture(autouse=True)
def clean_repository():
    """Ensure a clean repository state for each test."""
    original_cache = list(repository._cache.keys())
    for cid in original_cache:
        repository.delete(cid)
    yield
    for cid in list(repository._cache.keys()):
        repository.delete(cid)

def test_create_and_persist_conversation():
    # 1. Create conversation via API (like New Task button)
    response = client.post("/api/conversations/")
    assert response.status_code == 200
    data = response.json()
    cid = data["conversation_id"]
    assert cid is not None
    assert data["title"] == "New Conversation"
    
    # 2. Persist conversation
    assert repository.get(cid) is not None
    assert repository.get(cid).user_id == "local_user"

def test_persist_messages():
    # Create conversation
    res = client.post("/api/conversations/")
    cid = res.json()["conversation_id"]
    
    # 3. & 4. Persist user message and Argus response via form post
    response = client.post(
        "/chat", 
        data={"cid": cid, "message": "Remember this conversation as persistence test A."},
        follow_redirects=False
    )
    assert response.status_code == 303 # PRG pattern
    
    # Reload from backend
    conv = repository.get(cid)
    assert len(conv.messages) == 2
    assert conv.messages[0].role == "user"
    assert "persistence test A" in conv.messages[0].text
    assert conv.messages[1].role == "assistant"
    
    # 5. Reload conversation endpoint
    res2 = client.get(f"/api/conversations/{cid}")
    assert res2.status_code == 200
    assert len(res2.json()["messages"]) == 2

def test_switch_and_isolation():
    # Create Conv A
    res_a = client.post("/api/conversations/")
    cid_a = res_a.json()["conversation_id"]
    client.post("/chat", data={"cid": cid_a, "message": "Test A Message"})
    
    # Create Conv B
    res_b = client.post("/api/conversations/")
    cid_b = res_b.json()["conversation_id"]
    client.post("/chat", data={"cid": cid_b, "message": "Test B Message"})
    
    # 6. & 7. Switch and isolate
    conv_a = client.get(f"/api/conversations/{cid_a}").json()
    conv_b = client.get(f"/api/conversations/{cid_b}").json()
    
    assert len(conv_a["messages"]) == 2
    assert "Test A Message" in conv_a["messages"][0]["text"]
    
    assert len(conv_b["messages"]) == 2
    assert "Test B Message" in conv_b["messages"][0]["text"]
    
    # Ensure no bleeding
    assert "Test B" not in conv_a["messages"][0]["text"]

def test_rename_conversation():
    res = client.post("/api/conversations/")
    cid = res.json()["conversation_id"]
    
    # 8. Rename
    client.patch(f"/api/conversations/{cid}", json={"title": "Renamed Test"})
    conv = repository.get(cid)
    assert conv.title == "Renamed Test"

def test_delete_conversation():
    res = client.post("/api/conversations/")
    cid = res.json()["conversation_id"]
    
    # 9. Delete
    delete_res = client.delete(f"/api/conversations/{cid}")
    assert delete_res.status_code == 200
    
    assert repository.get(cid) is None
    
    # 12. Conversation-not-found
    not_found_res = client.get(f"/api/conversations/{cid}")
    assert not_found_res.status_code == 404

def test_search_conversations():
    res1 = client.post("/api/conversations/")
    cid1 = res1.json()["conversation_id"]
    client.patch(f"/api/conversations/{cid1}", json={"title": "Alpha Research"})
    client.post("/chat", data={"cid": cid1, "message": "Finding secret tokens"})
    
    res2 = client.post("/api/conversations/")
    cid2 = res2.json()["conversation_id"]
    client.patch(f"/api/conversations/{cid2}", json={"title": "Beta Project"})
    
    # 10. Search by title
    search_res = client.get("/api/conversations/search?q=Alpha")
    results = search_res.json()
    assert len(results) == 1
    assert results[0]["conversation_id"] == cid1
    
    # 10. Search by message content
    search_res2 = client.get("/api/conversations/search?q=secret")
    results2 = search_res2.json()
    assert len(results2) == 1
    assert results2[0]["conversation_id"] == cid1

def test_empty_conversation():
    # 11. Empty conversation
    # Navigating to root without cid shouldn't crash
    res = client.get("/")
    assert res.status_code == 200
    assert "What would you like to investigate?" in res.text

def test_persistence_failure(monkeypatch):
    # 13. Persistence failure handling
    def mock_save(*args, **kwargs):
        raise IOError("Disk full")
    
    monkeypatch.setattr(repository, "save", mock_save)
    
    # Attempting to chat should result in a 500 error because it can't save
    with pytest.raises(Exception):
        client.post("/chat", data={"message": "fail test"})

def test_authorization_failure():
    # Create conversation as normal user
    res = client.post("/api/conversations/")
    cid = res.json()["conversation_id"]
    
    # 14 & 15. Direct API authorization failure (impersonating a different user)
    # The API checks x_user_id header (depends local_user by default)
    # If we pass a different header, it should block access.
    # In FastAPI, a Header("local_user") named x_user_id looks for "x-user-id".
    
    res_auth = client.get(f"/api/conversations/{cid}", headers={"x-user-id": "hacker"})
    assert res_auth.status_code == 403

def test_duplicate_submission_race_behavior():
    # 16. Duplicate submission / Race behavior
    # Send same message twice very quickly
    res = client.post("/api/conversations/")
    cid = res.json()["conversation_id"]
    
    client.post("/chat", data={"cid": cid, "message": "Duplicate Post"}, follow_redirects=False)
    client.post("/chat", data={"cid": cid, "message": "Duplicate Post"}, follow_redirects=False)
    
    conv = repository.get(cid)
    # Should only have 2 messages (1 user, 1 assistant) despite posting twice
    assert len(conv.messages) == 2
