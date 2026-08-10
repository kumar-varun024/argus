import pytest
from fastapi.testclient import TestClient
from argus.workspace.web.app import app
from argus.workspace.models import Conversation

client = TestClient(app)

def test_api_conversations():
    # Because app has global instances, we might be writing to the real default directory.
    # We should avoid side-effects by creating a clean repository if possible, 
    # but for simplicity, let's just create and delete a specific test conversation.
    
    conv_id = "test-conv-1234"
    
    # Create
    conv_data = {
        "conversation_id": conv_id,
        "title": "API Test",
        "user_id": "api_test",
        "messages": []
    }
    
    resp = client.post("/api/conversations/", json=conv_data)
    assert resp.status_code == 200
    
    # List
    resp2 = client.get("/api/conversations/")
    assert resp2.status_code == 200
    data = resp2.json()
    assert any(c["conversation_id"] == conv_id for c in data)
    
    # Get specific
    resp3 = client.get(f"/api/conversations/{conv_id}")
    assert resp3.status_code == 200
    assert resp3.json()["title"] == "API Test"
    
    # Update (Archive)
    resp4 = client.patch(f"/api/conversations/{conv_id}", json={"status": "archived"})
    assert resp4.status_code == 200
    assert resp4.json()["status"] == "archived"
    
    # Should not appear in standard list
    resp5 = client.get("/api/conversations/")
    assert not any(c["conversation_id"] == conv_id for c in resp5.json())
    
    # Delete
    resp6 = client.delete(f"/api/conversations/{conv_id}")
    assert resp6.status_code == 200
    
    resp7 = client.get(f"/api/conversations/{conv_id}")
    assert resp7.status_code == 404
