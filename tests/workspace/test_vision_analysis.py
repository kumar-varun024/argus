import pytest
from fastapi.testclient import TestClient
from fastapi import FastAPI
import os
import uuid
import json
from pathlib import Path
from argus.workspace.api import router, repository, evidence_manager
from argus.workspace.models import Conversation, Message
from argus.workspace.storage import AttachmentStorage

@pytest.fixture
def test_app() -> FastAPI:
    app = FastAPI()
    app.include_router(router)
    return app

@pytest.fixture
def client(test_app) -> TestClient:
    repository._cache.clear()
    
    with TestClient(test_app) as c:
        yield c

def test_attachment_upload_and_auth(client):
    headersA = {"x-user-id": "user_A"}
    headersB = {"x-user-id": "user_B"}
    
    # Create conversation for User A
    conv_res_A = client.post("/api/conversations/", json={}, headers=headersA)
    conv_A_id = conv_res_A.json()["conversation_id"]
    
    # In a real app we'd test the web/app.py upload but since this is an API router test we mock the storage and check API routes.
    # We will test the file serving endpoint for auth.
    
    # Manually attach a mock image
    conv = repository.get(conv_A_id)
    from argus.workspace.models import ImageAttachment
    
    att_id = str(uuid.uuid4())
    att = ImageAttachment(
        image_id=att_id,
        filename="test.png",
        mime_type="image/png",
        size=1024,
        storage_reference="/tmp/fake_image.png"
    )
    msg = Message(role="user", text="Look at this", attachments=[att])
    conv.messages.append(msg)
    repository.save(conv)
    
    # Auth test
    # User B trying to access User A's attachment
    res = client.get(f"/api/attachments/{att_id}?cid={conv_A_id}", headers=headersB)
    assert res.status_code == 403
    
    # User A accesses it (but FileNotFoundError since it's a fake path)
    res2 = client.get(f"/api/attachments/{att_id}?cid={conv_A_id}", headers=headersA)
    assert res2.status_code == 404 # Fails gracefully due to missing file, but auth passed

def test_vision_pipeline_capability_fallback():
    from argus.workspace.vision import VisionPipeline
    from argus.workspace.provider import MockModelProvider
    from argus.workspace.models import ImageAttachment
    
    class NoVisionProvider(MockModelProvider):
        def capabilities(self):
            return {"vision": False, "streaming": True}
            
    pipeline = VisionPipeline(provider=NoVisionProvider())
    att = ImageAttachment(image_id="1", filename="test.png", mime_type="image/png", size=1024, storage_reference="/tmp/a")
    result = pipeline.analyze(att)
    
    assert result.analysis_status == "UNSUPPORTED"
    assert "does not support image analysis" in result.analysis_result

def test_vision_pipeline_success():
    from argus.workspace.vision import VisionPipeline
    from argus.workspace.provider import MockModelProvider
    from argus.workspace.models import ImageAttachment
    
    pipeline = VisionPipeline(provider=MockModelProvider())
    att = ImageAttachment(image_id="1", filename="test.png", mime_type="image/png", size=1024, storage_reference="/tmp/a")
    result = pipeline.analyze(att)
    
    assert result.analysis_status == "COMPLETED"
    assert "Mocked" in result.analysis_result
    assert len(result.visual_observations) == 1
    assert result.visual_observations[0].semantic_status == "OBSERVATION"
