import pytest
from fastapi import UploadFile, HTTPException
from io import BytesIO
from argus.workspace.storage import AttachmentStorage

def test_attachment_storage_valid_mime(tmp_path):
    storage = AttachmentStorage(storage_dir=str(tmp_path))
    
    file_obj = BytesIO(b"fake image data")
    upload = UploadFile(filename="test.png", file=file_obj, headers={"content-type": "image/png"})
    
    res = storage.save_upload(upload, "img-123")
    assert res["mime_type"] == "image/png"
    assert "img-123.png" in res["storage_reference"]
    
def test_attachment_storage_invalid_mime(tmp_path):
    storage = AttachmentStorage(storage_dir=str(tmp_path))
    
    file_obj = BytesIO(b"fake pdf data")
    upload = UploadFile(filename="test.pdf", file=file_obj, headers={"content-type": "application/pdf"})
    
    with pytest.raises(HTTPException) as exc:
        storage.save_upload(upload, "img-124")
    assert exc.value.status_code == 400
    assert "Unsupported file format" in exc.value.detail
