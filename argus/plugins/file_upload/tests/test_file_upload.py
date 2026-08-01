import pytest
from argus.runtime.mission import Mission
from argus.plugins.interfaces import ControlledMission
from argus.plugins.file_upload.plugin import FileUploadPlugin

def test_file_upload_intelligence_plugin():
    mission = Mission("test")
    mission.endpoints = [
        {"path": "/api/upload/avatar", "method": "POST"},
        {"path": "/api/import/csv", "method": "POST"},
        {"path": "/api/attachments/upload", "method": "POST"},
        {"path": "/api/tmp/download", "method": "GET"}
    ]
    
    plugin = FileUploadPlugin()
    controlled = ControlledMission(mission)
    plugin.execute(controlled)
    
    assert len(mission.upload_workflows) > 0
    titles = [inv.title.lower() for inv in mission.upload_workflows]
    
    # Should flag avatar processing, csv import, temporary storage, and attachment ownership
    assert any("file processing workflow" in t and "avatar" in t for t in titles)
    assert any("data import" in t for t in titles)
    assert any("temporary storage" in t for t in titles)
    assert any("attachment" in t for t in titles)
    
    # Check inventory
    assert len(mission.file_inventory) == 4
