import pytest
from argus.workspace.vision import VisionPipeline
from argus.workspace.models import ImageAttachment

def test_vision_pipeline():
    pipeline = VisionPipeline()
    att = ImageAttachment(image_id="img-1")
    
    assert att.analysis_status == "PENDING"
    
    res = pipeline.analyze(att)
    
    assert res.analysis_status == "COMPLETED"
    assert len(res.visual_observations) == 2
    assert res.visual_observations[0].semantic_status == "OBSERVATION"
    assert "HTTP GET" in res.analysis_result
