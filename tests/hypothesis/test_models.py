import pytest
from argus.hypothesis.models import Hypothesis, HypothesisCategory, HypothesisStatus, HypothesisPriority

def test_hypothesis_defaults():
    hyp = Hypothesis(
        title="Test Hyp",
        summary="Test summary",
        description="Test desc",
        category=HypothesisCategory.AUTHORIZATION
    )
    assert hyp.status == HypothesisStatus.DRAFT
    assert hyp.priority == HypothesisPriority.LOW
    assert hyp.confidence == 0.0
    assert hyp.priority_score == 0.0
    assert hyp.id is not None
    assert hyp.created_at is not None
    assert hyp.updated_at is not None
    assert len(hyp.history) == 0

def test_hypothesis_collections():
    hyp = Hypothesis(
        title="Test Hyp",
        summary="Test summary",
        description="Test desc",
        category=HypothesisCategory.API
    )
    assert isinstance(hyp.business_objects, list)
    assert isinstance(hyp.workflows, list)
    assert isinstance(hyp.related_evidence, list)
    assert isinstance(hyp.related_investigations, list)
