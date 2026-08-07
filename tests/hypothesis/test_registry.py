import pytest
from argus.hypothesis.models import Hypothesis, HypothesisCategory, HypothesisStatus
from argus.hypothesis.registry import HypothesisRegistry

@pytest.fixture
def registry():
    return HypothesisRegistry()

@pytest.fixture
def hyp():
    return Hypothesis(
        title="Test Hyp",
        summary="Test summary",
        description="Test desc",
        category=HypothesisCategory.AUTHORIZATION
    )

def test_add_and_find(registry, hyp):
    registry.add(hyp)
    found = registry.find(hyp.id)
    assert found == hyp

def test_remove(registry, hyp):
    registry.add(hyp)
    assert registry.remove(hyp.id) is True
    assert registry.find(hyp.id) is None
    assert registry.remove(hyp.id) is False

def test_search(registry, hyp):
    registry.add(hyp)
    results = registry.search("test")
    assert len(results) == 1
    assert results[0] == hyp

def test_filter_by_category(registry, hyp):
    registry.add(hyp)
    hyp2 = Hypothesis(title="H2", summary="S", description="D", category=HypothesisCategory.API)
    registry.add(hyp2)
    
    auth_results = registry.filter_by_category(HypothesisCategory.AUTHORIZATION.value)
    assert len(auth_results) == 1
    assert auth_results[0] == hyp

def test_filter_by_status(registry, hyp):
    hyp.status = HypothesisStatus.VALIDATED
    registry.add(hyp)
    
    results = registry.filter_by_status(HypothesisStatus.VALIDATED)
    assert len(results) == 1
    assert results[0] == hyp
    
    empty = registry.filter_by_status(HypothesisStatus.DRAFT)
    assert len(empty) == 0

def test_clear(registry, hyp):
    registry.add(hyp)
    registry.clear()
    assert len(registry.get_all()) == 0
