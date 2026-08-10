import pytest
from argus.investigation.registry import InvestigationRegistry
from argus.investigation.models import Investigation, InvestigationCategory

def test_investigation_registry():
    registry = InvestigationRegistry()
    
    inv = Investigation(
        title="Test",
        summary="Test summary",
        description="Test desc",
        category=InvestigationCategory.AUTHORIZATION
    )
    
    registry.add(inv)
    
    assert registry.find(inv.id) == inv
    assert len(registry.search("Test")) == 1
    assert len(registry.filter_by_category(InvestigationCategory.AUTHORIZATION)) == 1
    
    registry.remove(inv.id)
    assert registry.find(inv.id) is None
