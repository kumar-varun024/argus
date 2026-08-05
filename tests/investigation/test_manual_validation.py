import pytest
from argus.investigation.models import Investigation, InvestigationCategory
from argus.investigation.manual_validation import ManualValidationGenerator

def test_manual_validation():
    val_gen = ManualValidationGenerator()
    inv = Investigation(
        title="Test",
        summary="Test",
        description="Test",
        category=InvestigationCategory.AUTHORIZATION
    )
    inv.business_objects = ["User"]
    
    guidance = val_gen.generate_guidance(inv)
    assert "Review the identified context" in guidance
    assert "roles and ownership rules" in guidance
    assert "User" in guidance
    assert "exploit" not in guidance.lower()
