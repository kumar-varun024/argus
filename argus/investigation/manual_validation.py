from argus.investigation.models import Investigation, InvestigationCategory

class ManualValidationGenerator:
    """Generates non-destructive manual validation guidance for Investigations."""
    
    def generate_guidance(self, investigation: Investigation) -> str:
        """
        Generates safe guidance tailored to the category and context.
        Must respect Mission Policy (no exploitation, no attacks, no destructive actions).
        """
        
        guidance = "Review the identified context for intended behavior.\n"
        
        if investigation.category == InvestigationCategory.AUTHORIZATION:
            guidance += "- Review whether intended roles and ownership rules are enforced throughout the identified workflow.\n"
            guidance += "- Attempt to access the business objects with a lower-privileged test account.\n"
        
        elif investigation.category == InvestigationCategory.BUSINESS_LOGIC:
            guidance += "- Verify the state machine transitions in the workflow.\n"
            guidance += "- Ensure out-of-order execution is correctly handled by the application.\n"
            
        elif investigation.category == InvestigationCategory.AUTHENTICATION:
            guidance += "- Verify session expiration and token validation policies.\n"
            guidance += "- Check for correct implementation of authentication workflows.\n"
            
        elif investigation.category == InvestigationCategory.API:
            guidance += "- Review API endpoints for missing access controls or unexpected data exposure.\n"
            guidance += "- Validate that endpoints strictly require appropriate authentication headers.\n"
            
        else:
            guidance += "- Review the observations and evidence bundles.\n"
            guidance += "- Inspect the involved graph nodes and edges for anomalies.\n"
            
        if investigation.workflows:
            guidance += f"\nSpecific Workflows to check: {', '.join(investigation.workflows)}"
            
        if investigation.business_objects:
            guidance += f"\nSpecific Business Objects to check: {', '.join(investigation.business_objects)}"
            
        return guidance.strip()
