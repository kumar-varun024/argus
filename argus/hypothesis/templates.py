import logging
from argus.hypothesis.models import Hypothesis, HypothesisCategory

logger = logging.getLogger(__name__)

class HypothesisTemplateBuilder:
    """Generates structured reasoning and validation guidance for Hypotheses."""

    @staticmethod
    def generate_reasoning(hypothesis: Hypothesis) -> str:
        """Generates the primary reason text explaining why this hypothesis was formed."""
        reasons = []
        
        if hypothesis.related_investigations:
            reasons.append(f"Derived from {len(hypothesis.related_investigations)} active investigation(s).")
            
        if hypothesis.related_evidence:
            reasons.append(f"Supported by {len(hypothesis.related_evidence)} evidence bundle(s).")
            
        if hypothesis.business_objects:
            reasons.append(f"Impacts core business objects: {', '.join(hypothesis.business_objects)}.")
            
        if not reasons:
            return "Formed based on general mission observation and coverage gaps."
            
        return " ".join(reasons)

    @staticmethod
    def generate_manual_validation(hypothesis: Hypothesis) -> str:
        """Generates step-by-step manual validation instructions for a researcher."""
        steps = []
        
        # Generic prefix
        steps.append("1. Review the referenced evidence bundles and investigations to understand the context.")
        
        if hypothesis.category == HypothesisCategory.AUTHORIZATION:
            steps.append("2. Authenticate as two distinct users with different privilege levels.")
            steps.append("3. Attempt to access the related endpoints or objects identified in the evidence.")
            steps.append("4. Verify if authorization controls are enforced correctly on the server side.")
        
        elif hypothesis.category == HypothesisCategory.AUTHENTICATION:
            steps.append("2. Analyze the authentication flow identified in the evidence.")
            steps.append("3. Attempt to bypass or subvert the token/session generation process.")
            
        elif hypothesis.category == HypothesisCategory.BUSINESS_LOGIC:
            steps.append("2. Map out the full workflow steps identified.")
            steps.append("3. Attempt to execute steps out of order or skip mandatory steps.")
            steps.append("4. Verify if the application state remains consistent.")
            
        elif hypothesis.category == HypothesisCategory.API:
            steps.append("2. Inspect the identified API endpoints.")
            steps.append("3. Test for excessive data exposure, mass assignment, or lack of rate limiting.")
            
        else:
            steps.append(f"2. Investigate the identified {hypothesis.category.value} components.")
            steps.append("3. Verify the configurations and behaviors against expected security baselines.")

        return "\n".join(steps)
