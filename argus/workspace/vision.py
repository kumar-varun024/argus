import time
from typing import List, Optional
from argus.workspace.models import ImageAttachment, VisualObservation, Message
from argus.workspace.provider import MockModelProvider

VISION_SYSTEM_PROMPT = """You are a highly capable AI security researcher acting as the vision component of Argus.
You have been provided with one or more screenshots from a user's security research session.
Your task is to analyze these images and explain what you see in clear, simple language.

You must structure your response EXACTLY as follows:

WHAT I SEE
[Explain what is visibly present in the screenshot. E.g., UI elements, HTTP requests, responses, status codes, URLs, parameters, headers, error messages, tokens.]

WHAT IT COULD MEAN
[Explain the potential security significance or vulnerability type (e.g. IDOR, BOLA, XSS) implied by the observation.]

WHY IT MATTERS
[Explain the impact of this potential issue in simple, beginner-friendly terms.]

WHAT IS NOT PROVEN YET
[Clearly identify what evidence is missing. Be explicit about what you can only infer versus what is actually proven by the screenshot.]

WHAT TO CHECK NEXT
[Suggest safe, authorized follow-up verification steps.]

CRITICAL RULES:
- Distinguish clearly between OBSERVED facts and INFERRED meaning.
- Do NOT fabricate exploitability, CVSS, backend behavior, or claim a vulnerability is proven if it isn't.
- Do NOT fake visual analysis. If you cannot see the image, say so.
"""

class VisionPipeline:
    """Orchestrates image analysis and visual observation extraction."""
    
    def __init__(self, provider=None):
        # Defaulting to MockModelProvider for tests; in production this would be injected
        self.provider = provider or MockModelProvider()
        
    def analyze(self, attachment: ImageAttachment) -> ImageAttachment:
        """
        Extracts technical observations from the image using the configured AI provider.
        """
        attachment.analysis_status = "PROCESSING"
        
        # 1. Capability check
        capabilities = self.provider.capabilities()
        if not capabilities.get("vision", False):
            attachment.analysis_result = "The currently configured model does not support image analysis. Please configure a vision-capable model."
            attachment.analysis_status = "UNSUPPORTED"
            attachment.model = "unknown"
            return attachment
            
        # 2. Call provider
        try:
            # We treat the single image as a multimodal generate call.
            # Real provider would extract base64 or pass file paths.
            result = self.provider.multimodal_generate(
                messages=[],
                images=[attachment],
                system_prompt=VISION_SYSTEM_PROMPT
            )
            
            attachment.analysis_result = result
            attachment.analysis_status = "COMPLETED"
            attachment.model = "vision-capable-model"
            
            # Create a base observation that Engine can pick up to create Evidence
            obs = VisualObservation(
                image_id=attachment.image_id,
                description="Visual analysis completed. See analysis result for details.",
                category="Image Analysis",
                confidence="UNKNOWN",
                semantic_status="OBSERVATION",
                technical_significance="To be determined by context"
            )
            attachment.visual_observations = [obs]
            
        except Exception as e:
            attachment.analysis_result = f"Analysis failed: {str(e)}"
            attachment.analysis_status = "FAILED"
            
        return attachment
