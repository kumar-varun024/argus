import json
from argus.ai.context import ContextBuilder

def build_research_prompt(mission):
    builder = ContextBuilder()
    context = builder.build(mission)
    
    prompt = f"""
You are a senior security researcher analyzing an application during an authorized penetration test.
Analyze the application's architecture and provide structured research guidance based ONLY on the supplied context.

TARGET CONTEXT:
{json.dumps(context, indent=2)}

INSTRUCTIONS:
Answer the following questions based solely on the context:
1. What are the primary business objects?
2. What are the likely business workflows?
3. What are the likely authorization boundaries?
4. Which resources appear security-sensitive?
5. Which manual investigations should be prioritized?
6. Which areas lack sufficient evidence?
7. What additional reconnaissance would reduce uncertainty?

CRITICAL CONSTRAINTS:
- Never claim a vulnerability.
- Never invent evidence.
- Never fabricate technologies.
- Base every statement only on supplied context.
- Express uncertainty when evidence is incomplete.

OUTPUT FORMAT:
Return a strict JSON object exactly matching this structure:
{{
    "executive_summary": "string",
    "business_objects": ["string"],
    "business_workflows": ["string"],
    "authorization_boundaries": ["string"],
    "sensitive_operations": ["string"],
    "high_value_assets": ["string"],
    "research_questions": ["string"],
    "missing_evidence": ["string"],
    "recommended_next_steps": ["string"],
    "confidence": "string",
    "unknown_areas": ["string"]
}}
"""
    return prompt.strip()