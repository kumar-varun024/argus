import logging
from typing import List
from argus.orchestration.models import ResearchStep, ResearchStepType, ResearchStepState
from argus.runtime.manager import mission_manager
from argus.investigation.registry import InvestigationRegistry
from argus.evidence.manager import EvidenceManager

logger = logging.getLogger(__name__)

class WorkflowPlanner:
    def __init__(self):
        self.investigation_registry = InvestigationRegistry()
        self.evidence_manager = EvidenceManager()

    def identify_current_state(self, investigation_id: str) -> dict:
        inv = self.investigation_registry.find(investigation_id)
        if not inv:
            return {"status": "Investigation not found"}
        
        evidence = self.evidence_manager.get_by_investigation(investigation_id)
        
        return {
            "title": inv.title,
            "status": inv.status.value,
            "evidence_count": len(evidence),
            "open_questions": self.identify_open_questions(investigation_id)
        }

    def identify_open_questions(self, investigation_id: str) -> List[str]:
        # Dummy implementation for open questions based on investigation status
        inv = self.investigation_registry.find(investigation_id)
        if not inv:
            return []
            
        questions = []
        if inv.status.value == "Open":
            questions.append(f"What evidence exists to support {inv.title}?")
        elif inv.status.value == "In Progress":
            questions.append(f"Are there any contradicting pieces of evidence for {inv.title}?")
        return questions

    def generate_candidate_steps(self, investigation_id: str) -> List[ResearchStep]:
        state = self.identify_current_state(investigation_id)
        steps = []
        
        if state.get("evidence_count", 0) == 0:
            steps.append(ResearchStep(
                title="Identify Initial Endpoints",
                description="Discover endpoints related to the investigation.",
                step_type=ResearchStepType.TOOL_EXECUTION,
                rationale="We need to find endpoints to analyze."
            ))
        else:
            steps.append(ResearchStep(
                title="Review Collected Evidence",
                description="Analyze the currently collected evidence for contradictions.",
                step_type=ResearchStepType.ANALYZE,
                rationale="Ensure the evidence supports the investigation hypothesis."
            ))
            
        return steps

    def rank_candidate_steps(self, steps: List[ResearchStep]) -> List[ResearchStep]:
        # Simple ranking by putting Analyze steps first
        return sorted(steps, key=lambda s: 0 if s.step_type == ResearchStepType.ANALYZE else 1)
