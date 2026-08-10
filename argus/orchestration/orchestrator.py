import uuid
import logging
from typing import Dict, Any, Optional
from datetime import datetime
from argus.orchestration.models import (
    ResearchWorkflow, ResearchStep, ResearchStepState, 
    ToolExecution, WorkflowEvent
)
from argus.runtime.manager import mission_manager
from argus.runtime.registry import registry as tool_registry
from argus.authorization.gate import authorization_gate
from argus.evidence.manager import EvidenceManager
from argus.evidence.model import Evidence, ProvenanceData

logger = logging.getLogger(__name__)

class ResearchWorkflowOrchestrator:
    def __init__(self):
        # Using an in-memory dict for this prototype. Real app uses DB.
        self._workflows: Dict[str, ResearchWorkflow] = {}
        self.evidence_manager = EvidenceManager()

    def create_workflow(self, investigation_id: str, mission_id: str) -> ResearchWorkflow:
        workflow = ResearchWorkflow(
            investigation_id=investigation_id,
            mission_id=mission_id
        )
        self._workflows[workflow.id] = workflow
        self._record_event(workflow, "WORKFLOW_CREATED", "Initialized research workflow.")
        return workflow

    def get_workflow(self, workflow_id: str) -> Optional[ResearchWorkflow]:
        return self._workflows.get(workflow_id)

    def plan_next_step(self, workflow_id: str, step: ResearchStep) -> ResearchStep:
        workflow = self.get_workflow(workflow_id)
        if not workflow:
            raise ValueError("Workflow not found")
            
        step.state = ResearchStepState.PLANNING
        workflow.steps.append(step)
        self._record_event(workflow, "STEP_PLANNED", f"Planned step: {step.title}", {"step_id": step.id})
        return step

    def execute_step(self, workflow_id: str, step_id: str, user_id: str = "system_user"):
        workflow = self.get_workflow(workflow_id)
        if not workflow:
            raise ValueError("Workflow not found")
            
        step = next((s for s in workflow.steps if s.id == step_id), None)
        if not step:
            raise ValueError("Step not found")

        # Handle TOOL_EXECUTION steps
        if step.tool_execution:
            tool = tool_registry.get(step.tool_execution.tool_id)
            if not tool:
                step.state = ResearchStepState.FAILED
                step.tool_execution.error_message = "Tool not found"
                self._record_event(workflow, "TOOL_FAILED", "Tool not found in registry", {"step_id": step_id})
                return step

            # Security Gate: Scope + Permission Check (PR9 Integration)
            action = f"EXECUTE_{tool.capability.upper()}"
            auth = authorization_gate.can_execute_action(user_id, action, step.tool_execution.target, workflow.mission_id)
            
            if not auth.allowed:
                step.state = ResearchStepState.BLOCKED
                step.tool_execution.status = "BLOCKED_BY_POLICY"
                step.tool_execution.error_message = auth.reason
                self._record_event(workflow, "STEP_BLOCKED", f"Authorization denied: {auth.reason}", {"step_id": step_id})
                return step

            # Authorized -> Execute (Simulated)
            step.state = ResearchStepState.INVESTIGATING
            step.tool_execution.status = "RUNNING"
            step.tool_execution.started_at = datetime.utcnow().isoformat()
            self._record_event(workflow, "TOOL_INVOKED", f"Started tool {tool.name}", {"step_id": step_id})
            
            # Simulated Execution Result
            # In a real system, this would be async or delegated to an agent
            try:
                # Simulating a successful tool execution
                step.tool_execution.result = {"status": "success", "data": f"Output from {tool.name}"}
                step.tool_execution.status = "COMPLETED"
                step.tool_execution.completed_at = datetime.utcnow().isoformat()
                step.state = ResearchStepState.COMPLETED
                self._record_event(workflow, "TOOL_COMPLETED", f"Tool {tool.name} finished successfully", {"step_id": step_id})
                
                # Auto-create evidence from tool output
                self.create_evidence(workflow_id, step_id, f"Tool Result: {tool.name}", "Simulated result data", user_id)
            except Exception as e:
                step.tool_execution.status = "FAILED"
                step.tool_execution.error_message = str(e)
                step.state = ResearchStepState.FAILED
                self._record_event(workflow, "TOOL_FAILED", f"Tool {tool.name} failed: {e}", {"step_id": step_id})

        else:
            # Simple state update for non-tool steps
            step.state = ResearchStepState.COMPLETED
            self._record_event(workflow, "STEP_COMPLETED", f"Completed step: {step.title}", {"step_id": step_id})
            
        workflow.updated_at = datetime.utcnow().isoformat()
        return step

    def create_evidence(self, workflow_id: str, step_id: str, title: str, content: str, user_id: str = "system_user"):
        workflow = self.get_workflow(workflow_id)
        if not workflow:
            raise ValueError("Workflow not found")
            
        step = next((s for s in workflow.steps if s.id == step_id), None)
        if not step:
            raise ValueError("Step not found")

        prov = ProvenanceData(
            workflow_id=workflow_id,
            step_id=step_id
        )
        
        ev = Evidence(
            mission_id=workflow.mission_id,
            investigation_id=workflow.investigation_id,
            source_type="WORKFLOW_STEP",
            source_id=step_id,
            created_by=user_id,
            title=title,
            description=content,
            provenance=prov,
            status="UNVERIFIED"
        )
        
        saved_ev = self.evidence_manager.save(ev)
        step.produced_evidence_ids.append(saved_ev.evidence_id)
        self._record_event(workflow, "EVIDENCE_CREATED", f"Created evidence: {title}", {"evidence_id": saved_ev.evidence_id})
        return saved_ev

    def _record_event(self, workflow: ResearchWorkflow, event_type: str, desc: str, metadata: Dict[str, Any] = None):
        event = WorkflowEvent(event_type=event_type, description=desc, metadata=metadata or {})
        workflow.events.append(event)
        logger.info(f"Workflow [{workflow.id}] Event: {event_type} - {desc}")
