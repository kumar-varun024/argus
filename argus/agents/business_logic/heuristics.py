from abc import ABC, abstractmethod
from typing import List
from argus.agents.business_logic.models import BusinessLogicContext, BusinessHeuristicResult
from argus.intelligence.models import Investigation

class BaseBusinessLogicHeuristic(ABC):
    @property
    @abstractmethod
    def id(self) -> str: pass
    
    @abstractmethod
    def run(self, context: BusinessLogicContext) -> List[BusinessHeuristicResult]: pass

class UnexpectedStateTransitionHeuristic(BaseBusinessLogicHeuristic):
    @property
    def id(self) -> str: return "unexpected_state_transition"
    
    def run(self, context: BusinessLogicContext) -> List[BusinessHeuristicResult]:
        results = []
        for sm_id, sm in context.state_machines.items():
            if len(sm.states) > 2:
                inv = Investigation(
                    title=f"Review state transitions for workflow: {sm.name}",
                    category="State Machine Review",
                    affected_objects=[sm.name],
                    reasoning=f"The workflow {sm.name} has multiple states. It's critical to verify if users can skip mandatory states (e.g., jump from Draft directly to Approved without Submitted).",
                    supporting_evidence=[f"State Machine has {len(sm.states)} states"],
                    manual_validation_steps=[
                        "1. Identify the API request that transitions to the final state.",
                        "2. Attempt to send this request while the object is in the initial state.",
                        "3. Verify if the backend rejects the request due to invalid state transition."
                    ],
                    workflow=sm.name
                )
                results.append(BusinessHeuristicResult(investigation=inv, matched_nodes=[sm.name], heuristic_id=self.id))
        return results

class MissingPrerequisiteHeuristic(BaseBusinessLogicHeuristic):
    @property
    def id(self) -> str: return "missing_prerequisite"
    
    def run(self, context: BusinessLogicContext) -> List[BusinessHeuristicResult]:
        results = []
        for wf in context.workflows:
            if wf.dependencies:
                deps_str = ", ".join(wf.dependencies)
                inv = Investigation(
                    title=f"Verify prerequisites for {wf.name}",
                    category="Workflow Dependency Review",
                    affected_objects=[wf.name],
                    reasoning=f"The workflow {wf.name} depends on {deps_str}. The backend must enforce this prerequisite and not just rely on UI hiding.",
                    supporting_evidence=[f"Workflow dependencies: {deps_str}"],
                    manual_validation_steps=[
                        f"1. Attempt to execute the entry point for {wf.name} directly.",
                        f"2. Do not complete {deps_str} beforehand.",
                        "3. Verify the server enforces the dependency (e.g., returns an error)."
                    ],
                    workflow=wf.name
                )
                results.append(BusinessHeuristicResult(investigation=inv, matched_nodes=[wf.name], heuristic_id=self.id))
        return results

class WorkflowShortcutHeuristic(BaseBusinessLogicHeuristic):
    @property
    def id(self) -> str: return "workflow_shortcut"
    
    def run(self, context: BusinessLogicContext) -> List[BusinessHeuristicResult]:
        results = []
        for wf in context.workflows:
            if len(wf.steps) > 2:
                inv = Investigation(
                    title=f"Review multi-step workflow for shortcuts: {wf.name}",
                    category="Workflow Shortcut Review",
                    affected_objects=[wf.name],
                    reasoning=f"The workflow {wf.name} involves {len(wf.steps)} steps. Users might be able to skip intermediate steps (like payment or agreement) and execute the final step directly.",
                    supporting_evidence=[f"Workflow has {len(wf.steps)} steps"],
                    manual_validation_steps=[
                        "1. Identify the final API request of the workflow.",
                        "2. Execute it without performing the intermediate steps.",
                        "3. Check if the backend allows the operation."
                    ],
                    workflow=wf.name
                )
                results.append(BusinessHeuristicResult(investigation=inv, matched_nodes=[wf.name], heuristic_id=self.id))
        return results

class ReplayableTransactionHeuristic(BaseBusinessLogicHeuristic):
    @property
    def id(self) -> str: return "replayable_transaction"
    
    def run(self, context: BusinessLogicContext) -> List[BusinessHeuristicResult]:
        results = []
        for wf in context.workflows:
            name_lower = wf.name.lower()
            if any(k in name_lower for k in ["payment", "checkout", "refund", "transfer", "submit"]):
                inv = Investigation(
                    title=f"Check for replayable transactions in {wf.name}",
                    category="Critical Transaction Review",
                    affected_objects=[wf.name],
                    reasoning=f"The workflow {wf.name} appears to be a critical transaction. Without proper nonces, idempotency keys, or state locks, an attacker might replay the request to perform the action multiple times.",
                    supporting_evidence=[f"Workflow name suggests critical transaction: {wf.name}"],
                    manual_validation_steps=[
                        "1. Intercept the critical request.",
                        "2. Send it multiple times concurrently (Race condition).",
                        "3. Send it multiple times sequentially (Replay).",
                        "4. Verify the backend prevents duplicate processing."
                    ],
                    workflow=wf.name
                )
                results.append(BusinessHeuristicResult(investigation=inv, matched_nodes=[wf.name], heuristic_id=self.id))
        return results


BUSINESS_LOGIC_HEURISTIC_REGISTRY: List[BaseBusinessLogicHeuristic] = [
    UnexpectedStateTransitionHeuristic(),
    MissingPrerequisiteHeuristic(),
    WorkflowShortcutHeuristic(),
    ReplayableTransactionHeuristic()
]
