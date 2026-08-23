import uuid
import time
from datetime import datetime, timezone
from typing import Any, List, Dict, Optional
from argus.runtime.models import ToolExecutionResult, ToolArtifact, ToolExecutionStatus


class ResultCollector:
    """Collects logs, artifacts, metrics, and state updates during tool execution."""

    def __init__(self, tool_id: str, task_id: str):
        self.tool_id = tool_id
        self.task_id = task_id
        self.logs: List[str] = []
        self.observations: List[Any] = []
        self.evidence: List[Any] = []
        self.knowledge_graph_updates: List[Any] = []
        self.workflow_updates: List[Any] = []
        self.files: List[Dict[str, Any]] = []
        self.metrics: Dict[str, Any] = {}
        self.started_at = datetime.now(timezone.utc).isoformat()

    def log(self, message: str):
        """Append a log message."""
        self.logs.append(message)

    def add_observation(self, observation: Any):
        """Add an observation produced by the execution."""
        self.observations.append(observation)

    def add_evidence(self, ev: Any):
        """Add evidence discovered."""
        self.evidence.append(ev)
        
        try:
            from argus.runtime.events import EventBus, RuntimeEventType
            EventBus().publish(RuntimeEventType.EVIDENCE_CREATED, "unknown", details={"category": getattr(ev, "category", "unknown"), "source": getattr(ev, "source", "unknown")})
        except Exception:
            pass

    def add_knowledge_graph_update(self, update: Any):
        """Add a Knowledge Graph update instruction/object."""
        self.knowledge_graph_updates.append(update)

    def add_workflow_update(self, update: Any):
        """Add a Workflow Graph update instruction/object."""
        self.workflow_updates.append(update)

    def add_file(self, path: str, content: Any):
        """Add a file produced by the tool."""
        self.files.append({"path": path, "content": content})

    def add_metric(self, name: str, value: Any):
        """Record a performance or tool-specific metric."""
        self.metrics[name] = value

    def finalize(
        self,
        status: ToolExecutionStatus,
        execution_time_ms: float,
        error: Optional[str] = None
    ) -> ToolExecutionResult:
        """Constructs and returns the finalized ToolExecutionResult with provenance."""
        completed_at = datetime.now(timezone.utc).isoformat()
        
        # Capture provenance metadata for all produced artifacts
        provenance = {
            "tool_id": self.tool_id,
            "task_id": self.task_id,
            "timestamp": completed_at
        }

        artifacts: List[ToolArtifact] = []

        # Wrap observations
        for obs in self.observations:
            obs_id = getattr(obs, "id", str(uuid.uuid4()))
            artifacts.append(
                ToolArtifact(
                    name=f"observation_{obs_id}",
                    type="observation",
                    data=obs,
                    provenance=provenance
                )
            )

        # Wrap evidence
        for ev in self.evidence:
            ev_id = getattr(ev, "id", str(uuid.uuid4()))
            artifacts.append(
                ToolArtifact(
                    name=f"evidence_{ev_id}",
                    type="evidence",
                    data=ev,
                    provenance=provenance
                )
            )

        # Wrap knowledge graph updates
        for i, update in enumerate(self.knowledge_graph_updates):
            artifacts.append(
                ToolArtifact(
                    name=f"kg_update_{i}",
                    type="knowledge_graph_update",
                    data=update,
                    provenance=provenance
                )
            )

        # Wrap workflow updates
        for i, update in enumerate(self.workflow_updates):
            artifacts.append(
                ToolArtifact(
                    name=f"workflow_update_{i}",
                    type="workflow_update",
                    data=update,
                    provenance=provenance
                )
            )

        # Wrap files
        for f in self.files:
            artifacts.append(
                ToolArtifact(
                    name=f"file_{f['path']}",
                    type="file",
                    data=f["content"],
                    provenance=provenance
                )
            )

        # Wrap logs
        if self.logs:
            artifacts.append(
                ToolArtifact(
                    name="execution_logs",
                    type="log",
                    data=self.logs,
                    provenance=provenance
                )
            )

        # Wrap metrics
        if self.metrics:
            artifacts.append(
                ToolArtifact(
                    name="execution_metrics",
                    type="metric",
                    data=self.metrics,
                    provenance=provenance
                )
            )

        return ToolExecutionResult(
            tool_id=self.tool_id,
            task_id=self.task_id,
            status=status,
            observations=self.observations,
            evidence=self.evidence,
            knowledge_graph_updates=self.knowledge_graph_updates,
            workflow_updates=self.workflow_updates,
            files=self.files,
            logs=self.logs,
            metrics=self.metrics,
            artifacts=artifacts,
            error=error,
            execution_time_ms=execution_time_ms,
            started_at=self.started_at,
            completed_at=completed_at
        )
