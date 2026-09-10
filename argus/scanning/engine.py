from __future__ import annotations

import logging
import time
from datetime import datetime
from typing import Optional, List, Dict, Any, Set, TYPE_CHECKING

if TYPE_CHECKING:
    from argus.runtime.mission import Mission

from argus.runtime.state_machine import MissionStateMachine, TransitionError
from argus.runtime.registry import ToolRegistry, registry as default_registry
from argus.runtime.plugins import PluginExecutorAdapter
from argus.scanning.models import ScanResult, CollectorResult, CollectorStatus
from argus.scanning.dag import ScanDAG, ScanTask
from argus.reporting.generator import ReportGenerator
from argus.graph.attack_surface import AttackSurfaceGraphBuilder
from argus.evidence.store import EvidenceStore
from argus.evidence.model import Evidence
from argus.graph.graph import KnowledgeGraph

logger = logging.getLogger(__name__)


class ScanEngine:
    """
    Production-grade Scan Orchestration Engine for ARGUS.
    
    Accepts a target Mission, executes the full reconnaissance -> vulnerability
    detection DAG across all modules, dynamically resolves collectors via
    ToolRegistry and PluginExecutorAdapter / collectors module, isolates exceptions
    per collector while skipping dependent tasks, aggregates evidence into
    EvidenceStore and AttackSurfaceGraph, generates reports, and records complete
    scan telemetry.
    """

    def __init__(
        self,
        tool_registry: Optional[ToolRegistry] = None,
        dag: Optional[ScanDAG] = None,
        report_generator: Optional[ReportGenerator] = None,
        output_dir: Optional[str] = None,
        collector_factory: Optional[Any] = None,
    ):
        self.registry = tool_registry or default_registry
        self.dag = dag or ScanDAG()
        self.adapter = PluginExecutorAdapter()
        self.output_dir = output_dir
        self.report_generator = report_generator or ReportGenerator(output_dir=output_dir)
        self.graph_builder = AttackSurfaceGraphBuilder()
        self.collector_factory = collector_factory

    def resolve_collector(self, task: ScanTask) -> Optional[Any]:
        """
        Dynamically resolves and instantiates the collector for a given ScanTask
        without hardcoded imports in the caller.

        Delegates to the canonical
        :class:`argus.core.execution.resolver.CollectorResolver`, which owns the
        single id -> collector mapping shared with the plugin adapter.
        """
        from argus.core.execution.resolver import default_resolver
        return default_resolver.resolve(
            task,
            adapter=self.adapter,
            registry=self.registry,
            factory=self.collector_factory,
        )

    def _transition_mission(
        self,
        mission: Any,
        state_machine: MissionStateMachine,
        target_state: Any,
        reason: str,
    ) -> None:
        """Transitions mission state safely, recording history and timestamp."""
        from argus.runtime.mission import MissionState
        try:
            state_machine.transition_to(target_state, reason=reason)
        except TransitionError as e:
            logger.warning(f"Direct transition to {target_state} failed: {e}; applying fallback")
            now = datetime.utcnow().isoformat()
            record = {
                "from": mission.status.value if hasattr(mission.status, "value") else str(mission.status),
                "to": target_state.value if hasattr(target_state, "value") else str(target_state),
                "reason": reason,
                "timestamp": now,
            }
            if not hasattr(mission, "state_transitions") or mission.state_transitions is None:
                mission.state_transitions = []
            mission.state_transitions.append(record)
            mission.status = target_state
            mission.updated_at = now

    def run(self, mission: Any) -> ScanResult:
        """
        Executes an end-to-end security assessment against the mission target.
        """
        from argus.runtime.mission import MissionState
        t0 = time.time()
        start_time_iso = datetime.utcnow().isoformat()

        # Ensure mission attributes are properly initialized
        if getattr(mission, "evidence", None) is None:
            mission.evidence = EvidenceStore()
        if getattr(mission, "attack_surface_graph", None) is None:
            mission.attack_surface_graph = KnowledgeGraph()
        if getattr(mission, "state_transitions", None) is None:
            mission.state_transitions = []
        if getattr(mission, "reports", None) is None:
            mission.reports = []

        # Register mission in mission_manager so ScopeResolver and clients can resolve scope
        from argus.runtime.manager import mission_manager
        if hasattr(mission, "id") and mission.id:
            mission_manager._active_missions[mission.id] = mission

        state_machine = MissionStateMachine(mission)

        # 1. State machine progression: CREATED -> READY -> RUNNING -> COLLECTING_EVIDENCE
        if mission.status == MissionState.CREATED:
            self._transition_mission(mission, state_machine, MissionState.READY, "Scan engine initialized")

        if mission.status == MissionState.READY:
            self._transition_mission(mission, state_machine, MissionState.RUNNING, "Starting scan execution")

        if mission.status in (MissionState.RUNNING, MissionState.PLANNING, MissionState.RESEARCHING):
            self._transition_mission(
                mission,
                state_machine,
                MissionState.COLLECTING_EVIDENCE,
                "Executing reconnaissance and vulnerability detection collectors",
            )

        # 2. Resolve DAG execution order
        try:
            tasks = self.dag.get_execution_order()
        except Exception as e:
            logger.error(f"DAG resolution failed: {e}", exc_info=True)
            self._transition_mission(mission, state_machine, MissionState.FAILED, f"DAG resolution failed: {e}")
            end_time_iso = datetime.utcnow().isoformat()
            duration_s = time.time() - t0
            return ScanResult(
                scan_id=mission.id,
                target=mission.target,
                status="FAILED",
                start_time=start_time_iso,
                end_time=end_time_iso,
                duration_seconds=duration_s,
                collectors_total=len(self.dag.tasks),
                collectors_run=0,
                collectors_skipped=0,
                collectors_failed=len(self.dag.tasks),
                total_evidence=0,
                vulnerabilities_by_severity={"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
                collector_results=[],
                state_transitions=list(mission.state_transitions),
                report_paths=[],
                graph_summary={},
            )

        completed_task_identifiers: Set[str] = set()
        failed_task_identifiers: Set[str] = set()
        skipped_task_identifiers: Set[str] = set()
        collector_results: List[CollectorResult] = []

        # 3. Execute tasks in topological order
        for task in tasks:
            # Check if any prerequisite failed or was skipped
            prereq_failed = False
            failed_prereq_name = ""
            for dep in task.dependencies:
                canonical_dep = self.dag._resolve_canonical_key(dep) or dep
                if (
                    dep in failed_task_identifiers
                    or dep in skipped_task_identifiers
                    or canonical_dep in failed_task_identifiers
                    or canonical_dep in skipped_task_identifiers
                ):
                    prereq_failed = True
                    failed_prereq_name = dep
                    break

            if prereq_failed:
                skipped_task_identifiers.add(task.key)
                skipped_task_identifiers.add(task.title)
                skipped_task_identifiers.add(task.tool_id)
                collector_results.append(
                    CollectorResult(
                        tool_id=task.tool_id,
                        task_title=task.title,
                        status=CollectorStatus.SKIPPED,
                        evidence_count=0,
                        duration_ms=0.0,
                        error=f"Dependency '{failed_prereq_name}' failed or was skipped",
                        start_time=None,
                        end_time=None,
                        task_key=task.key,
                    )
                )
                continue

            # Resolve collector instance
            collector = self.resolve_collector(task)
            if collector is None:
                err_msg = f"Collector for tool_id '{task.tool_id}' could not be resolved"
                logger.warning(err_msg)
                failed_task_identifiers.add(task.key)
                failed_task_identifiers.add(task.title)
                failed_task_identifiers.add(task.tool_id)
                collector_results.append(
                    CollectorResult(
                        tool_id=task.tool_id,
                        task_title=task.title,
                        status=CollectorStatus.FAILED,
                        evidence_count=0,
                        duration_ms=0.0,
                        error=err_msg,
                        start_time=None,
                        end_time=None,
                        task_key=task.key,
                    )
                )
                continue

            # Execute collector
            t_col_start = time.time()
            col_start_iso = datetime.utcnow().isoformat()
            
            # Record initial evidence count
            initial_count = (
                mission.evidence.count()
                if hasattr(mission.evidence, "count")
                else len(mission.evidence.all() if hasattr(mission.evidence, "all") else list(mission.evidence))
            )

            try:
                if hasattr(collector, "collect"):
                    res = collector.collect(mission)
                elif hasattr(collector, "execute"):
                    res = collector.execute(mission)
                elif hasattr(collector, "discover"):
                    res = self.adapter.execute_plugin(task.tool_id, mission)
                else:
                    raise AttributeError(f"Collector {collector} has no collect, execute, or discover hook")

                # Ingest returned Evidence items into mission.evidence
                if isinstance(res, list):
                    all_existing = (
                        mission.evidence.all()
                        if hasattr(mission.evidence, "all")
                        else list(mission.evidence)
                    )
                    for item in res:
                        if isinstance(item, Evidence) and item not in all_existing:
                            mission.evidence.add(item)

                t_col_end = time.time()
                col_end_iso = datetime.utcnow().isoformat()
                col_duration_ms = (t_col_end - t_col_start) * 1000.0

                current_count = (
                    mission.evidence.count()
                    if hasattr(mission.evidence, "count")
                    else len(mission.evidence.all() if hasattr(mission.evidence, "all") else list(mission.evidence))
                )
                ev_count = max(0, current_count - initial_count)
                if isinstance(res, list) and ev_count == 0:
                    ev_count = len([i for i in res if isinstance(i, Evidence)])

                completed_task_identifiers.add(task.key)
                completed_task_identifiers.add(task.title)
                completed_task_identifiers.add(task.tool_id)

                collector_results.append(
                    CollectorResult(
                        tool_id=task.tool_id,
                        task_title=task.title,
                        status=CollectorStatus.COMPLETED,
                        evidence_count=ev_count,
                        duration_ms=col_duration_ms,
                        error=None,
                        start_time=col_start_iso,
                        end_time=col_end_iso,
                        task_key=task.key,
                    )
                )

            except Exception as exc:
                t_col_end = time.time()
                col_end_iso = datetime.utcnow().isoformat()
                col_duration_ms = (t_col_end - t_col_start) * 1000.0
                err_msg = str(exc)
                logger.warning(
                    f"Collector execution failed for task '{task.title}' ({task.tool_id}): {err_msg}",
                    exc_info=True,
                )

                failed_task_identifiers.add(task.key)
                failed_task_identifiers.add(task.title)
                failed_task_identifiers.add(task.tool_id)

                collector_results.append(
                    CollectorResult(
                        tool_id=task.tool_id,
                        task_title=task.title,
                        status=CollectorStatus.FAILED,
                        evidence_count=0,
                        duration_ms=col_duration_ms,
                        error=err_msg,
                        start_time=col_start_iso,
                        end_time=col_end_iso,
                        task_key=task.key,
                    )
                )

        # 4. Correlation Phase: synthesize attack surface graph
        self._transition_mission(
            mission,
            state_machine,
            MissionState.CORRELATING,
            "Correlating evidence and synthesizing attack surface graph",
        )

        try:
            self.graph_builder.build(mission)
        except Exception as e:
            logger.error(f"AttackSurfaceGraphBuilder failed during correlation: {e}", exc_info=True)

        # Build graph summary snapshot
        graph = mission.attack_surface_graph
        graph_summary = {
            "total_nodes": len(graph.nodes) if hasattr(graph, "nodes") else 0,
            "total_edges": len(graph.edges) if hasattr(graph, "edges") else 0,
            "vulnerabilities": len(graph.nodes_by_type("vulnerability")) if hasattr(graph, "nodes_by_type") else 0,
            "endpoints": len(graph.nodes_by_type("endpoint")) if hasattr(graph, "nodes_by_type") else 0,
            "live_hosts": len(graph.nodes_by_type("live_host")) if hasattr(graph, "nodes_by_type") else 0,
            "subdomains": len(graph.nodes_by_type("subdomain")) if hasattr(graph, "nodes_by_type") else 0,
        }

        # 5. Report Generation
        report_paths: List[str] = []
        try:
            report_paths = self.report_generator.generate_and_save(mission, output_dir=self.output_dir)
        except Exception as e:
            logger.error(f"Report generation failed: {e}", exc_info=True)

        # 5.1 Post-scan Vector RAG Indexing of Findings & Evidence
        try:
            from argus.reporting.vector_indexer import ScanEvidenceIndexer
            indexer = ScanEvidenceIndexer()
            indexer.index_mission(mission)
        except Exception as e:
            logger.warning(f"Post-scan semantic indexing skipped: {e}")


        # 6. Compute vulnerability breakdown by severity
        vulnerabilities_by_severity: Dict[str, int] = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }

        all_evidence = (
            mission.evidence.all()
            if hasattr(mission.evidence, "all")
            else list(mission.evidence)
        )
        for ev in all_evidence:
            s = getattr(ev, "severity", None)
            if s:
                s_str = str(s).lower().strip()
                if s_str in vulnerabilities_by_severity:
                    vulnerabilities_by_severity[s_str] += 1
                elif "crit" in s_str:
                    vulnerabilities_by_severity["critical"] += 1
                elif "high" in s_str:
                    vulnerabilities_by_severity["high"] += 1
                elif "med" in s_str:
                    vulnerabilities_by_severity["medium"] += 1
                elif "low" in s_str:
                    vulnerabilities_by_severity["low"] += 1
                else:
                    vulnerabilities_by_severity["info"] += 1

        # Also account for mission.vulnerabilities if not captured in evidence
        if hasattr(mission, "vulnerabilities") and isinstance(mission.vulnerabilities, list):
            for vuln in mission.vulnerabilities:
                if isinstance(vuln, dict) and "template_id" not in [getattr(e, "metadata", {}).get("template_id") for e in all_evidence]:
                    sev = str(vuln.get("severity", "info")).lower()
                    if sev in vulnerabilities_by_severity:
                        vulnerabilities_by_severity[sev] += 1
                    else:
                        vulnerabilities_by_severity["info"] += 1

        # 7. Final state transition: COMPLETED
        self._transition_mission(mission, state_machine, MissionState.COMPLETED, "Scan completed successfully")

        # 8. Construct final ScanResult
        duration_total_s = time.time() - t0
        end_time_iso = datetime.utcnow().isoformat()

        collectors_run = len([cr for cr in collector_results if cr.status == CollectorStatus.COMPLETED])
        collectors_skipped = len([cr for cr in collector_results if cr.status == CollectorStatus.SKIPPED])
        collectors_failed = len([cr for cr in collector_results if cr.status == CollectorStatus.FAILED])
        total_evidence_count = (
            mission.evidence.count()
            if hasattr(mission.evidence, "count")
            else len(all_evidence)
        )

        return ScanResult(
            scan_id=mission.id,
            target=mission.target,
            status="COMPLETED",
            start_time=start_time_iso,
            end_time=end_time_iso,
            duration_seconds=duration_total_s,
            collectors_total=len(tasks),
            collectors_run=collectors_run,
            collectors_skipped=collectors_skipped,
            collectors_failed=collectors_failed,
            total_evidence=total_evidence_count,
            vulnerabilities_by_severity=vulnerabilities_by_severity,
            collector_results=collector_results,
            state_transitions=list(mission.state_transitions),
            report_paths=list(report_paths),
            graph_summary=graph_summary,
        )
