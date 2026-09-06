from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Set

logger = logging.getLogger(__name__)


@dataclass
class ScanTask:
    key: str
    title: str
    tool_id: str
    dependencies: List[str] = field(default_factory=list)
    category: str = ""
    phase: str = "recon"
    priority: float = 0.0
    goal: str = ""
    required_inputs: List[str] = field(default_factory=list)
    expected_outputs: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "key": self.key,
            "title": self.title,
            "tool_id": self.tool_id,
            "dependencies": list(self.dependencies),
            "category": self.category,
            "phase": self.phase,
            "priority": self.priority,
            "goal": self.goal,
            "required_inputs": list(self.required_inputs),
            "expected_outputs": list(self.expected_outputs),
            "metadata": dict(self.metadata),
        }


class ScanDAG:
    """
    Dependency-aware DAG parser and deterministic topological sorter
    for reconnaissance and vulnerability detection collectors.
    """

    @classmethod
    def create_for_profile(cls, profile_name: str = "full") -> ScanDAG:
        """
        Creates and returns a ScanDAG instance configured for the specified profile.

        Profiles:
            - 'full': All 26 reconnaissance and vulnerability detection tasks.
            - 'recon': Reconnaissance phase tasks only (subfinder, httpx, katana_crawler, nuclei, info_disclosure).
            - 'vuln' (or 'vulnerability'): Vulnerability detection phase tasks only.
            - 'quick': Reconnaissance tasks + high-priority vulnerability detection tasks.
        """
        base_dag = cls()
        norm = (profile_name or "full").lower().strip()

        if norm in ("full", "all", "default"):
            return base_dag

        if norm in ("recon", "reconnaissance", "recon-only"):
            recon_tasks = [t for t in base_dag.tasks if t.phase == "recon"]
            return cls(tasks=recon_tasks)

        if norm in ("vuln", "vulnerability", "vuln-only"):
            vuln_tasks = [t for t in base_dag.tasks if t.phase == "vulnerability"]
            return cls(tasks=vuln_tasks)

        if norm in ("quick", "fast"):
            quick_keys = {
                "subfinder",
                "httpx",
                "katana_crawler",
                "nuclei",
                "info_disclosure",
                "sql_injection",
                "xss",
                "auth_bypass",
                "access_control",
                "ssrf",
                "command_injection",
                "cors_security",
                "cache_security",
            }
            quick_tasks = [
                t for t in base_dag.tasks
                if t.key in quick_keys or (t.phase == "vulnerability" and t.priority >= 0.82)
            ]
            return cls(tasks=quick_tasks)

        return base_dag

    from_profile = create_for_profile

    def __init__(self, tasks: Optional[List[ScanTask]] = None):
        self._tasks: Dict[str, ScanTask] = {}
        self._task_order: List[str] = []

        if tasks is not None:
            for task in tasks:
                self.add_task(task)
        else:
            self._load_default_recon_templates()

    def _load_default_recon_templates(self) -> None:
        """Loads default task definitions from argus.planning.templates.RECON_TEMPLATES."""
        try:
            from argus.planning.templates import RECON_TEMPLATES as _RECON_TEMPLATES
        except ImportError as e:
            logger.error(f"Failed to import RECON_TEMPLATES: {e}")
            return

        recon_keys = {"subfinder", "httpx", "katana_crawler", "nuclei", "info_disclosure"}

        for key, template in _RECON_TEMPLATES.items():
            cat = template.get("category", "")
            cat_str = getattr(cat, "value", str(cat)) if cat else ""
            tool_id = template.get("metadata", {}).get("tool_id", key)
            phase = "recon" if key in recon_keys else "vulnerability"

            task = ScanTask(
                key=key,
                title=template.get("title", key),
                tool_id=tool_id,
                dependencies=list(template.get("dependencies", [])),
                category=cat_str,
                phase=phase,
                priority=float(template.get("priority", 0.0)),
                goal=template.get("goal", ""),
                required_inputs=list(template.get("required_inputs", [])),
                expected_outputs=list(template.get("expected_outputs", [])),
                metadata=dict(template.get("metadata", {})),
            )
            self.add_task(task)

    def add_task(self, task: ScanTask) -> None:
        """Registers a ScanTask in the DAG."""
        if task.key in self._tasks:
            # Overwrite existing
            self._tasks[task.key] = task
        else:
            self._tasks[task.key] = task
            self._task_order.append(task.key)

    def get_task(self, key_or_identifier: str) -> Optional[ScanTask]:
        """Look up a task by key, tool_id, or title."""
        if key_or_identifier in self._tasks:
            return self._tasks[key_or_identifier]

        for task in self._tasks.values():
            if task.title == key_or_identifier or task.tool_id == key_or_identifier:
                return task
        return None

    @property
    def tasks(self) -> List[ScanTask]:
        """Returns all registered ScanTask instances in insertion order."""
        return [self._tasks[k] for k in self._task_order if k in self._tasks]

    def _resolve_canonical_key(self, identifier: str) -> Optional[str]:
        """Resolves an identifier (key, tool_id, or title) to its canonical task key."""
        if identifier in self._tasks:
            return identifier
        for task in self._tasks.values():
            if task.title == identifier or task.tool_id == identifier:
                return task.key
        return None

    def get_execution_order(self) -> List[ScanTask]:
        """
        Computes deterministic topological execution order using Kahn's algorithm.
        Recon tasks precede vulnerability detection modules, and tasks respecting
        dependencies are ordered strictly.
        """
        all_tasks = self.tasks
        if not all_tasks:
            return []

        # Build alias lookup to canonical key
        canonical_map: Dict[str, str] = {}
        for task in all_tasks:
            canonical_map[task.key] = task.key
            canonical_map[task.title] = task.key
            canonical_map[task.tool_id] = task.key

        # Adjacency list: prereq -> dependents
        adj: Dict[str, List[str]] = {t.key: [] for t in all_tasks}
        # In-degree count: task.key -> number of prerequisites in this DAG
        in_degree: Dict[str, int] = {t.key: 0 for t in all_tasks}

        # Build dependency graph
        for task in all_tasks:
            resolved_prereqs: Set[str] = set()
            for dep in task.dependencies:
                canonical_prereq = canonical_map.get(dep)
                if canonical_prereq and canonical_prereq in self._tasks and canonical_prereq != task.key:
                    resolved_prereqs.add(canonical_prereq)

            in_degree[task.key] = len(resolved_prereqs)
            for prereq in resolved_prereqs:
                adj[prereq].append(task.key)

        # Index for stable tie-breaking
        key_indices = {t.key: i for i, t in enumerate(all_tasks)}

        def sort_key(k: str):
            t = self._tasks[k]
            # Recon phase first (0), then vulnerability (1)
            phase_score = 0 if t.phase == "recon" else 1
            # Priority descending (-t.priority), then original index ascending
            return (phase_score, -t.priority, key_indices.get(k, 0))

        # Initial zero in-degree queue
        available = [k for k, deg in in_degree.items() if deg == 0]
        available.sort(key=sort_key)

        execution_order: List[ScanTask] = []

        while available:
            # Pick the best candidate deterministically
            curr_key = available.pop(0)
            execution_order.append(self._tasks[curr_key])

            # For all downstream dependent tasks, decrement in-degree
            newly_available: List[str] = []
            for dependent_key in adj[curr_key]:
                in_degree[dependent_key] -= 1
                if in_degree[dependent_key] == 0:
                    newly_available.append(dependent_key)

            if newly_available:
                available.extend(newly_available)
                available.sort(key=sort_key)

        if len(execution_order) < len(all_tasks):
            unresolved = [t.key for t in all_tasks if t not in execution_order]
            raise ValueError(f"Cycle detected in ScanDAG dependencies among tasks: {unresolved}")

        return execution_order
