# Attack Surface Diff Engine & Test Suite Investigation (Sprint 2)

**Author:** Explorer Subagent (`explorer_diff_tests`)  
**Date:** 2026-08-27  
**Working Directory:** `/home/varun/argus/.agents/explorer_diff_tests`  
**Reference Request:** `/home/varun/argus/.agents/ORIGINAL_REQUEST.md`  

---

## 1. Observation

### 1.1 Codebase & File Observations
1. **KnowledgeGraph Base Architecture (`argus/graph/graph.py`, `node.py`, `edge.py`)**:
   - `KnowledgeGraph` (`argus/graph/graph.py:6-165`) implements `nodes: dict[str, Node]` and `edges: list[Edge]` with methods `add()`, `get()`, `connect()`, `all()`, `node_count()`, `edge_count()`, `nodes_by_type()`, `edges_from()`, `edges_to()`, `neighbors()`, `summary()`.
   - `Node` (`argus/graph/node.py:4-18`) is `@dataclass(slots=True)` with `id: str`, `type: str`, `value: str`, `metadata: dict[str, Any]`.
   - `Edge` (`argus/graph/edge.py:4-18`) is `@dataclass(slots=True)` with `source: str`, `target: str`, `type: str`, `metadata: dict[str, Any]`.
   - `builder.py` (`argus/graph/builder.py:4-129`) contains a legacy `KnowledgeGraphBuilder` mapping `BusinessObject` and `APIEndpoint` models. It must be upgraded or complemented with `AttackSurfaceGraphBuilder` to handle recon nodes (`target`, `subdomain`, `live_host`, `endpoint`, `technology`, `vulnerability`) and edges (`RESOLVES_TO`, `HOSTS`, `HAS_ENDPOINT`, `RUNS_TECHNOLOGY`, `HAS_VULNERABILITY`).

2. **Mission State & Evidence Store Models (`argus/runtime/mission.py`, `argus/evidence/store.py`)**:
   - `Mission` (`argus/runtime/mission.py:75-232`) maintains:
     - `subdomains`: `list[str]`
     - `live_hosts`: `list[dict]` (keys: `url`, `scheme`, `host`, `port`, `status`, `title`, `server`, `technologies`)
     - `technologies`: `list[str]`
     - `endpoints`: `list[dict]` (keys: `url`, `path`, `host`, `method`, `params`)
     - `vulnerabilities`: `list[dict]` (keys: `template_id`, `name`, `severity`, `host`, `matched_at`, `description`, `tags`)
     - `evidence`: `EvidenceStore`
   - `EvidenceStore` (`argus/evidence/store.py:4-37`) supports `add()`, `all()`, `filter(category)`, `count()`, `clear()`, iterator protocol.

3. **Baseline Test Suite Run**:
   - Executed command: `python -m pytest tests/ --ignore=tests/workspace -x -q`
   - Exact result: **`493 passed, 2848 warnings in 14.54s`** (exited code 0).
   - Deprecation warnings are solely python 3.12+ `datetime.utcnow()` deprecations across legacy test modules.
   - Zero test failures currently exist.

---

## 2. Logic Chain

### 2.1 Diff Engine Location and Architecture Design
- **Module Path**: `argus/graph/diff.py` (with exports in `argus/graph/__init__.py`). An alias `argus/graph/diff_engine.py` can re-export for developer convenience.
- **Rationale**: Keeps graph algorithms consolidated under `argus/graph/` alongside `graph.py`, `builder.py`, `node.py`, and `edge.py`.

### 2.2 Diff Engine Data Structures
The Diff Engine requires two core dataclasses:
1. `HostChange` (or `HostDiff`): Represents granular host-level drift between two snapshots.
2. `AttackSurfaceDiff`: Top-level structured result containing all additions, removals, and host modifications.

```python
# Proposed data structures in argus/graph/diff.py

from dataclasses import dataclass, field
from typing import Optional, Any

@dataclass
class HostChange:
    """Represents detected drift on a single live host between two missions."""
    host: str
    status_changed: bool = False
    old_status: Optional[int] = None
    new_status: Optional[int] = None
    server_changed: bool = False
    old_server: Optional[str] = None
    new_server: Optional[str] = None
    added_technologies: list[str] = field(default_factory=list)
    removed_technologies: list[str] = field(default_factory=list)
    added_endpoints: list[str] = field(default_factory=list)
    removed_endpoints: list[str] = field(default_factory=list)
    added_vulnerabilities: list[str] = field(default_factory=list)
    removed_vulnerabilities: list[str] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return (
            self.status_changed
            or self.server_changed
            or bool(self.added_technologies)
            or bool(self.removed_technologies)
            or bool(self.added_endpoints)
            or bool(self.removed_endpoints)
            or bool(self.added_vulnerabilities)
            or bool(self.removed_vulnerabilities)
        )

@dataclass
class AttackSurfaceDiff:
    """Structured representation of attack surface deltas between two missions."""
    new_subdomains: list[str] = field(default_factory=list)
    removed_subdomains: list[str] = field(default_factory=list)
    new_live_hosts: list[str] = field(default_factory=list)
    removed_live_hosts: list[str] = field(default_factory=list)
    new_endpoints: list[str] = field(default_factory=list)
    removed_endpoints: list[str] = field(default_factory=list)
    new_technologies: list[str] = field(default_factory=list)
    removed_technologies: list[str] = field(default_factory=list)
    new_vulnerabilities: list[dict] = field(default_factory=list)
    removed_vulnerabilities: list[dict] = field(default_factory=list)
    changed_hosts: list[HostChange] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return bool(
            self.new_subdomains
            or self.removed_subdomains
            or self.new_live_hosts
            or self.removed_live_hosts
            or self.new_endpoints
            or self.removed_endpoints
            or self.new_technologies
            or self.removed_technologies
            or self.new_vulnerabilities
            or self.removed_vulnerabilities
            or self.changed_hosts
        )

    def total_changes(self) -> int:
        return (
            len(self.new_subdomains)
            + len(self.removed_subdomains)
            + len(self.new_live_hosts)
            + len(self.removed_live_hosts)
            + len(self.new_endpoints)
            + len(self.removed_endpoints)
            + len(self.new_technologies)
            + len(self.removed_technologies)
            + len(self.new_vulnerabilities)
            + len(self.removed_vulnerabilities)
            + len(self.changed_hosts)
        )

    def summary(self) -> dict[str, int]:
        return {
            "new_subdomains": len(self.new_subdomains),
            "removed_subdomains": len(self.removed_subdomains),
            "new_live_hosts": len(self.new_live_hosts),
            "removed_live_hosts": len(self.removed_live_hosts),
            "new_endpoints": len(self.new_endpoints),
            "removed_endpoints": len(self.removed_endpoints),
            "new_technologies": len(self.new_technologies),
            "removed_technologies": len(self.removed_technologies),
            "new_vulnerabilities": len(self.new_vulnerabilities),
            "removed_vulnerabilities": len(self.removed_vulnerabilities),
            "changed_hosts": len(self.changed_hosts),
        }
```

### 2.3 Diffing Mechanism & Host Drift Detection
The Diff Engine provides flexible entry points:
- `AttackSurfaceDiffEngine.diff_missions(base: Mission, current: Mission) -> AttackSurfaceDiff`
- `AttackSurfaceDiffEngine.diff_graphs(base: KnowledgeGraph, current: KnowledgeGraph) -> AttackSurfaceDiff`
- `AttackSurfaceDiffEngine.diff_evidence(base: EvidenceStore, current: EvidenceStore) -> AttackSurfaceDiff`
- `AttackSurfaceDiffEngine.diff(base: Any, current: Any) -> AttackSurfaceDiff`

**Algorithm details**:
1. **Subdomains**:
   - `base_subs = {s.lower().strip() for s in base.subdomains}`
   - `curr_subs = {s.lower().strip() for s in current.subdomains}`
   - `new_subdomains = sorted(list(curr_subs - base_subs))`
   - `removed_subdomains = sorted(list(base_subs - curr_subs))`
2. **Endpoints**:
   - Normalize URLs/paths (e.g. `ep.get("url")` or `str(ep)`).
   - Set difference computes `new_endpoints` and `removed_endpoints`.
3. **Technologies**:
   - Normalize tech names (e.g. `tech.lower().strip()`).
   - Set difference computes `new_technologies` and `removed_technologies`.
4. **Vulnerabilities**:
   - Keyed by `(template_id, host)` or `name`.
   - Set comparison computes added and removed vulnerability dictionaries.
5. **Live Hosts & Changed Hosts**:
   - Map hosts by canonical URL or hostname:
     - `base_host_map = {h["url"]: h for h in base.live_hosts}`
     - `curr_host_map = {h["url"]: h for h in current.live_hosts}`
   - Newly appeared hosts: `curr_host_map.keys() - base_host_map.keys()` -> `new_live_hosts`
   - Disappeared hosts: `base_host_map.keys() - curr_host_map.keys()` -> `removed_live_hosts`
   - Common hosts: For each host present in both:
     - Compare `status` / `status_code` (`status_changed`, `old_status`, `new_status`)
     - Compare `server` / `webserver` (`server_changed`, `old_server`, `new_server`)
     - Compare `technologies` list (`added_technologies`, `removed_technologies`)
     - Compare host-specific endpoints (`added_endpoints`, `removed_endpoints`)
     - Compare host-specific vulnerabilities (`added_vulnerabilities`, `removed_vulnerabilities`)
     - If `host_change.has_changes` is True, append to `changed_hosts`.

---

### 2.4 Test Suite Architecture & Matrix (>= 15 Comprehensive Tests)

We recommend organizing new tests cleanly under `tests/graph/`:
- `tests/graph/test_attack_surface_builder.py` (R1 tests)
- `tests/graph/test_graph_queries.py` (R2 tests)
- `tests/graph/test_attack_surface_diff.py` (R3 tests)
- `tests/graph/test_graph_integration.py` (R4 integration tests)

#### Comprehensive Test Matrix (25 Specific Test Cases):

| # | Test Case Name | Target Requirement | Description & Assertions |
|---|---|---|---|
| 1 | `test_builder_standard_recon_graph` | R1 | Build graph with 2 subdomains, 2 live hosts, 3 endpoints, 1 tech, 1 vuln. Assert `graph.node_count() == 10` (1 target + 2 sub + 2 host + 3 ep + 1 tech + 1 vuln). |
| 2 | `test_builder_node_type_filtering` | R1 | Assert `nodes_by_type("subdomain")`, `nodes_by_type("live_host")`, `nodes_by_type("endpoint")`, `nodes_by_type("technology")`, `nodes_by_type("vulnerability")` return exact matching node lists. |
| 3 | `test_builder_all_edge_types_present` | R1 | Verify edges with types `RESOLVES_TO`, `HOSTS`, `HAS_ENDPOINT`, `RUNS_TECHNOLOGY`, `HAS_VULNERABILITY` are correctly connected. |
| 4 | `test_builder_idempotency` | R1 | Run `builder.build(mission)` twice consecutively. Assert node count and edge count remain strictly identical. |
| 5 | `test_builder_populates_from_evidence_store` | R1 | Construct `EvidenceStore` with 5 categories of Evidence objects; build graph; verify all nodes and metadata are populated. |
| 6 | `test_builder_empty_mission` | R1 | Build from empty mission. Assert single target node created and 0 edges without exceptions. |
| 7 | `test_builder_backward_compatibility` | R1 / R4 | Verify legacy `BusinessObject` and `APIEndpoint` graph building (from `test_graph_root.py`) remains 100% compatible. |
| 8 | `test_query_hosts_with_no_endpoint_coverage` | R2 | Graph with Host A (has endpoint) and Host B (no endpoint). Query returns `[Host B]`. |
| 9 | `test_query_hosts_with_no_vulnerability_coverage` | R2 | Graph with Host A (has vuln edge) and Host B (no vuln edge). Query returns `[Host B]`. |
| 10 | `test_query_summary_by_type` | R2 | Verify `graph.summary()` / `graph.summary_by_type()` returns accurate count dictionary matching graph contents. |
| 11 | `test_query_subdomains_for_target` | R2 | Query subdomains resolving to a specific target node via `RESOLVES_TO`. |
| 12 | `test_query_technologies_for_host` | R2 | Query technologies connected to a specific live host via `RUNS_TECHNOLOGY`. |
| 13 | `test_query_endpoints_for_host` | R2 | Query endpoints connected to a specific live host via `HAS_ENDPOINT`. |
| 14 | `test_gap_analyzer_queries_attack_surface_graph` | R2 | Verify `GapAnalyzer` inspects `mission.attack_surface_graph` to target uncovered hosts in gap `related_assets`. |
| 15 | `test_diff_subdomain_additions_and_removals` | R3 | Mission A `[a.example.com, b.example.com]` vs Mission B `[b.example.com, c.example.com]`. Assert `new_subdomains == ["c.example.com"]`, `removed_subdomains == ["a.example.com"]`. |
| 16 | `test_diff_endpoint_additions_and_removals` | R3 | Compare missions with distinct endpoints; assert `new_endpoints` and `removed_endpoints` identified. |
| 17 | `test_diff_technology_additions_and_removals` | R3 | Compare missions with distinct technologies; assert `new_technologies` and `removed_technologies` identified. |
| 18 | `test_diff_vulnerability_additions_and_removals` | R3 | Compare missions with distinct vulnerabilities; assert `new_vulnerabilities` and `removed_vulnerabilities` identified. |
| 19 | `test_diff_changed_hosts_status_code` | R3 | Host with status 200 in Mission A changes to 403 in Mission B. Assert `changed_hosts` contains host with `status_changed=True`, `old_status=200`, `new_status=403`. |
| 20 | `test_diff_changed_hosts_technologies` | R3 | Host with `["Nginx"]` changes to `["Nginx", "React"]`. Assert `changed_hosts` contains host with `added_technologies=["React"]`. |
| 21 | `test_diff_identical_missions_no_changes` | R3 | Comparing identical missions produces `diff.has_changes == False` and `diff.total_changes() == 0`. |
| 22 | `test_diff_from_evidence_stores` | R3 | Diffing two raw `EvidenceStore` instances produces accurate `AttackSurfaceDiff`. |
| 23 | `test_diff_from_knowledge_graphs` | R3 | Diffing two `KnowledgeGraph` instances directly produces accurate `AttackSurfaceDiff`. |
| 24 | `test_diff_summary_and_serialization` | R3 | Verify `diff.summary()` and `diff.total_changes()` methods return structured integer metrics. |
| 25 | `test_e2e_mission_attack_surface_graph_integration` | R4 | Full E2E mission run verifies `mission.attack_surface_graph` is populated at mission completion and `mission.status == COMPLETED`. |

---

## 3. Caveats
- **Legacy KnowledgeGraphBuilder**: `argus/graph/builder.py` currently builds business object nodes. `AttackSurfaceGraphBuilder` should either extend this builder or be unified such that legacy calls in `tests/test_graph_root.py` and `tests/plugins/graphql/` continue to work without disruption.
- **Host Normalization**: A live host can be referenced as `http://api.example.com` or `api.example.com`. The diff engine should normalize URLs by stripping trailing slashes and ensuring consistent protocol/host indexing.
- **Graph Node ID Conventions**: Standard ID prefixes (`target_<target>`, `sub_<subdomain>`, `host_<url_or_host>`, `ep_<url_or_path>`, `tech_<name>`, `vuln_<template_id>`) ensure idempotent lookups and clean traversals.

---

## 4. Conclusion
1. **Module Placement**: The Diff Engine should live in `argus/graph/diff.py` and be exported through `argus/graph/__init__.py`.
2. **Data Model**: `AttackSurfaceDiff` and `HostChange` provide a typed, structured, concrete interface representing all asset additions, removals, and in-place host changes.
3. **Graph Queries**: `KnowledgeGraph` should be extended with helper query methods (`get_hosts_without_endpoints()`, `get_hosts_without_vulnerabilities()`, `summary()`) to directly empower `ResearchPlanner` and `GapAnalyzer`.
4. **Test Suite**: Baseline is solid at **493 passing tests**. Implementing the 25 test cases across `tests/graph/` will achieve comprehensive test coverage for Sprint 2 with 0 regressions.

---

## 5. Verification Method

### Test Execution Command
```bash
python -m pytest tests/ --ignore=tests/workspace -x -q
```
Expected baseline result: `493 passed` (and >= 508 passed once Sprint 2 tests are implemented).

### Specific Test Modules to Run Once Implemented
```bash
python -m pytest tests/graph/ -v
python -m pytest tests/test_graph_root.py -v
python -m pytest tests/runtime/test_e2e_mission.py -v
python -m pytest tests/planning/test_recon_task_generation.py -v
```
