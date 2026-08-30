# Implementation Plan: Sprint 2 — Attack-Surface Graph & Delta Detection

## Executive Summary
This plan outlines the architecture and execution sequence for Sprint 2 of the ARGUS autonomous security research platform.
The objective is to connect structured evidence gathered from recon tools (Subfinder, HTTPX, Katana, Nuclei) into a strongly-typed `KnowledgeGraph`, integrate graph queries into `ResearchPlanner` and `GapAnalyzer`, provide an `AttackSurfaceDiffEngine` for delta detection across missions, and verify all functionality with >= 15 tests and 0 regressions.

## Milestones & Work Breakdown

### Milestone 1: Attack-Surface Graph Builder (`AttackSurfaceGraphBuilder`)
- **Target Files**:
  - `argus/graph/attack_surface.py` (New file)
  - `argus/graph/__init__.py` (Exports)
  - `argus/runtime/mission.py` (Add `attack_surface_graph` field and alias)
- **Key Capabilities**:
  - Typed nodes: `target`, `subdomain`, `live_host`, `endpoint`, `technology`, `vulnerability`
  - Typed edges: `RESOLVES_TO`, `HOSTS`, `HAS_ENDPOINT`, `RUNS_TECHNOLOGY`, `HAS_VULNERABILITY`
  - Canonical node ID conventions ensuring 100% idempotency
  - Flexible ingestion from `EvidenceStore` and `Mission` objects.

### Milestone 2: Graph Query Interface & Planning Integration
- **Target Files**:
  - `argus/graph/graph.py` (Additive query methods)
  - `argus/planning/gap_analysis.py` (Dual-mode gap analysis with graph support)
  - `argus/runtime/mission_runtime.py` (Graph builder invocation in `AutonomousMissionRuntime.step()`)
- **Key Capabilities**:
  - `get_hosts_without_endpoints() -> list[Node]`
  - `get_hosts_without_vulnerabilities() -> list[Node]`
  - `get_asset_counts() -> dict[str, int]`
  - `GapAnalyzer` targets specific uncovered hosts in `CoverageGap.related_assets` when graph is present, falling back gracefully to bare mission lists.

### Milestone 3: Attack Surface Diff Engine (`AttackSurfaceDiffEngine`)
- **Target Files**:
  - `argus/graph/diff.py` (New file)
  - `argus/graph/__init__.py` (Exports)
- **Key Capabilities**:
  - Dataclasses `HostChange` and `AttackSurfaceDiff`
  - Granular detection of added/removed subdomains, live hosts, endpoints, technologies, and vulnerabilities
  - Granular detection of in-place host changes (status codes, servers, technologies, endpoints, vulnerabilities)
  - Poly-input support (diffing Missions, KnowledgeGraphs, or EvidenceStores).

### Milestone 4: Comprehensive Test Suite & Victory Verification
- **Target Files**:
  - `tests/graph/test_attack_surface_builder.py`
  - `tests/graph/test_graph_queries.py`
  - `tests/graph/test_attack_surface_diff.py`
  - `tests/graph/test_graph_integration.py`
- **Key Capabilities**:
  - 25+ comprehensive test cases covering R1, R2, R3, R4
  - Full suite verification (`python -m pytest tests/ --ignore=tests/workspace -x -q` -> >= 508 passed, 0 failed)
  - E2E Mission test verification (`tests/runtime/test_e2e_mission.py`).

## Acceptance Criteria Checklist
- [ ] R1: `graph.node_count() == 10` for standard 2-sub/2-host/3-ep/1-tech/1-vuln (+1 target) fixture.
- [ ] R1: `nodes_by_type()` filters all 5+ asset types accurately.
- [ ] R1: All 5 edge types (`RESOLVES_TO`, `HOSTS`, `HAS_ENDPOINT`, `RUNS_TECHNOLOGY`, `HAS_VULNERABILITY`) correctly populated.
- [ ] R1: Graph builder is strictly idempotent.
- [ ] R1: Accessible as `mission.attack_surface_graph`.
- [ ] R2: Hosts with no endpoint coverage query works.
- [ ] R2: Hosts with no vulnerability scan query works.
- [ ] R2: Asset counts by type query returns dictionary of counts.
- [ ] R3: Structured diff correctly detects additions, removals, and changed host drift.
- [ ] R4: 0 regressions across all 493+ baseline tests; >= 15 new comprehensive tests passing.
