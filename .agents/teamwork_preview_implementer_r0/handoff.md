# Handoff Report: TaskGenerator & GapAnalyzer Refactoring

## Overview
Refactored `TaskGenerator` (`argus/planning/task_generator.py`) and `GapAnalyzer` (`argus/planning/gap_analysis.py`) to produce concrete, dependency-aware recon tasks with explicit `metadata.tool_id` routing, removing all legacy `"ReconAgent"` specialist references and ensuring end-to-end execution through `ToolDispatcher`, `TaskScheduler`, and `ToolRegistry`.

## Key Changes
1. **Concrete Recon Task Generation (`argus/planning/task_generator.py`)**:
   - Implemented `_RECON_TEMPLATES` for:
     - `Discover Subdomains`: `subfinder`, `category=TaskCategory.TECHNOLOGY_DISCOVERY`, `dependencies=[]`, `required_specialists=[]`, `metadata={"tool_id": "subfinder"}`
     - `Fingerprint Live Hosts`: `httpx`, `category=TaskCategory.TECHNOLOGY_DISCOVERY`, `dependencies=["Discover Subdomains"]`, `required_specialists=[]`, `metadata={"tool_id": "httpx"}`
     - `Discover API Endpoints`: `katana_crawler`, `category=TaskCategory.API_DISCOVERY`, `dependencies=["Fingerprint Live Hosts"]`, `required_specialists=[]`, `metadata={"tool_id": "katana_crawler"}`
     - `Scan Live Hosts`: `nuclei`, `category=TaskCategory.EVIDENCE_CORRELATION`, `dependencies=["Fingerprint Live Hosts"]`, `required_specialists=[]`, `metadata={"tool_id": "nuclei"}`
   - Added `generate_recon_tasks()` method to construct the complete concrete pipeline.
   - Refactored `_resolve_template_for_gap` and `from_gaps` to map recon and specialist gaps directly to real registry tool IDs without non-existent specialists (e.g. `graphql_specialist`, `javascript_specialist`, `authorization_specialist`, `authentication_specialist`, `business_logic_specialist`, `api_specialist`).

2. **Recon-State Aware Gap Analysis (`argus/planning/gap_analysis.py`)**:
   - Added `_check_recon_gaps()` to distinguish between distinct recon states:
     - State 1: No subdomains -> returns `Subdomains` gap (`TaskCategory.TECHNOLOGY_DISCOVERY`, severity=0.95)
     - State 2: Subdomains exist, but no live hosts -> returns `Live Hosts` gap (`TaskCategory.TECHNOLOGY_DISCOVERY`, severity=0.90)
     - State 3: Live hosts exist, but no endpoints crawled -> returns `Endpoints` gap (`TaskCategory.API_DISCOVERY`, severity=0.85)
     - State 4: Live hosts exist, but vulnerability scan not performed -> returns `Vulnerability Scanning` gap (`TaskCategory.EVIDENCE_CORRELATION`, severity=0.80)
   - Implemented `_has_vulnerability_scan()` to inspect mission attributes, evidence store, execution history, and scheduled tasks.

3. **Comprehensive Verification & Regression Suite (`tests/planning/test_recon_task_generation.py`)**:
   - `TestExplicitDispatcherRouting`: Verified dispatcher resolves tasks with explicit `metadata.tool_id` (`subfinder`, `httpx`, `katana_crawler`, `nuclei`, `graphql_specialist`).
   - `TestReconStateGapAnalyzer`: Verified all 4 distinct recon states and evidence-backed states.
   - `TestConcreteReconTaskGeneration`: Verified tasks generated from gaps and `generate_recon_tasks()` contain correct tool IDs, outputs, inputs, and no `"ReconAgent"` references.
   - `TestReconTaskExecutionOrder`: Verified `TaskScheduler` respects dependency chains: `subfinder` (Ready) -> `httpx` (unblocked upon completion) -> `katana_crawler` & `nuclei` (unblocked upon completion).

## Test Verification
- Ran full test suite: `python3 -m pytest tests/ --ignore=tests/workspace -x -q`
- Result: **416 passed, 0 failed** (15 new unit/integration tests).
