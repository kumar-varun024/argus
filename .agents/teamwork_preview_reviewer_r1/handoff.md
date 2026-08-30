# Adversarial Review & QA Handoff Report: TaskGenerator & Recon Pipeline

## Overview
Completed comprehensive adversarial review and defect remediation for the `TaskGenerator` refactoring and `GapAnalyzer` recon-state awareness changes.

## 1. Defects Identified in Prior Attempt
1. **Fatal Queue Deadlock on Partial / Dynamic Mission Plans**:
   - **Input**: Mission with pre-existing live hosts or multi-round iterative planning where `from_gaps()` generates dependent tasks (`Discover API Endpoints` or `Scan Live Hosts`) without scheduling `Fingerprint Live Hosts` in the same queue batch.
   - **Expected**: Tasks with already-satisfied prerequisites should transition to `READY` and execute immediately.
   - **Actual**: `TaskDependencyResolver.resolve()` required all named dependencies in `task.dependencies` to be in `completed_titles`. Since `Fingerprint Live Hosts` was not in the execution queue, it could never complete, causing `katana_crawler` and `nuclei` tasks to remain permanently `BLOCKED`, deadlocking the scheduler.
   - **Root Cause**: `TaskDependencyResolver.resolve()` did not filter dependencies by active queue membership (`title_map`), unlike `TaskDependencyResolver.topological_order()` which already used `title_set`.
2. **Recon-State Inversion for Pre-Seeded Live Hosts**:
   - **Input**: Mission initialized with `live_hosts` (e.g. IP target or pre-discovered URLs) but empty `subdomains`.
   - **Expected**: `GapAnalyzer` identifies that live hosts exist, skips subdomain discovery, and produces gaps for `Endpoints` and `Vulnerability Scanning`.
   - **Actual**: `GapAnalyzer._check_recon_gaps()` checked `if not subdomains:` first, emitting a `Subdomains` gap and ignoring missing endpoints and vulnerability scans.
   - **Root Cause**: Control flow did not check `live_hosts` before checking `subdomains`.
3. **Incomplete Vulnerability Scan Detection**:
   - **Input**: Mission where Nuclei completed execution recorded in `task_states` or execution event history.
   - **Expected**: `GapAnalyzer._has_vulnerability_scan()` recognizes previous scan and does not emit duplicate vulnerability scan gap.
   - **Actual**: Did not check event objects or `task_states` mapping.
   - **Root Cause**: Narrow check only inspected raw dict fields.

## 2. Changes Made
- `argus/runtime/dependencies.py`:
  - Updated `TaskDependencyResolver.resolve()` to only require completion of dependencies present within the active queue (`title_map`), treating non-queued external prerequisites as satisfied.
- `argus/planning/gap_analysis.py`:
  - Updated `_check_recon_gaps()` to evaluate `live_hosts` presence first, properly handling pre-seeded hosts or IP targets without subdomains.
  - Enhanced `_has_vulnerability_scan()` to inspect execution history events, `task_states` mapping, and completed tasks.
- `argus/planning/task_generator.py`:
  - Refined template input resolution in `from_gaps()` to fallback to live hosts, subdomains, or target when related assets are not explicit.
  - Updated technology fallback logic to avoid unnecessary subfinder recommendation when live hosts are present.
- `tests/planning/test_recon_task_generation.py`:
  - Added unit tests for pre-seeded live hosts without subdomains, unblocked execution of dependent tasks in `TaskScheduler`, and execution history vulnerability scan detection.

## 3. Verification Record
- **Deep Verification (ran actual tests):**
  - Full test suite: `python3 -m pytest tests/ --ignore=tests/workspace -x -q` -> 419 passed in 15.03s.
  - Planning tests: `python3 -m pytest tests/planning/ -v` -> 39 passed in 0.81s.
  - Scheduler and E2E integration: `python3 -m pytest tests/runtime/test_scheduler.py tests/runtime/test_e2e_mission.py -v` -> 8 passed.
  - Acceptance Criteria Dispatcher Routing: Verified all 5 routes (`subfinder`, `httpx`, `katana_crawler`, `nuclei`, `graphql_specialist`) return `PASS`.
- **Unverified aspects:**
  - Live external network calls to third-party binaries (`subfinder`, `httpx`, `katana`, `nuclei`) against real target domains (mocked/sandboxed in test environment).

## 4. Verdict
Refactoring is verified, fully tested, and ready for production merging.
