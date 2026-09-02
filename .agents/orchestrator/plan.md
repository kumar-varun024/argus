# Sprint 26 Execution Plan: File Upload Vulnerability Detection Module

## Objective
Build, integrate, test, and independently verify the File Upload Vulnerability Detection Module for the ARGUS platform, ensuring R1-R6 compliance, 30 new tests, and zero regressions against 1,784+ baseline tests.

## Milestone Schedule
1. **Survey & Architecture Mapping (Complete)**:
   - Surveyed `BaseCollector`, `AuthenticatedHttpClient`, `TaskGenerator`, `ToolRegistry`, `AttackSurfaceGraphBuilder`, and `CVSSCalculator`.
   - Baseline test execution verified: 1,784 passed.

2. **Milestone 1: Core Collector & Probing Engine (In Progress)**:
   - Implement `argus/collectors/file_upload.py`.
   - Update `argus/http/client.py` for multipart support if needed.
   - Update `argus/collectors/__init__.py`.

3. **Milestone 2: Pipeline Connectivity & Graph/CVSS Wiring (Planned)**:
   - Wire `argus/runtime/registry.py` and `argus/runtime/plugins.py`.
   - Wire `argus/planning/task_generator.py` (DAG template, gap resolver, input resolver).
   - Wire `argus/graph/attack_surface.py` (vulnerability nodes, `HAS_ENDPOINT`, `HAS_VULNERABILITY` edges).
   - Wire `argus/reporting/cvss.py` (CWE-434, CWE-436, CVSS scores).

4. **Milestone 3: Comprehensive Test Suites (Planned)**:
   - Implement `tests/collectors/test_file_upload.py` (16 tests).
   - Implement `tests/collectors/test_file_upload_adversarial.py` (14 tests).

5. **Milestone 4: Verification, Multi-Agent Review, Audit & Sprint Handoff (Planned)**:
   - Run full regression suite (`python -m pytest tests/ --ignore=tests/workspace -x -q` -> >= 1,814 passed).
   - Dispatch Reviewers, Challengers, and Forensic Auditor.
   - Gate verification.
   - Write handoff to `/home/varun/argus/.agents/sprint26_file_upload/handoff.md`.
