## 2026-09-01T01:25:30Z
You are Worker 1 for Sprint 23: Web Cache Poisoning & Cache Deception Detection Module in the ARGUS platform.

Working directory: /home/varun/argus
Your agent directory: /home/varun/argus/.agents/worker_1
Read the following authoritative specification files before starting:
- /home/varun/argus/.agents/ORIGINAL_REQUEST.md
- /home/varun/argus/.agents/orchestrator/PROJECT.md
- /home/varun/argus/.agents/orchestrator/implementation_plan.md
- /home/varun/argus/.agents/survey_explorer_1/handoff.md
- /home/varun/argus/.agents/survey_spec_miner/handoff.md
- /home/varun/argus/.agents/survey_explorer_2/handoff.md

## MANDATORY INTEGRITY WARNING
DO NOT CHEAT. All implementations must be genuine. DO NOT hardcode test results, create dummy/facade implementations, or circumvent the intended task. A teamwork_preview_auditor will independently verify your work. Integrity violations WILL be detected and your work WILL be rejected.

## Objective & Tasks
You are responsible for implementing the complete Sprint 23 scope across four milestones:
1. Core Collector, Differential Prober, Generator & Security Analyzer (`argus/collectors/cache_security.py`, `argus/collectors/__init__.py`)
2. Pipeline Connectivity & Wiring (`argus/runtime/registry.py`, `argus/runtime/plugins.py`, `argus/planning/task_generator.py`, `argus/graph/attack_surface.py`, `argus/reporting/cvss.py`, `argus/reporting/processor.py`)
3. Unit, Integration & Adversarial Test Suites (`tests/collectors/test_cache_security.py`, `tests/collectors/test_cache_security_adversarial.py`)
4. Full Victory Audit & Zero Regression Verification on existing 1,648+ tests.
