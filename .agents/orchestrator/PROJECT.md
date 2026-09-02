# Project: ARGUS API Security Testing Module (REST/gRPC)

## Architecture
- **Tripartite Active Collector Pattern**: `APISecurityCollector` (inheriting from `BaseCollector`), `APISecurityPayloadGenerator`, `APISecurityProber` (using `AuthenticatedHttpClient`), and `APISecurityAnalyzer`.
- **Quadruple State Publishing**: State emitted across `raw_mission.evidence`, `raw_mission.vulnerabilities`, `raw_mission.attack_surface_graph`, and `ControlledMission.publish_finding`.
- **Pipeline Connectivity**: Integrated with `TaskGenerator` DAG (dependent on `Discover API Endpoints`), `ToolRegistry` with alias mapping, `PluginExecutorAdapter` fallback resolution, `AttackSurfaceGraphBuilder` Section 27 graph expansion (`HAS_VULNERABILITY` edges), and `CVSSCalculator` (CWE-639, CWE-915, CWE-770).

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| 1 | API Collector & Prober (R1) | Active collector inheriting from BaseCollector using AuthenticatedHttpClient | M1 | ORIGINAL_REQUEST §R1 |
| 2 | Multi-Vector Detection Modes (R2) | 6 modes: Parameter Tampering, Mass Assignment, Rate Limiting Bypass, BOLA/IDOR, Excessive Data Exposure, Method Tampering | M1 | ORIGINAL_REQUEST §R2 |
| 3 | API Response Analysis (R3) | Schema violations, authorization boundaries, rate limit headers, error disclosure, pagination bypass, false positive rejection | M1 | ORIGINAL_REQUEST §R3 |
| 4 | Mutation & Evasion Strategies (R4) | 5 strategies: Content-Type Switching, Parameter Pollution, Header-Based Auth Bypass, Version Downgrade, Encoding Variations | M1 | ORIGINAL_REQUEST §R4 |
| 5 | Pipeline Connectivity (R5) | DAG scheduling in task_generator.py, tool registration in registry.py, plugin fallback in plugins.py, graph expansion in attack_surface.py, CWE-639/915/770 in cvss.py | M2 | ORIGINAL_REQUEST §R5 |
| 6 | Zero Regression & E2E Validation (R6) | 1,828+ baseline passing, >=25 new unit & adversarial tests in tests/collectors/, sprint handoff in .agents/sprint27_api_security/handoff.md | M3, M4 | ORIGINAL_REQUEST §R6 |

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| 1 | Core Collector & Tripartite Models | Implement `argus/collectors/api_security.py` with enums, dataclasses, PayloadGenerator, Prober, Analyzer, and Collector | none | PLANNED |
| 2 | Pipeline Connectivity & Reporting | Wire `task_generator.py`, `registry.py`, `plugins.py`, `attack_surface.py`, `cvss.py` | M1 | PLANNED |
| 3 | Test Suite Implementation & Verification | Create `tests/collectors/test_api_security.py` and `tests/collectors/test_api_security_adversarial.py`, verify >=1,853 tests pass | M1, M2 | PLANNED |
| 4 | Review, Challenger, Forensic Audit & Handoff | Multi-agent verification (Reviewers, Challengers, Auditor) and write `.agents/sprint27_api_security/handoff.md` | M3 | PLANNED |

## Code Layout
- `argus/collectors/api_security.py`: Core collector, prober, analyzer, payload generator
- `argus/planning/task_generator.py`: DAG templates & gap resolution
- `argus/runtime/registry.py`: Tool registry & aliases
- `argus/runtime/plugins.py`: Plugin adapter fallback
- `argus/graph/attack_surface.py`: Section 27 graph expansion
- `argus/reporting/cvss.py`: CWE database & preset vectors
- `tests/collectors/test_api_security.py`: Unit & integration tests
- `tests/collectors/test_api_security_adversarial.py`: Adversarial & resilience tests
- `.agents/sprint27_api_security/handoff.md`: Sprint handoff report
