# E2E Test Infra: ARGUS Sprint 11 — Command Injection (CMDi) Detection Engine

## Test Philosophy
- Opaque-box, requirement-driven. Derives from `ORIGINAL_REQUEST.md § 2026-08-30T11:08:07Z`.
- Methodology: Category-Partition + BVA + Pairwise + Workload Testing across Tiers 1-4.
- Target baseline: 996 currently passing tests -> target $\ge 1016$ passing tests (0 regressions).

## Feature Inventory & Test Mapping
| # | Feature | Source | Tier 1 (Coverage) | Tier 2 (Boundary) | Tier 3 (Pairwise) | Tier 4 (E2E) |
|---|---------|--------|:-----------------:|:-----------------:|:-----------------:|:------------:|
| 1 | Result-Based CMDi | ORIGINAL_REQUEST R2 | 5 test cases | 5 test cases | ✓ | ✓ |
| 2 | Time-Based Blind CMDi | ORIGINAL_REQUEST R2 | 5 test cases | 5 test cases | ✓ | ✓ |
| 3 | Error-Based CMDi | ORIGINAL_REQUEST R2 | 5 test cases | 5 test cases | ✓ | ✓ |
| 4 | Separator & Bypass Mutations | ORIGINAL_REQUEST R3 | 5 test cases | 5 test cases | ✓ | ✓ |
| 5 | Parameter Injection Points | ORIGINAL_REQUEST R1 | 5 test cases | 5 test cases | ✓ | ✓ |
| 6 | DAG Scheduling & Registry | ORIGINAL_REQUEST R4 | 3 test cases | 2 test cases | ✓ | ✓ |
| 7 | Attack Surface Graph Edges | ORIGINAL_REQUEST R4 | 3 test cases | 2 test cases | ✓ | ✓ |

## Test Architecture
- Test files:
  - `tests/collectors/test_command_injection.py`: Unit and component tests for CommandInjectionCollector, PayloadGenerator, Analyzer, Parameter injection vectors, Mutation strategies, False positive suppression.
  - `tests/pipeline/test_cmdi_pipeline.py`: DAG Task generation, Registry resolution, Graph node/edge creation (`HAS_ENDPOINT`, `HAS_VULNERABILITY`), and Mission execution loop.
- Test runner invocation: `python3 -m pytest tests/ --ignore=tests/workspace -x -q`
- Expected outcome: All 996+ existing tests pass + $\ge 20$ new tests pass with exit code 0.
