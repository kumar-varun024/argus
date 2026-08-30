# Project: ARGUS Autonomous Security Platform — Phase 8: Path & Directory Traversal Engine

## Architecture
ARGUS employs an autonomous offensive-security pipeline consisting of recon (subfinder, httpx, katana), vulnerability detection collectors (nuclei, info_disclosure, access_control, and path_traversal), evidence management, and attack surface graph reasoning.

In Phase 8, the Path & Directory Traversal Engine actively fuzzes discovered endpoint parameters and URL paths for directory escape vulnerabilities using `AuthenticatedHttpClient`.

```
[Discovered Endpoints & Hosts] -> [PathTraversalCollector]
                                            |
                       +--------------------+--------------------+
                       |                                         |
            [Payload Generation Engine]                 [HTTP Dispatch via AuthenticatedHttpClient]
            - Standard (../, ....//)                    - Session-aware & scope-checked
            - Encoded (%2e%2e%2f, double)               - Exponential backoff & retry
            - Absolute (/etc/passwd, win.ini)                    |
            - Bypasses (%00, null bytes)                         v
                       |                                [Response Analyzer]
                       +-------------------------------> - OS Signatures (root:x:0:0:, [extensions], boot loader)
                                                         - False Positive Filtering (Echo suppression, 404/500 discard)
                                                                 |
                                                                 v
                                            [Evidence & Graph Convergence]
                                            - Evidence(category="path_traversal", severity="critical")
                                            - mission.vulnerabilities & mission.evidence update
                                            - AttackSurfaceGraph: HAS_VULNERABILITY & HAS_ENDPOINT edges
```

## Feature Inventory
| # | Feature | Description | Milestone | Source | Status |
|---|---------|-------------|-----------|--------|--------|
| 1 | `PathTraversalCollector` Core | Base collector executing against endpoints/live_hosts via `AuthenticatedHttpClient` | M1 | ORIGINAL_REQUEST § R1 | DONE |
| 2 | Traversal Payload Engine | Generates standard (`../`, `....//`), encoded (`%2e%2e%2f`, double), absolute (`/etc/passwd`, `win.ini`), null-byte (`%00`) payloads | M1 | ORIGINAL_REQUEST § R2 | DONE |
| 3 | OS Signature & FP Analyzer | Regex signature matching (`root:x:0:0:`, `[extensions]`, `boot loader`) with reflection & status code filtering | M1 | ORIGINAL_REQUEST § R3 | DONE |
| 4 | Pipeline & DAG Integration | `TaskGenerator` recon templates, gap resolution, `registry.py` tool registration, `plugins.py` adapter hook | M2 | ORIGINAL_REQUEST § R4 | DONE |
| 5 | Attack Surface Graph Wiring | `HAS_VULNERABILITY` and `HAS_ENDPOINT` graph edge creation & `AttackSurfaceGraphBuilder` support | M2 | ORIGINAL_REQUEST § R4 | DONE |
| 6 | Test Suite & Zero Regression | >=15 new tests in `tests/collectors/test_path_traversal.py`, mock tests, full 749+ test suite pass | M3 | ORIGINAL_REQUEST § Acceptance Criteria | DONE |

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| 1 | Collector, Payloads & Signature Detection | Implement `PathTraversalCollector`, `PayloadGenerator`, `SignatureAnalyzer` in `argus/collectors/path_traversal.py` | None | DONE |
| 2 | Pipeline Connectivity & Graph Integration | Wire `TaskGenerator`, `registry.py`, `plugins.py`, `argus/graph/attack_surface.py` | M1 | DONE |
| 3 | Verification, Tests & Zero Regression | Add >=15 tests, mock verification test on `root:x:0:0:root:/root:/bin/bash`, verify 749+ tests pass | M1, M2 | DONE |

## Code Layout
- `argus/collectors/path_traversal.py` — Core collector, payload generator, and signature analyzer
- `argus/collectors/__init__.py` — Export `PathTraversalCollector`
- `argus/planning/task_generator.py` — DAG recon template `path_traversal` & gap resolution
- `argus/runtime/registry.py` — Internal tool registration `path_traversal`
- `argus/runtime/plugins.py` — `PluginExecutorAdapter` fallback instantiation
- `argus/graph/attack_surface.py` — `category == "path_traversal"` edge wiring in `AttackSurfaceGraphBuilder`
- `tests/collectors/test_path_traversal.py` — Comprehensive unit and integration tests (19 tests)
- `tests/runtime/test_e2e_path_traversal.py` — E2E mission integration test (1 test)
- `tests/collectors/test_path_traversal_adversarial.py` — Adversarial stress test suite (92 tests)

## Interface Contracts
### `PathTraversalCollector`
- `__init__(http_client: Optional[Any] = None, payloads: Optional[List[str]] = None, timeout: float = 5.0, analyzer: Optional[Any] = None)`
- `collect(mission: Any) -> List[Evidence]`
- `execute(mission: Any) -> List[Evidence]`
- Emits `Evidence(category="path_traversal", severity="critical", status="CONFIRMED", confidence=0.95)`
