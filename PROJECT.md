# Project: ARGUS Prototype Pollution & Client-Side Attack Detection Module (Sprint 29)

## Architecture
The Prototype Pollution & Client-Side Attack Detection Module is an active security scanner in ARGUS that discovers, probes, and analyzes client-side and server-side prototype pollution, DOM clobbering, open redirect chains, and clickjacking vulnerabilities across discovered endpoints.

### Subsystem Components
1. **Core Collector Module (`argus/collectors/prototype_pollution.py`)**:
   - `PrototypePollutionCollector` (inheriting from `BaseCollector`)
   - `PrototypePollutionPayloadGenerator`
   - `PrototypePollutionProber`
   - `PrototypePollutionAnalyzer`
   - Data models & enums (`PrototypePollutionSeverity`, `PrototypePollutionVulnerabilityType`, `PrototypePollutionMutationStrategy`, `GadgetFramework`, `PrototypePollutionProbe`, `PrototypePollutionProbeResponse`, `PrototypePollutionResult`)
   - Compatibility aliases (`ClientSideAttackCollector`, `DOMClobberingCollector`, `OpenRedirectCollector`, `ClickjackingCollector`)
2. **Pipeline Connectivity**:
   - `argus/collectors/__init__.py`: Export all classes, models, and enums in `__all__`.
   - `argus/planning/task_generator.py`: DAG recon template, gap resolution, endpoint input wiring.
   - `argus/runtime/registry.py`: Canonical `Tool` registration + 15+ aliases.
   - `argus/runtime/plugins.py`: Specialist fallback in `PluginExecutorAdapter`.
   - `argus/scanning/engine.py`: Collector class mapping in `collector_class_map`.
   - `argus/graph/attack_surface.py`: Section 29 evidence ingestion and `HAS_VULNERABILITY` graph edges.
   - `argus/reporting/cvss.py`: CWE mappings for CWE-1321, CWE-79, CWE-601, CWE-1021 and CVSS calibration.
3. **Comprehensive Test Suite**:
   - `tests/collectors/test_prototype_pollution.py`: Core unit, prober, analyzer, false-positive rejection, and quadruple state publishing tests.
   - `tests/collectors/test_prototype_pollution_adversarial.py`: 5 mutation strategies, WAF rejection, deep traversal, rate limiting, and network fault tolerance tests.
   - `tests/collectors/test_prototype_pollution_pipeline.py`: TaskGenerator DAG, registry, graph Section 29, and CVSS calculator tests.

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| 1 | Active Collector & Prober (R1) | BaseCollector subclass using AuthenticatedHttpClient, candidate discovery, batch probing, and Quadruple State Publishing | M1 | ORIGINAL_REQUEST §R1 |
| 2 | Server-Side Prototype Pollution (R2.1) | Node.js/Express prototype pollution detection via JSON injection (`__proto__`, `constructor.prototype`) with observable side effects | M1 | ORIGINAL_REQUEST §R2.1 |
| 3 | Client-Side Prototype Pollution (R2.2) | DOM-based prototype pollution detection via URL fragment/query gadgets (`location.hash`, `URLSearchParams`) modifying Object.prototype | M1 | ORIGINAL_REQUEST §R2.2 |
| 4 | DOM Clobbering Detection (R2.3) | HTML injection where named elements shadow DOM APIs (`document.cookie`, `document.body`, `document.getElementById`) | M1 | ORIGINAL_REQUEST §R2.3 |
| 5 | Open Redirect Chain Detection (R2.4) | Unvalidated redirect parameters (`url=`, `next=`, `redirect=`, `return_to=`, `continue=`) with multi-hop chain tracing | M1 | ORIGINAL_REQUEST §R2.4 |
| 6 | Clickjacking / UI Redressing (R2.5) | Detection of missing `X-Frame-Options` and missing/permissive CSP `frame-ancestors` on sensitive endpoints | M1 | ORIGINAL_REQUEST §R2.5 |
| 7 | Prototype Pollution Gadget Analysis (R3) | Express, Lodash, jQuery, Handlebars gadgets, DoS via `toString`/`valueOf`, Node.js `child_process.exec` RCE, and traversal depth analysis | M1 | ORIGINAL_REQUEST §R3 |
| 8 | 5 Mutation & Evasion Strategies (R4) | JSON key encoding, Content-Type manipulation, Redirect URL encoding, DOM clobbering variants, Frame-busting bypass | M1 | ORIGINAL_REQUEST §R4 |
| 9 | Pipeline DAG & Registry Connectivity (R5) | TaskGenerator DAG, ToolRegistry registration, specialist plugin fallback, engine map | M2 | ORIGINAL_REQUEST §R5 |
| 10 | Attack Surface Graph & CVSS (R5) | Section 29 evidence ingestion with `HAS_VULNERABILITY` edges, CWE-1321, CWE-79, CWE-601, CWE-1021 mappings | M2 | ORIGINAL_REQUEST §R5 |
| 11 | Unit, Adversarial & Pipeline Tests (R6) | >=25 (targeting 50+) tests across 3 test files covering all modes, mutations, and pipeline wiring | M3 | ORIGINAL_REQUEST §R6 |
| 12 | Zero Regression & Victory Audit (R6) | 1,929+ baseline passing tests maintained with 0 regressions, forensic audit, and handoff report | M4 | ORIGINAL_REQUEST §R6 |

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| 1 | Core Collector & Multi-Vector Engine | `argus/collectors/prototype_pollution.py`, `argus/collectors/__init__.py` | none | PLANNED |
| 2 | Pipeline Connectivity & Graph Integration | `argus/planning/task_generator.py`, `argus/runtime/registry.py`, `argus/runtime/plugins.py`, `argus/scanning/engine.py`, `argus/graph/attack_surface.py`, `argus/reporting/cvss.py` | M1 | PLANNED |
| 3 | Test Suite Implementation (Core, Adversarial, Pipeline) | `tests/collectors/test_prototype_pollution.py`, `tests/collectors/test_prototype_pollution_adversarial.py`, `tests/collectors/test_prototype_pollution_pipeline.py` | M1, M2 | PLANNED |
| 4 | Review, Adversarial Challenge, Forensic Audit & Handoff | Full regression test suite run, reviewer & challenger verification, forensic auditor verification, final handoff | M3 | PLANNED |

## Interface Contracts
### `argus.collectors.prototype_pollution`
- `PrototypePollutionCollector(BaseCollector)`:
  - `collect(mission: Any) -> List[Evidence]`
  - `execute(mission: Any) -> List[Evidence]`
  - `_discover_candidate_endpoints(mission: Any) -> List[str]`
  - `_emit_evidence(mission: Any, result: PrototypePollutionResult, target_url: str, base_url: str) -> Evidence`
- `PrototypePollutionPayloadGenerator`:
  - `generate_all_probes(endpoint_url: str) -> List[PrototypePollutionProbe]`
  - `generate_server_side_pp_probes(endpoint_url: str) -> List[PrototypePollutionProbe]`
  - `generate_client_side_pp_probes(endpoint_url: str) -> List[PrototypePollutionProbe]`
  - `generate_dom_clobbering_probes(endpoint_url: str) -> List[PrototypePollutionProbe]`
  - `generate_open_redirect_probes(endpoint_url: str) -> List[PrototypePollutionProbe]`
  - `generate_clickjacking_probes(endpoint_url: str) -> List[PrototypePollutionProbe]`
  - `generate_gadget_chain_probes(endpoint_url: str) -> List[PrototypePollutionProbe]`
  - `apply_mutation(probe: PrototypePollutionProbe, strategy: PrototypePollutionMutationStrategy) -> PrototypePollutionProbe`
- `PrototypePollutionProber`:
  - `execute_probe(mission: Any, target_url: str, probe: PrototypePollutionProbe) -> PrototypePollutionProbeResponse`
  - `execute_redirect_chain_probe(mission: Any, target_url: str, probe: PrototypePollutionProbe, max_hops: int = 5) -> PrototypePollutionProbeResponse`
- `PrototypePollutionAnalyzer`:
  - `evaluate_probe(probe: PrototypePollutionProbe, response: PrototypePollutionProbeResponse, target_url: str) -> Optional[PrototypePollutionResult]`
  - `is_false_positive(probe: PrototypePollutionProbe, response: PrototypePollutionProbeResponse) -> bool`

## Code Layout
- `argus/collectors/prototype_pollution.py` (Owned by Worker)
- `argus/collectors/__init__.py` (Owned by Worker)
- `argus/planning/task_generator.py` (Owned by Worker)
- `argus/runtime/registry.py` (Owned by Worker)
- `argus/runtime/plugins.py` (Owned by Worker)
- `argus/scanning/engine.py` (Owned by Worker)
- `argus/graph/attack_surface.py` (Owned by Worker)
- `argus/reporting/cvss.py` (Owned by Worker)
- `tests/collectors/test_prototype_pollution.py` (Owned by Worker / Test Writer)
- `tests/collectors/test_prototype_pollution_adversarial.py` (Owned by Worker / Test Writer)
- `tests/collectors/test_prototype_pollution_pipeline.py` (Owned by Worker / Test Writer)
