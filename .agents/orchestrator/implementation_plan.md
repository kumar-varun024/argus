# Implementation Plan: Prototype Pollution & Client-Side Attack Detection Module (Sprint 29)

## 1. Overview & Objective
Build and integrate the Prototype Pollution & Client-Side Attack Detection Module (`PrototypePollutionCollector`) for the ARGUS platform. The module actively probes discovered endpoints for server-side & client-side prototype pollution, DOM clobbering, open redirect chains, and clickjacking vulnerabilities, complete with gadget analysis, 5 mutation/evasion strategies, full pipeline connectivity, quadruple state publishing, and zero regressions across the 1,929+ baseline test suite.

## 2. Architectural Blueprint & Component Design

### 2.1 Core Collector Module (`argus/collectors/prototype_pollution.py`)
- **Tripartite Pattern Structure**:
  1. **Enums & Dataclasses**:
     - `PrototypePollutionSeverity`: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`, `CRIT` alias.
     - `PrototypePollutionVulnerabilityType`: `SERVER_SIDE_PROTOTYPE_POLLUTION`, `CLIENT_SIDE_PROTOTYPE_POLLUTION`, `DOM_CLOBBERING`, `OPEN_REDIRECT`, `CLICKJACKING`, `GADGET_POLLUTION`, `DOS_POLLUTION`, `RCE_GADGET`.
     - `PrototypePollutionMutationStrategy`: `JSON_KEY_ENCODING`, `CONTENT_TYPE_MANIPULATION`, `REDIRECT_URL_ENCODING`, `DOM_CLOBBERING_VARIANTS`, `FRAME_BUSTING_BYPASS`, `STANDARD`.
     - `GadgetFramework`: `EXPRESS`, `LODASH`, `JQUERY`, `HANDLEBARS`, `NODEJS_CHILD_PROCESS`, `GENERIC`.
     - `PrototypePollutionProbe`, `PrototypePollutionProbeResponse`, `PrototypePollutionResult`.
  2. **`PrototypePollutionPayloadGenerator`**:
     - Server-side JSON injection: `__proto__`, `constructor.prototype`, property pollution canaries.
     - Client-side DOM pollution: URL query & hash parameters (`location.hash`, `URLSearchParams`).
     - DOM clobbering payloads: `<form id="cookie">`, `<a id="x" name="cookie">`, `<object id="body">`, `<embed id="...">`, nested form elements.
     - Open redirect payloads: `url=`, `next=`, `redirect=`, `return_to=`, `continue=`, external domains, scheme-relative `//evil.com`, `@` authority prefix.
     - Clickjacking inspection requests: sensitive endpoints (login, settings, payment, account).
     - Gadget payloads: Express (`settings.views`, `view options`), Lodash (`templateSettings.interpolate`), jQuery (`htmlPrefilter`), Handlebars (`compiler`), Node.js `child_process.exec` options (`shell`, `NODE_OPTIONS`), DoS via `toString`/`valueOf`, nested traversal depth testing.
     - Mutation / evasion methods: JSON key encoding (`\u005f\u005fproto\u005f\u005f`, `constructor["prototype"]`), Content-Type switching (`application/json`, `application/x-www-form-urlencoded`, `multipart/form-data`), redirect URL encoding (double encoding, Unicode fullwidth, backslash), DOM clobbering variants, frame-busting bypass (sandbox framing, double framing, data: URI framing).
  3. **`PrototypePollutionProber`**:
     - Polymorphic HTTP execution via `AuthenticatedHttpClient` or test mock clients.
     - Support for redirect tracing (`max_hops=5`) to detect multi-hop open redirect chains.
     - Robust error handling, timeout recovery, and response normalization into `PrototypePollutionProbeResponse`.
  4. **`PrototypePollutionAnalyzer`**:
     - Evaluates responses against probe expectations and baseline requests.
     - Strict False Positive Rejection:
       - Prototype pollution: Endpoints that sanitize/strip `__proto__` without side effects or return standard 400 validation errors do NOT trigger findings.
       - DOM Clobbering: Validates shadow DOM APIs without HTML entity escaping neutralization. Calibrates XSS clobbering = High, logic corruption = Medium.
       - Open Redirect: Validates redirection reaches untrusted external domains; suppresses same-origin and allowlisted domains. Traces multi-hop chains (Medium severity).
       - Clickjacking: Missing `X-Frame-Options` AND missing/permissive CSP `frame-ancestors` on sensitive pages. Suppresses when properly protected.
  5. **`PrototypePollutionCollector`**:
     - Inherits from `BaseCollector`.
     - Multi-tier candidate endpoint discovery.
     - Dual entry points: `collect(mission) -> List[Evidence]` and `execute(mission) -> List[Evidence]`.
     - **Quadruple State Publishing**:
       1. `raw_mission.evidence` (EvidenceStore)
       2. `raw_mission.vulnerabilities` (List of vulnerability dictionaries)
       3. `attack_surface_graph` KnowledgeGraph (`live_host`, `endpoint`, `vulnerability` nodes + `HAS_ENDPOINT`, `HAS_VULNERABILITY` edges)
       4. `ControlledMission.publish_finding`
     - Backwards compatibility aliases: `ClientSideAttackCollector`, `DOMClobberingCollector`, `OpenRedirectCollector`, `ClickjackingCollector`.

### 2.2 Pipeline Connectivity (`argus/planning/`, `argus/runtime/`, `argus/graph/`, `argus/reporting/`)
- `argus/collectors/__init__.py`: Export collector, payload generator, prober, analyzer, results, enums, dataclasses, and backwards compatibility aliases in `__all__`.
- `argus/planning/task_generator.py`: Add `_RECON_TEMPLATES["prototype_pollution"]` dependent on `"Discover API Endpoints"`, update `_resolve_template_for_gap` area matches and category fallbacks, update `from_gaps` tool ID list.
- `argus/runtime/registry.py`: Register `Tool(id="prototype_pollution", ...)` with full capabilities, priority 95, and 15+ aliases (`proto_pollution`, `dom_clobbering`, `open_redirect`, `open_redirect_chain`, `clickjacking_detector`, `client_side_attacks`, etc.).
- `argus/runtime/plugins.py`: Update `PluginExecutorAdapter._instantiate_specialist_fallback` to map `prototype_pollution` and aliases to `PrototypePollutionCollector()`.
- `argus/scanning/engine.py`: Update `collector_class_map` to map `prototype_pollution` and aliases to `"PrototypePollutionCollector"`.
- `argus/graph/attack_surface.py`: Add Section 29 to `AttackSurfaceGraphBuilder.build_from_evidence()` to parse `prototype_pollution`, `client_side`, `dom_clobbering`, `open_redirect`, `clickjacking` evidence and wire `live_host`, `endpoint`, `vulnerability` nodes with `HAS_ENDPOINT` and `HAS_VULNERABILITY` edges.
- `argus/reporting/cvss.py`: Add CWE entries for `CWE-1321` (Prototype Pollution), `CWE-79` (DOM Clobbering), `CWE-601` (Open Redirect), `CWE-1021` (Clickjacking), and calibrate CVSS score presets (Critical 9.8 for RCE gadgets, High 8.1/8.2 for pollution & DOM XSS, Medium 5.3/6.1 for logic clobbering, open redirect, and clickjacking).

### 2.3 Comprehensive Testing Matrix
- `tests/collectors/test_prototype_pollution.py`: 25+ unit & component tests covering all 5 vectors, gadget analysis, prober, analyzer, false-positive rejection, and quadruple state publishing.
- `tests/collectors/test_prototype_pollution_adversarial.py`: 15+ tests covering the 5 mutation/evasion strategies, WAF rejection, deep traversal, rate limiting, and network fault tolerance.
- `tests/collectors/test_prototype_pollution_pipeline.py`: 15+ tests covering TaskGenerator DAG, registry, graph Section 29, and CVSS calculator.

## 3. Milestones & Execution Plan

| Milestone | Scope | Deliverables | Verification |
|---|---|---|---|
| **M1: Core Collector Module** | `argus/collectors/prototype_pollution.py`, `argus/collectors/__init__.py` | Full implementation of Tripartite pattern, data models, 5 vectors, gadget analysis, 5 mutation strategies, Prober, Analyzer, Collector with Quadruple State Publishing | Import checks & component unit tests |
| **M2: Pipeline Connectivity** | `argus/planning/task_generator.py`, `argus/runtime/registry.py`, `argus/runtime/plugins.py`, `argus/scanning/engine.py`, `argus/graph/attack_surface.py`, `argus/reporting/cvss.py` | Full integration into DAG, tool registry, engine map, graph Section 29, and CVSS CWE mappings | Pipeline integration test suite |
| **M3: Test Suite Implementation** | `tests/collectors/test_prototype_pollution.py`, `tests/collectors/test_prototype_pollution_adversarial.py`, `tests/collectors/test_prototype_pollution_pipeline.py` | 50+ new comprehensive test cases (unit, adversarial, pipeline) | Targeted test suite execution |
| **M4: Zero Regression & Victory Audit** | Entire codebase & full test suite | 1,929+ baseline tests passing + 50+ new tests (0 regressions), Reviewer & Challenger verification, Forensic Audit, and Handoff Report | Full pytest suite run (`python -m pytest tests/ --ignore=tests/workspace -x -q`) |
