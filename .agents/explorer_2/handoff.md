# Test Suite, Graph Architecture & Pipeline Integration Investigation Report
**Sprint 12: SSRF Validation Collector**
**Author**: `explorer_2` (Test & Pipeline Investigator / Spec Miner)
**Date**: 2026-08-30

---

## 1. Observation

### 1.1 Test Suite Status & Execution Baseline
- **Execution Command**: `python -m pytest tests/ --ignore=tests/workspace -x -q`
- **Result**: `1071 passed, 24122 warnings in 41.90s` (Exit code: `0`)
- **Suite Layout & Organization**:
  - `tests/collectors/`: Unit & adversarial tests for vulnerability collectors:
    - `test_access_control.py`, `test_challenger2_access_control_adversarial.py`
    - `test_information_disclosure.py`, `test_information_disclosure_adversarial.py`, `test_challenger2_adversarial_info_disclosure.py`
    - `test_path_traversal.py`, `test_path_traversal_adversarial.py`
    - `test_sql_injection.py`, `test_sql_injection_adversarial.py`
    - `test_xss.py`, `test_xss_adversarial.py`
    - `test_command_injection.py`, `test_command_injection_adversarial.py`
  - `tests/pipeline/`: Pipeline integration tests:
    - `test_cmdi_pipeline.py`, `test_cmdi_adversarial_challenge.py`
  - `tests/runtime/`: Runtime orchestrator & end-to-end integration tests:
    - `test_e2e_access_control.py`, `test_e2e_info_disclosure.py`, `test_e2e_mission.py`, `test_e2e_path_traversal.py`, `test_e2e_sql_injection.py`, `test_e2e_xss.py`, `test_e2e_xss_stress.py`, `test_runtime_orchestrator.py`, `test_scheduler.py`
  - `tests/graph/`: `test_attack_surface_builder.py`, `test_adversarial_graph_reasoning.py`, `test_graph_root.py`
  - `tests/http/`: `test_authenticated_http_client.py`, `test_authorized_http_client.py`, `test_sprint4_empirical_stress.py`
  - `tests/planning/`: `test_research_planner.py`
  - `tests/workspace/`: Contains standalone context/persistence tests (excluded by `--ignore=tests/workspace`).

### 1.2 Mocking Harnesses and Test Patterns
The codebase standardizes on dedicated class-based Mock HTTP clients implementing the `AuthenticatedHttpClient` / `HttpResponse` interface:
- **`HttpResponse` Model** (`argus/http/client.py:72-85`):
  ```python
  @dataclass
  class HttpResponse:
      success: bool
      status_code: Optional[int] = None
      headers: Dict[str, str] = field(default_factory=dict)
      request_headers: Dict[str, str] = field(default_factory=dict)
      body: Optional[str] = None
      raw_body: Optional[str] = None
      url: str = ""
      method: str = ""
      elapsed: float = 0.0
      error: Optional[str] = None
      scope_decision: Optional[ScopeDecision] = None
      authorization_decision: Optional[AuthDecision] = None
  ```
- **Mock Client Pattern** (as observed in `tests/collectors/test_command_injection.py`, `tests/collectors/test_sql_injection.py`, `tests/collectors/test_path_traversal.py`):
  - Injected via collector constructor: `collector = SSRFCollector(http_client=mock_client)`.
  - Supports route registration: `mock_client.set_route(url_or_key, status_code, body, elapsed=0.05)`.
  - Implements `.get(mission_or_url, url=None, **kwargs)` and `.post(mission_or_url, url=None, **kwargs)`.
  - Handles URL unquoting (`urllib.parse.unquote_plus`), header matching (`header:{name}:{value}`), parameter extraction, and differential timing (`elapsed >= 4.0`).

### 1.3 Knowledge Graph Models & Edge Relations
- **Core Models**:
  - `Node` (`argus/graph/node.py:5-18`): `id: str`, `type: str`, `value: str`, `metadata: dict[str, Any]`
  - `Edge` (`argus/graph/edge.py:5-18`): `source: str`, `target: str`, `type: str`, `metadata: dict[str, Any]`
  - `KnowledgeGraph` (`argus/graph/graph.py:6-95`): `nodes: dict[str, Node]`, `edges: list[Edge]`, methods: `add(node)`, `get(node_id)`, `connect(source, target, edge_type, metadata)`, `nodes_by_type(node_type)`, `node_count()`, `edge_count()`.
- **Attack Surface Graph Topology for Vulnerability Collectors**:
  - **Node ID Conventions**:
    - Live Host: `live_host:{base_url}` (e.g. `live_host:https://example.com`) with `type="live_host"`
    - Endpoint: `endpoint:{target_url}` (e.g. `endpoint:https://example.com/api/fetch?url=...`) with `type="endpoint"`
    - Vulnerability: `vulnerability:{template_id}:{target_url}:{param}` (or `vulnerability:{template_id}:{target_url}`) with `type="vulnerability"`
  - **Edge Topology (Triad)**:
    1. `graph.connect(lh_id, ep_id, edge_type="HAS_ENDPOINT")` (host -> endpoint)
    2. `graph.connect(lh_id, vuln_id, edge_type="HAS_VULNERABILITY")` (host -> vulnerability)
    3. `graph.connect(ep_id, vuln_id, edge_type="HAS_VULNERABILITY")` (endpoint -> vulnerability)
- **Collector State Updates**:
  When a vulnerability is confirmed during fuzzing:
  1. `Evidence` is instantiated:
     ```python
     ev = Evidence(
         mission_id=getattr(raw_mission, "id", ""),
         source_type="LOG",
         created_by="SYSTEM_GENERATED",
         title=f"SSRF: {param} on {target_url}",
         description=description,
         category="ssrf",  # or "server_side_request_forgery"
         value=target_url,
         source=target_url,
         status="CONFIRMED",
         confidence=confidence,  # 0.95 (or 0.90 for timing)
         severity=severity,      # "critical" for cloud metadata/internal admin, "high" for services
         provenance=ProvenanceData(step_id="ssrf_collector"),
         tags=["ssrf", "server_side_request_forgery", technique, template_id],
         metadata={
             "url": target_url,
             "host": base_url,
             "path": url_path,
             "parameter": param,
             "parameter_type": param_type,
             "payload": payload,
             "category": "ssrf",
             "severity": severity,
             "technique": technique,
             "template_id": template_id,
             "service": service_type,
             "status_code": status_code,
             "evidence_snippet": snippet[:250],
         },
     )
     ```
  2. Appended to `mission.evidence.add(ev)` (or `mission.evidence.append(ev)`).
  3. Appended to `mission.vulnerabilities.append({...})`.
  4. Expanded directly on `mission.attack_surface_graph` with `live_host`, `endpoint`, `vulnerability` nodes and `HAS_ENDPOINT`, `HAS_VULNERABILITY` edges.
  5. Safely published to `ControlledMission` wrapper via `mission.publish_finding(ev.id, ev)`.
- **`AttackSurfaceGraphBuilder` Reconstruction** (`argus/graph/attack_surface.py`):
  - Ingests `EvidenceStore` records by category.
  - Section 1-13 exist for: subdomains, live hosts, technologies, endpoints, generic vulnerabilities, subdomain takeover, information disclosure, broken access control, path traversal, SQL injection, XSS, and command injection.
  - **Section 14 required for SSRF**:
    ```python
    # 14. Server-Side Request Forgery (SSRF) Vulnerabilities
    for ev in evidence_items:
        if getattr(ev, "category", None) in ("ssrf", "server_side_request_forgery", "ssrf_vulnerability"):
            # build nodes & connect HAS_ENDPOINT and HAS_VULNERABILITY
    ```

### 1.4 TaskGenerator & DAG Scheduling
- **File**: `argus/planning/task_generator.py`
- **Recon Templates (`_RECON_TEMPLATES`)**:
  - `subfinder` -> `httpx` (depends on `Discover Subdomains`) -> `katana_crawler` (depends on `Fingerprint Live Hosts`) -> `nuclei` (depends on `Fingerprint Live Hosts`) -> `info_disclosure` (depends on `Fingerprint Live Hosts`).
  - Active fuzzing collectors (`access_control`, `path_traversal`, `sql_injection`, `xss`, `command_injection`) depend on `Discover API Endpoints` (`katana_crawler`).
  - **SSRF Template required**:
    ```python
    "ssrf": {
        "title": "Validate Server-Side Request Forgery (SSRF)",
        "goal": "Actively fuzz discovered endpoint parameters, POST bodies, and headers for SSRF vulnerabilities and cloud metadata disclosure using AuthenticatedHttpClient.",
        "category": TaskCategory.EVIDENCE_CORRELATION,
        "required_inputs": ["endpoints"],
        "expected_outputs": ["vulnerabilities", "observations", "evidence"],
        "dependencies": ["Discover API Endpoints"],
        "required_specialists": [],
        "metadata": {"tool_id": "ssrf"},
        "estimated_duration_minutes": 10,
        "priority": 0.81,
    }
    ```
- **Gap Resolution (`_resolve_template_for_gap`)**:
  - Maps string matching on `gap.area` and `gap.description` (e.g. `ssrf`, `server side request forgery`, `cloud metadata`, `metadata disclosure`, `imds`).
- **Gap Transformation (`from_gaps`)**:
  - Resolves inputs from `endpoints` when `tool_id == "ssrf"`.

### 1.5 ToolRegistry & Plugin Execution Pipeline
- **`ToolRegistry`** (`argus/runtime/registry.py:5-350`):
  - Registers `Tool` instances by `id`.
  - Tool definition required for `ssrf`:
    ```python
    registry.register(
        Tool(
            id="ssrf",
            name="SSRF Validation Collector",
            capability="ssrf_detector",
            description="Actively fuzzes endpoint parameters, POST bodies, and HTTP headers for server-side request forgery (SSRF) and cloud metadata access using AuthenticatedHttpClient.",
            supported_tasks=["SSRF Validation", "SSRF Detection", "Server-Side Request Forgery", "Vulnerability Scanning", "Evidence Correlation", "API Discovery"],
            required_inputs=["endpoints"],
            produced_outputs=["vulnerabilities", "observations", "evidence"],
            capabilities=["ssrf_detector", "ssrf_collector", "ssrf_validator"],
            safety_requirements={"type": "internal", "permissions": ["network", "db_read", "db_write"]},
            timeout=300.0,
            priority=95,
        )
    )
    ```
  - Alias lookup in `ToolRegistry.get()`: Add aliases `ssrf_validator`, `server_side_request_forgery`.
- **`PluginExecutorAdapter`** (`argus/runtime/plugins.py:65-110`):
  - In `_instantiate_specialist_fallback(self, plugin_id)`:
    ```python
    elif "ssrf" in plugin_id or "server_side_request_forgery" in plugin_id:
        from argus.collectors.ssrf import SSRFCollector
        return SSRFCollector()
    ```
- **`argus/collectors/__init__.py`**:
  - Export `SSRFCollector`, `SSRFAnalyzer`, `SSRFPayloadGenerator`, etc.

---

## 2. Logic Chain

1. **Vulnerability Detection Pattern Alignment**:
   - All 5 existing vulnerability collectors (`SQLInjectionCollector`, `XSSCollector`, `PathTraversalCollector`, `AccessControlCollector`, `CommandInjectionCollector`) adhere to the standard multi-class architecture:
     - `<Vuln>PayloadGenerator`: Generates payloads, bypass mutations, and targets.
     - `<Vuln>Analyzer`: Matches response signatures (cloud metadata, internal service banners, admin titles) and differential timing latencies.
     - `<Vuln>Collector(BaseCollector)`: Coordinates candidate extraction from `mission.endpoints` (GET query params, POST form/JSON body fields, headers `Referer` / `X-Forwarded-For`), executes requests via `AuthenticatedHttpClient`, emits `Evidence`, updates `mission.vulnerabilities`, and expands `mission.attack_surface_graph`.
     - Adapter methods: `.execute(mission)` calling `.collect(mission)`.
2. **SSRF Specifications from ORIGINAL_REQUEST.md**:
   - **R1 Injection Targets**: GET query strings, POST JSON & form fields, headers (`Referer`, `X-Forwarded-For`). Probing internal IPs (`127.0.0.1`, `localhost`, RFC 1918 `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) and Cloud metadata endpoints (`169.254.169.254` AWS IMDSv1/v2, GCP `metadata.google.internal`, Azure `169.254.169.254/metadata/instance`).
   - **R2 Detection Techniques**:
     1. Cloud Metadata Response Detection (AWS IAM role names, GCP instance IDs, Azure VM metadata JSON).
     2. Internal Service Response Detection (Redis `+PONG`, MySQL/Postgres handshake banners, internal admin HTML titles).
     3. Differential Timing (latency >= 4.0s vs baseline).
   - **R3 Bypass Mutations**: At least 6 distinct bypass strategies (decimal IP `2130706433`, hex IP `0x7f000001`, octal IP `0177.0.0.1`, shortened IP `127.1`, URL encoding/double encoding, URI schemes `dict://`, `gopher://`, `file://`, IPv6 `[::1]`, `[::ffff:127.0.0.1]`, DNS rebinding).
3. **Pipeline Invariance**:
   - `TaskGenerator` places SSRF task after endpoint crawling (`dependencies: ["Discover API Endpoints"]`).
   - `ToolRegistry` makes it discoverable by `tool_id="ssrf"`, `capability="ssrf_detector"`.
   - `AttackSurfaceGraphBuilder` section 14 guarantees graph isomorphism whether built live or reconstructed from `EvidenceStore`.
4. **Test Suite Invariance (Zero Regressions + >20 New Tests)**:
   - Full baseline currently stands at 1071 passing tests.
   - Comprehensive new tests should be created in:
     - `tests/collectors/test_ssrf.py` (Unit tests for collector, payload generator, analyzer, graph wiring, mutations)
     - `tests/collectors/test_ssrf_adversarial.py` (Adversarial stress: false positives, boundary latencies, non-metadata JSON, nested payloads)
     - `tests/pipeline/test_ssrf_pipeline.py` or `tests/runtime/test_e2e_ssrf.py` (E2E mission lifecycle, ToolRegistry, PluginExecutorAdapter fallback, AttackSurfaceGraphBuilder reconstruction).

---

## 3. Discovered Features & Edge Cases

### Features Discovered

| # | Category | Feature | Description | Inputs | Outputs | Error Behavior | Discovered Via |
|---|----------|---------|-------------|--------|---------|----------------|----------------|
| 1 | Collector | `SSRFCollector` | Defensive validation module to detect SSRF misconfigurations across endpoints | `mission: Mission` | `List[Evidence]` | Handles network errors/timeouts gracefully; logs and skips invalid endpoints | `argus/collectors/command_injection.py`, `sql_injection.py` |
| 2 | Payloads | `SSRFPayloadGenerator` | Generates cloud metadata, internal service, and loopback probe payloads with bypass mutations | Target URLs, parameter names, bypass schemes | `List[str]`, `List[Tuple[str, str, Dict]]` | Returns default payload list if no custom options provided | `argus/collectors/path_traversal.py`, `xss.py` |
| 3 | Analyzer | `SSRFAnalyzer` | Analyzes responses for cloud metadata, internal banners, HTML titles, and differential timing | `HttpResponse`, baseline elapsed time, technique config | `Optional[Dict[str, Any]]` analysis result | Returns None if no matching signature or threshold not met | `argus/collectors/command_injection.py` |
| 4 | Graph Models | `KnowledgeGraph` Node/Edge Creation | Creates `live_host`, `endpoint`, `vulnerability` nodes with `HAS_ENDPOINT` and `HAS_VULNERABILITY` edges | Node IDs, types, metadata | Boolean success (prevents duplicate edges) | Returns False if node missing or edge already exists | `argus/graph/graph.py`, `argus/collectors/sql_injection.py` |
| 5 | Graph Builder | `AttackSurfaceGraphBuilder` Sec 14 | Ingests `ssrf` evidence from `EvidenceStore` and reconstructs graph topology | `EvidenceStore`, `target` | Populated `KnowledgeGraph` | Tolerates missing metadata or partial URLs | `argus/graph/attack_surface.py:520-577` |
| 6 | Planning | `TaskGenerator` SSRF Task | Generates `ResearchTask` for SSRF validation dependent on `Discover API Endpoints` | `Mission`, `CoverageGap` | `ResearchTask` | Fallback to default inputs if endpoints empty | `argus/planning/task_generator.py:12-134` |
| 7 | Runtime | `ToolRegistry` SSRF Registration | Registers `ssrf` tool with capabilities and aliases in global registry | Tool ID, name, capabilities | `Tool` object | Resolves by primary ID, alias, or capability name | `argus/runtime/registry.py:5-50` |
| 8 | Runtime | `PluginExecutorAdapter` Fallback | Instantiates `SSRFCollector` for internal plugin execution | `plugin_id` | Instantiated `SSRFCollector` | Logs error and returns None if unknown | `argus/runtime/plugins.py:65-110` |

### Edge Cases

| # | Feature | Input | Observed Behavior |
|---|---------|-------|-------------------|
| 1 | Differential Timing | Response latency 3.9s (threshold >= 4.0s) | Must NOT trigger timing-based SSRF confirmation; must meet exact `>= 4.0s` differential. |
| 2 | High Baseline Latency | Server has 5.0s baseline latency, probe takes 5.5s (delta = 0.5s) | Must calculate delta `elapsed - baseline`; delta < 4.0s must NOT flag vulnerability. |
| 3 | False Positive Metadata | HTML or JSON containing string "aws" or "gcp" without matching IAM/token/project signatures | Analyzer must use strict regex matching for IAM role credentials, GCP instance ID/attributes, Azure VM compute JSON. |
| 4 | Non-URL Parameters | Parameter named `search` or `q` without URL structure | Collector must test both generic parameters and high-probability URL/webhook/dest/uri parameters. |
| 5 | Header Injection | `Referer` and `X-Forwarded-For` injection points | Collector must inject into HTTP headers and test server response / out-of-band behavior. |
| 6 | ControlledMission Wrapper | `ControlledMission(mission)` wrapper during plugin execution | Collector must unwrap `_mission = getattr(mission, "_mission", mission)` and call `mission.publish_finding(ev.id, ev)`. |

---

## 4. Caveats

1. **Read-Only Scope**: This investigation did not modify any source code or test files in the project.
2. **Deprecation Warnings**: Running pytest outputs deprecation warnings regarding `datetime.utcnow()`. These are legacy warnings across older modules and do not impact test suite execution or pass rates.
3. **Workspace Directory**: The directory `tests/workspace/` is intentionally excluded from the primary test run via `--ignore=tests/workspace` as designed by the project test runner.

---

## 5. Conclusion

The ARGUS codebase has a highly consistent, decoupled, and extensible architecture for vulnerability collectors:
- **Implementation Targets**:
  - `argus/collectors/ssrf.py` (New): `SSRFCollector`, `SSRFPayloadGenerator`, `SSRFAnalyzer`, `SSRFResult`, `SSRFTechnique`.
  - `argus/collectors/__init__.py` (Modify): Export SSRF classes and update `__all__`.
  - `argus/graph/attack_surface.py` (Modify): Add Section 14 for `category in ("ssrf", "server_side_request_forgery")` in `AttackSurfaceGraphBuilder`.
  - `argus/planning/task_generator.py` (Modify): Add `"ssrf"` to `_RECON_TEMPLATES`, update `_resolve_template_for_gap` and `from_gaps`.
  - `argus/runtime/registry.py` (Modify): Register `Tool(id="ssrf", ...)` and add aliases in `ToolRegistry.get()`.
  - `argus/runtime/plugins.py` (Modify): Add `ssrf` handler in `PluginExecutorAdapter._instantiate_specialist_fallback`.
- **Test Targets**:
  - `tests/collectors/test_ssrf.py` (New unit tests)
  - `tests/collectors/test_ssrf_adversarial.py` (New adversarial & boundary tests)
  - `tests/runtime/test_e2e_ssrf.py` (New E2E mission lifecycle & graph reconstruction tests)

All 1071 current tests are confirmed passing. The implementation of Sprint 12 will seamlessly fit into existing graph, planning, and execution contracts with zero regressions.

---

## 6. Verification Method

To verify these findings independently:
1. **Run full pytest suite**:
   ```bash
   python -m pytest tests/ --ignore=tests/workspace -x -q
   ```
   *Expected*: 1071 passed, 0 failures.
2. **Inspect existing collector graph & DAG integration**:
   ```bash
   grep -n "HAS_VULNERABILITY" argus/collectors/command_injection.py
   grep -n "HAS_VULNERABILITY" argus/graph/attack_surface.py
   grep -n "command_injection" argus/planning/task_generator.py
   grep -n "command_injection" argus/runtime/registry.py
   grep -n "command_injection" argus/runtime/plugins.py
   ```
