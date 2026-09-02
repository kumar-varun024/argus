# Pipeline & Integration Survey Report: Authentication Bypass & Credential Attack Detection Module

**Author**: Pipeline & Integration Explorer  
**Sprint**: Authentication Bypass & Credential Attack Detection Module  
**Date**: 2026-09-02  
**Artifact**: `/home/varun/argus/.agents/explorer_survey_pipeline/handoff.md`

---

## 1. Observation

### 1.1 TaskGenerator & DAG Scheduling Architecture
- **Location**: `/home/varun/argus/argus/planning/task_generator.py`
  - **Recon & Tool Templates (`_RECON_TEMPLATES`)** (lines 12–302):
    - Stores structured task metadata keyed by canonical tool ID (`subfinder`, `httpx`, `katana_crawler`, `nuclei`, `info_disclosure`, `access_control`, `path_traversal`, `sql_injection`, `xss`, `command_injection`, `ssrf`, `oauth`, `xml_parser_validation`, `deserialization`, `graphql_security`, `websocket_security`, `request_smuggling`, `race_conditions`, `business_logic`, `ssti`, `cache_security`, `cors_security`, `file_upload`, `api_security`).
    - Standard keys per template: `title`, `goal`, `category` (from `TaskCategory`), `required_inputs`, `expected_outputs`, `dependencies`, `required_specialists`, `metadata: {"tool_id": ...}`, `estimated_duration_minutes`, `priority`.
  - **Gap Resolution Engine (`_resolve_template_for_gap`)** (lines 520–865):
    - Maps `CoverageGap.area` and `CoverageGap.description` to the appropriate tool or specialist template.
    - Uses lower-cased area matching (e.g., `"access control"`, `"oauth"`, `"websocket"`, `"file upload"`, `"api security"`), keyword searches in `gap.description`, and fallback to `gap.category` (`TaskCategory.TECHNOLOGY_DISCOVERY`, `TaskCategory.API_DISCOVERY`, `TaskCategory.AUTHENTICATION_ANALYSIS`, `TaskCategory.AUTHORIZATION_ANALYSIS`, `TaskCategory.EVIDENCE_CORRELATION`, `TaskCategory.COVERAGE_IMPROVEMENT`).
  - **Task Generation (`from_gaps`)** (lines 866–924):
    - Converts `List[CoverageGap]` into deduplicated `List[ResearchTask]`.
    - Automatically maps `required_inputs` by inspecting `gap.related_assets`, `mission.endpoints`, `mission.live_hosts`, or root `mission.target`.
- **Location**: `/home/varun/argus/argus/planning/gap_analysis.py`
  - **Gap Detection Engine (`GapAnalyzer`)** (lines 31–450):
    - Continuously inspects mission state via `analyze()` running 9 modular checks:
      1. `_check_recon_gaps()` (lines 51–177): checks subdomains, live hosts, uncrawled hosts (`graph.get_hosts_without_endpoints()`), unscanned hosts (`graph.get_hosts_without_vulnerabilities()`), info disclosure probing.
      2. `_check_technology_gaps()` (lines 315–325)
      3. `_check_api_gaps()` (lines 327–344)
      4. `_check_graphql_gaps()` (lines 346–359)
      5. `_check_authentication_gaps()` (lines 361–383): verifies if authentication state exists but has no analyzed workflows.
      6. `_check_authorization_gaps()` (lines 385–400)
      7. `_check_business_logic_gaps()` (lines 402–415)
      8. `_check_javascript_gaps()` (lines 417–432)
      9. `_check_correlation_gaps()` (lines 434–450)
- **Location**: `/home/varun/argus/argus/scanning/dag.py`
  - **ScanDAG** (lines 40–191):
    - Loads task templates from `task_generator._RECON_TEMPLATES` and classifies into `phase="recon"` (for `subfinder`, `httpx`, `katana_crawler`, `nuclei`, `info_disclosure`) or `phase="vulnerability"` (for active fuzzing/validation collectors).
    - `get_execution_order()` (lines 120–190): Computes deterministic topological order using Kahn's algorithm with stable tie-breaking: `(phase_score, -priority, registration_index)`.
- **Location**: `/home/varun/argus/argus/scanning/engine.py`
  - **ScanEngine** (lines 25–486):
    - Orchestrates end-to-end execution across state machine transitions (`CREATED` -> `READY` -> `RUNNING` -> `COLLECTING_EVIDENCE`).
    - `resolve_collector(task)` (lines 53–136): Resolves collectors dynamically via `collector_factory`, `PluginExecutorAdapter._instantiate_specialist_fallback`, `collector_class_map` (importing from `argus.collectors`), or `PluginManager`.
    - Isolates collector execution, collects telemetry, updates `EvidenceStore` and `AttackSurfaceGraph`, and generates reports.

### 1.2 Plugin & Tool Registry Mechanisms
- **Location**: `/home/varun/argus/argus/runtime/registry.py`
  - **`ToolRegistry` & singleton `registry`** (lines 5–985):
    - Stores `Tool` records with fields: `id`, `name`, `capability`, `description`, `supported_tasks`, `required_inputs`, `produced_outputs`, `capabilities`, `safety_requirements`, `timeout`, `priority`.
    - Implements alias lookup via `get(key)` resolving aliases (e.g., `"auth_bypass"`, `"jwt"`, `"oauth"`, `"session_fixation"`, `"deserialization"`).
- **Location**: `/home/varun/argus/argus/plugins/registry.py`
  - **`PluginRegistry`** (lines 6–66):
    - Manages plugin registrations with manifest permission checking (`network`, `filesystem`, `db_read`, `db_write`) and topological dependency resolution (`resolve_load_order`).
- **Location**: `/home/varun/argus/argus/runtime/plugins.py`
  - **`PluginExecutorAdapter`** (lines 10–249):
    - Wraps missions in `ControlledMission` and invokes `execute()` or `discover()/analyze()`.
    - `_instantiate_specialist_fallback(plugin_id)` (lines 65–246): Instantiates internal collector classes if not loaded from external plugin directories.
- **Location**: `/home/varun/argus/argus/collectors/base.py`
  - **`BaseCollector`** (lines 4–10): Abstract base class requiring `collect(self, mission)` (and conventionally `execute(self, mission)`).

### 1.3 Attack Surface Graph & Model Architecture
- **Location**: `/home/varun/argus/argus/graph/node.py` and `argus/graph/edge.py`
  - `Node(id: str, type: str, value: str, metadata: dict[str, Any])`
  - `Edge(source: str, target: str, type: str, metadata: dict[str, Any])`
- **Location**: `/home/varun/argus/argus/graph/graph.py`
  - `KnowledgeGraph`: Thread-safe in-memory graph with `add(node)`, `connect(source, target, edge_type, metadata)`, `get(node_id)`, `nodes_by_type(type)`, `edges_from(node)`, `edges_to(node)`, `neighbors(node)`.
- **Location**: `/home/varun/argus/argus/graph/attack_surface.py`
  - **`AttackSurfaceGraphBuilder`** (lines 11–1380):
    - Node Types: `target`, `subdomain`, `live_host`, `technology`, `endpoint`, `vulnerability`, `cname`, `service`, `secret`.
    - Edge Types:
      - `target` -> `subdomain` via `RESOLVES_TO`
      - `subdomain` -> `live_host` via `HOSTS`
      - `live_host` -> `technology` via `RUNS_TECHNOLOGY`
      - `live_host` -> `endpoint` via `HAS_ENDPOINT`
      - `live_host` -> `vulnerability` via `HAS_VULNERABILITY`
      - `endpoint` -> `vulnerability` via `HAS_VULNERABILITY`
      - `subdomain` -> `vulnerability` via `HAS_VULNERABILITY`
      - `subdomain` -> `cname` via `POINTS_TO_CNAME`
      - `vulnerability` -> `secret` via `EXPOSES_SECRET`
      - `vulnerability` -> `subdomain` via `DISCLOSED_SUBDOMAIN`
  - **Quadruple State Publishing Convention** (exemplified in `argus/collectors/file_upload.py:1328-1375`):
    1. `raw_mission.evidence.add(ev)` (or `.append(ev)`)
    2. `raw_mission.vulnerabilities.append({...})`
    3. `attack_surface_graph.connect(lh_id, ep_id, "HAS_ENDPOINT")`, `attack_surface_graph.connect(lh_id, vuln_id, "HAS_VULNERABILITY")`, `attack_surface_graph.connect(ep_id, vuln_id, "HAS_VULNERABILITY")`
    4. `ControlledMission.publish_finding(ev.evidence_id, ev)`

### 1.4 CVSS & CWE Mappings
- **Location**: `/home/varun/argus/argus/reporting/cvss.py`
  - **`CVSSCalculator`** (lines 21–543):
    - Strict FIRST CVSS v3.1 calculation with floating-point precision correction via `cvss_roundup()`.
    - Computes Base Score from vector string or metric dict (handling Scope Changed vs Scope Unchanged).
    - `CWE_DATABASE` (lines 33–264): Dictionary mapping normalized finding names/tags to `CWEInfo(id, name)`.
    - Current relevant mappings:
      - `"authentication"` / `"auth_bypass"` / `"broken_authentication"` -> `CWE-287 ("Improper Authentication")`
      - `"session_fixation"` -> `CWE-384 ("Session Fixation")`
      - `"jwt"` -> `CWE-345 ("Insufficient Verification of Data Authenticity")`
      - `"broken_access_control"` -> `CWE-284 ("Improper Access Control")`
      - `"idor"` / `"bola"` -> `CWE-639 ("Authorization Bypass Through User-Controlled Key")`
      - `"rate_limiting"` -> `CWE-770 ("Allocation of Resources Without Limits or Throttling")`
    - Mappings requiring expansion for Authentication Sprint:
      - `CWE-307`: `Improper Restriction of Excessive Authentication Attempts` (for brute force, password spraying, credential stuffing)
      - `CWE-640`: `Weak Password Recovery Mechanism for Forgotten Password` (for password reset abuse, predictable tokens, host header injection)
      - `CWE-288`: `Authentication Bypass Using an Alternate Path or Channel` (for MFA bypass, direct endpoint access)
      - `CWE-1390`: `Weak Authentication Token` (for JWT manipulation, alg:none, key confusion)
      - `CWE-798`: `Use of Hard-coded Credentials` (for default credentials on admin interfaces)
      - `CWE-522`: `Insufficiently Protected Credentials` (for auth state leakage in errors)
      - `CWE-613`: `Insufficient Session Expiration` (for session token expiration / rotation)
      - `CWE-1275`: `Sensitive Cookie with Improper SameSite Attribute` (for cookie flag audits)

### 1.5 Existing Test Suite Baseline & Environment
- **Test Command**: `./venv/bin/pytest --import-mode=importlib -q`
- **Execution Result**: **1,953 passed, 1 skipped in 62.99s**
- **Test Infrastructure**:
  - Requires `--import-mode=importlib` to avoid module name shadowing between top-level `tests/` and nested plugin test packages.
  - Standard test structure: `tests/<module>/test_<feature>.py` and `tests/<module>/test_<feature>_adversarial.py`.
  - Mocks: `unittest.mock.Mock`, `unittest.mock.MagicMock`, `unittest.mock.patch`, custom simulated HTTP clients returning `HttpResponse` instances.

---

## 2. Logic Chain

```
                   +-----------------------------------------------+
                   |              Reconnaissance Phase             |
                   |   (Subfinder -> Httpx -> Katana / Nuclei)     |
                   +-----------------------------------------------+
                                          |
                                          v
               +------------------------------------------------------+
               |                GapAnalyzer Inspection                |
               |  - Detects endpoints with login/auth paths           |
               |  - Identifies missing authentication security scans  |
               +------------------------------------------------------+
                                          |
                                          v
               +------------------------------------------------------+
               |                 TaskGenerator Routing                |
               |  - Maps auth gap to auth_bypass / credential_attack  |
               |  - Generates ResearchTask(tool_id="auth_bypass")     |
               +------------------------------------------------------+
                                          |
                                          v
               +------------------------------------------------------+
               |                     ScanDAG Sort                     |
               |  - Orders: Discover API Endpoints -> Auth Bypass     |
               |  - Phase: "vulnerability", Priority: 0.81            |
               +------------------------------------------------------+
                                          |
                                          v
               +------------------------------------------------------+
               |                  ScanEngine Execution                |
               |  - Resolves AuthenticationBypassCollector            |
               |  - Executes Tripartite Probe Pipeline:               |
               |    * AuthPayloadGenerator (Modes 1-6 + Evasions)     |
               |    * AuthenticatedHttpClient Prober                  |
               |    * AuthAnalyzer (Strict FP Rejection)              |
               +------------------------------------------------------+
                                          |
                                          v
               +------------------------------------------------------+
               |              Quadruple State Publishing              |
               |  1. raw_mission.evidence.add(ev)                     |
               |  2. raw_mission.vulnerabilities.append(vuln_dict)    |
               |  3. KnowledgeGraph (Node + HAS_VULNERABILITY)        |
               |  4. ControlledMission.publish_finding(id, ev)        |
               +------------------------------------------------------+
                                          |
                                          v
               +------------------------------------------------------+
               |               CVSS & Report Generation               |
               |  - CVSSCalculator maps CWE-287, 307, 384, 640, etc.  |
               |  - Base score calculated & report synthesized        |
               +------------------------------------------------------+
```

1. **Step 1: Gap Detection**: When Katana crawls endpoints containing authentication interfaces (e.g., `/login`, `/auth`, `/oauth/token`, `/reset-password`, `/admin`, `/mfa`), `GapAnalyzer` detects an active assessment gap for authentication mechanisms.
2. **Step 2: Task Generation**: `TaskGenerator._resolve_template_for_gap` maps the gap to `_RECON_TEMPLATES["auth_bypass"]` (or `"credential_attack"`), creating a `ResearchTask` with `dependencies=["Discover API Endpoints"]` and `metadata={"tool_id": "auth_bypass"}`.
3. **Step 3: DAG Ordering**: `ScanDAG` builds a dependency graph where `Discover API Endpoints` must complete before `auth_bypass` executes, ordering tasks topologically via Kahn's algorithm.
4. **Step 4: Tool Resolution & Execution**: `ScanEngine.resolve_collector` resolves `tool_id="auth_bypass"` via `collector_class_map` / `PluginExecutorAdapter` to instantiate `AuthenticationBypassCollector` (subclass of `BaseCollector`).
5. **Step 5: Tripartite Probing**:
   - `AuthPayloadGenerator` synthesizes probes across 6 multi-vector modes and 5 evasion strategies.
   - Prober issues HTTP requests via `AuthenticatedHttpClient`.
   - `AuthAnalyzer` applies strict false positive rejection (suppressing legitimate 401/403/429 rejections and rate limits) and emits validated findings.
6. **Step 6: Graph & State Integration**: `_emit_evidence()` updates the 4 sinks: Evidence store, Vulnerabilities list, KnowledgeGraph nodes/edges (`HAS_ENDPOINT`, `HAS_VULNERABILITY`), and `ControlledMission.publish_finding`.
7. **Step 7: CVSS & Reporting**: `CVSSCalculator` resolves CWE details and CVSS v3.1 scores for reporting.

---

## 3. Caveats

1. **Test Execution Import Mode**: Pytest must be invoked with `--import-mode=importlib` (e.g. `./venv/bin/pytest --import-mode=importlib`) due to identically named test files in legacy plugin folders (e.g. `test_file_upload.py`, `test_graphql.py`, `test_business_logic.py`).
2. **CWE Database Precision**: `CVSSCalculator.CWE_DATABASE` already has entries for `authentication` (CWE-287) and `session_fixation` (CWE-384), but explicitly requires additions for CWE-307, CWE-640, CWE-288, CWE-1390, CWE-798, CWE-522, and CWE-613 to support all 6 attack vectors without falling back to generic CWE-699.
3. **Graph Builder Dynamic Resolution**: `AttackSurfaceGraphBuilder.build_from_evidence()` should include explicit evidence category matching for `authentication`, `auth_bypass`, `credential_attack`, `brute_force`, `password_reset`, `mfa_bypass`, `session_fixation`, `jwt_manipulation`, `default_credentials` so that graphs reconstructed from serialized evidence stores contain identical node IDs and `HAS_VULNERABILITY` edges.
4. **Tool Registry Aliases**: `ToolRegistry` and `PluginExecutorAdapter` must register comprehensive alias variants (`auth_bypass`, `authentication_bypass`, `credential_attack`, `brute_force`, `jwt_manipulation`, `password_reset`, `mfa_bypass`, `session_fixation`, `default_credentials`) to ensure smooth resolution regardless of how tasks or callers invoke the capability.

---

## 4. Conclusion

The ARGUS pipeline architecture is highly modular and strictly structured. Implementing the **Authentication Bypass & Credential Attack Detection Module** requires integrating across 5 exact touchpoints:

| Component | Target File | Specific Integration Required |
|---|---|---|
| **1. Collector Module** | `argus/collectors/authentication.py` or `argus/collectors/auth_bypass.py` | Implement `AuthenticationBypassCollector`, `AuthPayloadGenerator`, `AuthAnalyzer`, `AuthProber` following Tripartite Pattern and Quadruple State Publishing. Expose in `argus/collectors/__init__.py`. |
| **2. Task Generator & DAG** | `argus/planning/task_generator.py` | Add `"auth_bypass"` template to `_RECON_TEMPLATES`, add matching rules in `_resolve_template_for_gap`, add required inputs mapping in `from_gaps`. |
| **3. ScanDAG & Engine** | `argus/scanning/dag.py` & `argus/scanning/engine.py` | Ensure `"auth_bypass"` is in `collector_class_map` in `ScanEngine.resolve_collector`. |
| **4. Tool & Plugin Registry** | `argus/runtime/registry.py` & `argus/runtime/plugins.py` | Register `Tool(id="auth_bypass", ...)` with capability flags and aliases in `registry`; add fallback in `_instantiate_specialist_fallback()`. |
| **5. Graph & CVSS/CWE** | `argus/graph/attack_surface.py` & `argus/reporting/cvss.py` | Add auth category ingestion in `AttackSurfaceGraphBuilder.build_from_evidence`; add CWE-307, CWE-640, CWE-288, CWE-1390, CWE-798, CWE-522, CWE-613 in `CVSSCalculator.CWE_DATABASE` and `_get_preset_vector`. |

The existing test suite is healthy with **1,953 passing tests**, providing an established baseline for zero-regression validation.

---

## 5. Verification Method

### 5.1 Pytest Test Suite Execution
To verify the existing test suite baseline and ensure zero regressions:
```bash
cd /home/varun/argus
./venv/bin/pytest --import-mode=importlib -q
```
*Expected Output*: `1953 passed, 1 skipped` (or higher when new tests are added).

### 5.2 TaskGenerator Integration Verification
```bash
./venv/bin/pytest --import-mode=importlib -k "task_generator" -q
```

### 5.3 ScanDAG & ScanEngine Topological Verification
```bash
./venv/bin/pytest --import-mode=importlib tests/scanning/ -q
```

### 5.4 Graph Model & CVSS Verification
```bash
./venv/bin/pytest --import-mode=importlib tests/reporting/test_cvss.py tests/graph/ -q
```

---
*Report complete and ready for the Orchestrator and Specialist implementation teams.*
