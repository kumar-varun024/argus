# Sprint 18 Research & Codebase Investigation Report

**Role**: explorer_1 (Codebase Researcher)  
**Date**: 2026-08-31  
**Target Milestone**: Sprint 18 — WebSocket Security Detection Module  

---

## 1. Observation

Direct investigation of the codebase and test suite revealed the following architectural facts:

### A. Collector Hierarchy & Implementation Patterns
- **Base Collector (`argus/collectors/base.py`)**:
  - `BaseCollector` defines `@abstractmethod def collect(self, mission: Any) -> List[Evidence]`.
  - All modern security collectors (e.g. `GraphQLSecurityCollector` in `argus/collectors/graphql.py`, `DeserializationCollector` in `argus/collectors/deserialization.py`, `XMLParserSecurityCollector` in `argus/collectors/xml_parser.py`) follow a consistent 3-part modular architecture:
    1. **Payload & Mutation Generator** (e.g. `GraphQLPayloadGenerator`): Builds baseline, technique-specific probe payloads, and applies mutation/bypass strategies (returning structured request specifications).
    2. **Security Analyzer** (e.g. `GraphQLSecurityAnalyzer`): Analyzes `HttpResponse` bodies, status codes, response headers, elapsed time, and regex signature catalogs (`INTROSPECTION_SIGNATURES`, `SQL_ERROR_SIGNATURES`, `COMMAND_OUTPUT_SIGNATURES`, etc.) to produce strongly typed result dataclasses (`GraphQLSecurityResult`).
    3. **Collector Orchestrator** (e.g. `GraphQLSecurityCollector(BaseCollector)`): Manages candidate endpoint discovery (`_discover_candidate_endpoints`), baseline profiling, probe dispatch across mutation strategies, false-positive suppression, and quadruple state updates.
- **Quadruple State Updates**:
  1. `mission.evidence.add(ev)`: Persists structured `Evidence` object to the mission evidence store with `status="CONFIRMED"`, category (e.g. `category="websocket_security"`), confidence, severity, CVSS score, CWE ID, and rich metadata.
  2. `mission.vulnerabilities.append({...})`: Appends finding dictionary to `mission.vulnerabilities`.
  3. `mission.attack_surface_graph` / `mission.graph`: Adds `Node` items (`live_host`, `endpoint`, `vulnerability`) and connects them via `HAS_ENDPOINT` and `HAS_VULNERABILITY` edges.
  4. `mission.publish_finding(ev.evidence_id, ev)`: Emits finding if wrapped in `ControlledMission`.

### B. AuthenticatedHttpClient Capabilities (`argus/http/client.py`)
- **Scope & Authorization Gates**:
  - Every request strictly checks `ScopeResolver.check_scope(url, mission.id)` and `authorization_gate.can_execute_action(...)` before network transmission.
  - Out-of-scope requests are immediately blocked, returning `HttpResponse(success=False, error="Blocked by scope: ...")`.
- **Identity & Session Injection**:
  - Injects auth headers (`Authorization: Bearer <token>`, `X-API-Key: ...`) and cookies from `TestIdentity`.
  - Automatically captures and syncs returned cookies back to `TestIdentity.update_session(...)`.
- **Custom HTTP Request & Upgrade Headers**:
  - `AuthenticatedHttpClient.request(...)` (and `.get()`, `.post()`) accepts arbitrary custom `headers` and `cookies`.
  - HTTP Upgrade requests for WebSocket handshakes can be dispatched via standard HTTP GET with:
    `Upgrade: websocket`, `Connection: Upgrade`, `Sec-WebSocket-Key: <base64_nonce>`, `Sec-WebSocket-Version: 13`, `Origin: <origin_url>`, `Sec-WebSocket-Protocol: <subprotocol>`.
- **Polymorphic Inversion of Control**:
  - Collectors accept an optional `http_client` constructor parameter.
  - If `http_client` is provided (e.g., in unit/integration tests), calls are delegated to `client.get()`, `client.post()`, or `client.request()`. If omitted, the collector instantiates `with AuthenticatedHttpClient(timeout=..., max_retries=...) as client:`.

### C. Test Fixtures & Mock Server Architecture (`tests/collectors/`)
- Tests in `tests/collectors/test_graphql.py`, `tests/collectors/test_oauth.py`, `tests/collectors/test_deserialization.py`, etc., employ in-memory mock HTTP clients (`MockGraphQLHttpClient`, `MockOAuthHttpClient`, `MockDeserializationHttpClient`).
- Key features of the mock clients:
  - Route dictionary mapping keys/regexes to `(status_code, body, headers, elapsed)`.
  - Records all incoming GETs/POSTs/requests for verification assertions.
  - Supports simulated baseline responses and false-positive suppression validation.
- Test suites follow a standard 7-suite layout:
  1. Enums & Data Models
  2. Payload Generator
  3. Mutation Strategies
  4. Security Analyzer Detection
  5. False Positive Suppression & Hardened Server Handling
  6. Collector Execution & Quadruple State Updates
  7. Pipeline, DAG, Registry & Graph Integration

### D. Pipeline, DAG & Registry Connectivity
- **Tool Registry (`argus/runtime/registry.py`)**:
  - Tools are registered via `registry.register(Tool(id="websocket_security", name="WebSocket Security Detection Collector", ...))`.
  - Lookup aliases map legacy/alternate names (e.g., `websocket_security_collector`, `websocket_detector`, `cswsh_detector`, `websocket_fuzzer`) to `"websocket_security"`.
- **Plugin Executor Fallback (`argus/runtime/plugins.py`)**:
  - `PluginExecutorAdapter._instantiate_specialist_fallback(plugin_id)` dynamically imports and instantiates the collector when referenced in plugin execution workflows.
- **Task Generator DAG (`argus/planning/task_generator.py`)**:
  - `_RECON_TEMPLATES["websocket_security"]`: Configures task title `"Validate WebSocket Security"`, category `TaskCategory.EVIDENCE_CORRELATION`, dependencies `["Discover API Endpoints"]`, required inputs `["endpoints"]`, metadata `{"tool_id": "websocket_security"}`.
  - `_resolve_template_for_gap()`: Matches keywords (`"websocket"`, `"ws"`, `"cswsh"`, `"socket.io"`, `"web socket"`) in gap descriptions to `_RECON_TEMPLATES["websocket_security"]`.
- **CVSS & CWE Mapping (`argus/reporting/cvss.py`)**:
  - `CVSSCalculator.CWE_DATABASE` maps categories:
    - `"websocket_security"` -> `CWE-285` (Improper Authorization) / `CWE-346` (Origin Validation Error)
    - `"cswsh"` -> `CWE-346` (Origin Validation Error / Cross-Site WebSocket Hijacking)
    - `"websocket_dos"` -> `CWE-400` (Uncontrolled Resource Consumption)
    - `"websocket_injection"` -> `CWE-89` (SQLi) / `CWE-78` (Command Injection) / `CWE-79` (XSS)
- **Attack Surface Graph Builder (`argus/graph/attack_surface.py`)**:
  - Ingests evidence with `category="websocket_security"`, creates `Node(type="vulnerability")`, and links `live_host -> HAS_VULNERABILITY` and `endpoint -> HAS_VULNERABILITY`.

### E. Python Environment & Baseline Test Suite
- Python environment verification:
  - `httpx` is available at `/usr/lib/python3/dist-packages/httpx/__init__.py`.
  - `websockets` (version 16.0) is available at `/usr/lib/python3/dist-packages/websockets/__init__.py`.
- Baseline test run: `python -m pytest tests/ --ignore=tests/workspace -q` exits 0 with **1,425 passed**.

---

## 2. Logic Chain

1. **Design Alignment**:
   - To adhere to existing collector design principles (established in `graphql.py`, `deserialization.py`, `xml_parser.py`), the new module should be placed in `argus/collectors/websocket.py` implementing `WebSocketSecurityCollector(BaseCollector)` alongside `WebSocketPayloadGenerator`, `WebSocketSecurityAnalyzer`, `WebSocketSecurityResult`, and enum types (`WebSocketSeverity`, `WebSocketTechnique`, `WebSocketMutationStrategy`).
2. **WebSocket Probing Strategy**:
   - **Handshake Probing (CSWSH, Authentication, Protocol Fuzzing)**:
     - WebSocket connection establishment begins with an HTTP GET Upgrade request.
     - `AuthenticatedHttpClient` can directly generate and send the HTTP Upgrade GET request with custom headers (`Sec-WebSocket-Key`, `Sec-WebSocket-Version: 13`, `Upgrade: websocket`, `Connection: Upgrade`, `Origin: ...`).
     - If the server accepts the upgrade from an unauthorized origin (e.g., `Origin: https://evil.com`, `Origin: null`, `Origin: https://target.com.attacker.com`), status code 101 (or 200 with upgrade headers) is returned, confirming Cross-Site WebSocket Hijacking (CSWSH).
     - If the server accepts the upgrade without required authentication tokens/cookies or accepts query parameter tokens (`?token=secret`), broken authentication is confirmed.
   - **Frame Probing (Message Injection, Frame Fuzzing, DoS)**:
     - After or alongside handshake validation, message frame fuzzing probes text/JSON message structures for injection vulnerabilities:
       - SQL Injection: `{"action": "query", "user_id": "1' OR '1'='1"}`
       - OS Command Injection: `{"cmd": "; id ;", "exec": "127.0.0.1 | cat /etc/passwd"}`
       - Cross-Site Scripting: `{"message": "<script>alert(1)</script>"}`
       - Prototype Pollution: `{"__proto__": {"admin": true}}`
     - DoS and resource exhaustion testing:
       - Unmasked client frames (RFC 6455 Section 5.1 violation)
       - Oversized frame buffers (>64KB/1MB)
       - Ping-pong / message rate-limit bursts
   - **Mutation & Bypass Strategies (At least 5 distinct strategies)**:
     1. `ORIGIN_MANIPULATION`: `null`, `https://evil.com`, `https://target.com.attacker.com`, `https://attacker-target.com`, `http://localhost`
     2. `SUBPROTOCOL_TAMPERING`: `Sec-WebSocket-Protocol` tampering (`graphql-ws`, `wamp.2.json`, `soap`, `stomp`, `chat.v1`)
     3. `HOP_BY_HOP_SMUGGLING`: `Connection: keep-alive, Upgrade`, `Connection: close, Upgrade`, `Connection: Upgrade, X-Forwarded-For`
     4. `CASING_WHITESPACE_MUTATION`: `upgrade: WebSocket`, `CONNECTION: UPGRADE`, `sec-websocket-key: ...`, extra whitespace/tabs in header values
     5. `EXTENSION_DEFLATE_FUZZING`: `Sec-WebSocket-Extensions: permessage-deflate; client_no_context_takeover; client_max_window_bits=15`, malformed compression parameters
     6. `PARAMETER_AUTHENTICATION_BYPASS`: Shifting auth tokens across headers, query parameters (`?token=`), subprotocols, and initial handshake frames
3. **Mocking & Testability**:
   - `MockWebSocketHttpClient` can emulate HTTP 101 Switching Protocols, 401/403/426 rejections, and frame exchanges by inspecting requested URLs, headers, and payloads.
   - All tests can run in milliseconds without network I/O or external daemon dependencies, satisfying deterministic regression benchmarks.

---

## 3. Caveats

- **Network-Level Frame Transmissions vs HTTP Probing**:
  - Standard `httpx.Client` handles the HTTP upgrade request and returns `101 Switching Protocols`. In mock and pure-Python testing, HTTP handshake probing and simulated frame exchanges provide 100% deterministic coverage without requiring live background asyncio WebSocket servers.
  - Live frame socket interactions can optionally utilize standard `websockets` or `socket` when operating against real live targets with active TCP sockets.
- **False Positive Suppression**:
  - The analyzer must explicitly verify that hardened endpoints returning 401, 403, 400, or 426 Upgrade Required (with error messages like `"Origin not allowed"`, `"Unauthorized"`, `"Missing authentication token"`) do NOT generate evidence findings.
  - Baseline response subtraction must be performed to avoid reporting noise.

---

## 4. Conclusion & Recommended Architecture

The WebSocket Security Detection Module for Sprint 18 should be structured as follows:

### File Layout & Responsibilities
1. **`argus/collectors/websocket.py`**:
   - **Enums**:
     - `WebSocketSeverity` (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`)
     - `WebSocketTechnique` (`CSWSH`, `BROKEN_AUTHENTICATION`, `TOKEN_IN_QUERY_PARAM`, `INJECTION_SQLI`, `INJECTION_CMDI`, `INJECTION_XSS`, `PROTOTYPE_POLLUTION`, `UNMASKED_FRAME_DOS`, `OVERSIZED_FRAME_DOS`, `RATE_LIMIT_FLOOD`)
     - `WebSocketMutationStrategy` (`STANDARD`, `ORIGIN_MANIPULATION`, `SUBPROTOCOL_TAMPERING`, `HOP_BY_HOP_SMUGGLING`, `CASING_WHITESPACE_MUTATION`, `EXTENSION_DEFLATE_FUZZING`, `PARAMETER_AUTHENTICATION_BYPASS`)
   - **Dataclass**: `WebSocketSecurityResult`
   - **Signature Catalogs**:
     - `CSWSH_VULNERABLE_SIGNATURES`, `HARDENED_WS_DEFENSE_SIGNATURES`, `SQL_ERROR_SIGNATURES`, `COMMAND_OUTPUT_SIGNATURES`, `XSS_OUTPUT_SIGNATURES`, `DOS_CRASH_SIGNATURES`
   - **Classes**:
     - `WebSocketPayloadGenerator`: Handshake builders, origin mutations, frame injection payloads, subprotocol tamperers.
     - `WebSocketSecurityAnalyzer`: Evaluates handshake responses and frame responses, suppresses false positives, checks origin acceptance, regex signature matches.
     - `WebSocketSecurityCollector(BaseCollector)`: Discovers candidate endpoints (`/ws`, `/socket.io`, `/cable`, `/websocket`, etc.), executes baseline and mutation probes, and executes quadruple state updates. Exported alias: `WebSocketCollector`.
2. **`argus/runtime/registry.py`**:
   - Register `Tool(id="websocket_security", name="WebSocket Security Detection Collector", ...)` with supported tasks and capabilities.
   - Register aliases (`websocket_security_collector`, `websocket_detector`, `cswsh_detector`, `websocket_vuln`, `websocket_collector`, etc.).
3. **`argus/runtime/plugins.py`**:
   - Add fallback import for `"websocket_security"` in `PluginExecutorAdapter._instantiate_specialist_fallback()`.
4. **`argus/planning/task_generator.py`**:
   - Add `_RECON_TEMPLATES["websocket_security"]` dependent on `["Discover API Endpoints"]`.
   - Update `_resolve_template_for_gap()` to resolve websocket/CSWSH/socket.io gaps to `"websocket_security"`.
5. **`argus/reporting/cvss.py`**:
   - Add `CWE_DATABASE` entries for `websocket_security` (`CWE-346`), `cswsh` (`CWE-346`), `websocket_dos` (`CWE-400`), and `websocket_injection` (`CWE-89`/`CWE-78`).
6. **`argus/graph/attack_surface.py`**:
   - Add evidence ingestion handler for `category="websocket_security"` (and related categories) creating `vulnerability` nodes and connecting `HAS_VULNERABILITY` and `HAS_ENDPOINT` edges.
7. **`tests/collectors/test_websocket.py` & `tests/collectors/test_websocket_adversarial.py`**:
   - Comprehensive test suite covering enums, payload generator, all mutation strategies, analyzer detection, false positive suppression, collector execution with quadruple state updates, registry/DAG/graph integration, and adversarial edge cases.

---

## 5. Verification Method

To verify the investigation and downstream implementation:

1. **Full Baseline Test Suite**:
   ```bash
   python -m pytest tests/ --ignore=tests/workspace -x -q
   ```
   Must pass with 1,425+ tests (0 failures).

2. **Dedicated WebSocket Test Suite**:
   ```bash
   python -m pytest tests/collectors/test_websocket.py -v
   ```
   Must execute all newly authored tests with 100% pass rate.

3. **Registry & Pipeline Integration Check**:
   ```bash
   python -c "from argus.runtime.registry import registry; assert registry.get('websocket_security') is not None"
   python -c "from argus.collectors.websocket import WebSocketSecurityCollector, WebSocketCollector; assert WebSocketCollector is not None"
   python -c "from argus.planning.task_generator import _RECON_TEMPLATES; assert 'websocket_security' in _RECON_TEMPLATES"
   ```
