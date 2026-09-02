# Final Sprint Report — Sprint 19: HTTP Request Smuggling Detection Module

## 1. Executive Summary
Sprint 19 delivers the complete HTTP Request Smuggling Detection Module for the ARGUS platform. The module actively tests whether frontend reverse proxies, load balancers, and backend application servers properly synchronize HTTP request boundaries in accordance with RFC 7230 §3.3.3 and RFC 9113.

The implementation features the Tripartite Collector Pattern (`RequestSmugglingPayloadGenerator`, `RequestSmugglingSecurityAnalyzer`, `HTTPRequestSmugglingCollector`), a custom `RawHttpStreamProber` preserving exact un-sanitized byte streams with safe timeouts and differential latency tracking, detection of CL.TE, TE.CL, TE.TE obfuscations, HTTP/2 downgrading flaws (H2.CL, H2.TE, CRLF injections), 2-request confirmation pipelines with status inversion / canary reflection analysis, and false positive suppression for hardened RFC-compliant servers.

All 1,476 baseline tests continue to pass without regressions, and 39 comprehensive unit, functional, and adversarial tests were added (total: 1,515 passing tests).

---

## 2. Deliverables & Architectural Implementation

### 2.1 Core Collector Module (`argus/collectors/request_smuggling.py`)
- **Tripartite Pattern**:
  1. `RequestSmugglingPayloadGenerator`: Constructs CL.TE, TE.CL, TE.TE, H2.CL, H2.TE, and pseudo-header CRLF injection probes across 6+ mutation strategies.
  2. `RequestSmugglingSecurityAnalyzer`: Validates differential response timing (threshold delta >= 3.0s), 2-request pipeline confirmation (canary reflection / status inversion), and rejects false positives from hardened endpoints (400/501/505).
  3. `HTTPRequestSmugglingCollector(BaseCollector)` (with alias `RequestSmugglingCollector`): Discovers candidate endpoints, executes probes, and performs quadruple state updates (`mission.evidence`, `mission.vulnerabilities`, `mission.attack_surface_graph`, `publish_finding`).
- **Raw Stream Prober (`RawHttpStreamProber`)**:
  - Direct TCP and TLS socket prober transmitting byte-precise un-sanitized HTTP streams.
  - Safe timeout handling (`socket.timeout`), protocol parsing, and `transport_adapter` hooks for deterministic testing.
  - `RawHttpResponse` model capturing headers, raw headers, body, raw bytes, status, protocol, and elapsed time.

### 2.2 Mutation & Obfuscation Strategies
1. **Header Casing & Whitespace**: `Transfer-Encoding: chunked`, `Transfer-encoding: \tchunked`, `Transfer-Encoding : chunked`, `Transfer-Encoding:\r\n chunked`.
2. **Dual Conflicting Headers**: `Transfer-Encoding: x\r\nTransfer-Encoding: chunked`, `Transfer-Encoding: chunked\r\nTransfer-Encoding: identity`.
3. **Hop-by-Hop Stripping**: `Connection: Transfer-Encoding\r\nTransfer-Encoding: chunked`, `X-Forwarded-For with Connection: Transfer-Encoding`.
4. **Chunk Size Mutations & Extensions**: `0;foo=bar\r\n\r\n`, hex uppercase `0X0\r\n\r\n`.
5. **HTTP/2 Pseudo-Header CRLF Injection**: `:path: /endpoint HTTP/1.1\r\nTransfer-Encoding: chunked`, custom header CRLF.
6. **Comma-Delimited**: `Transfer-Encoding: chunked, identity`.

### 2.3 Pipeline Connectivity
1. **Tool Registry (`argus/runtime/registry.py`)**:
   - Registered `request_smuggling` (priority 95, capability `request_smuggling_detector`, inputs `["endpoints"]`, outputs `["vulnerabilities", "observations", "evidence"]`).
   - Registered 16 aliases in `ToolRegistry.get()` (`request_smuggling`, `http_request_smuggling`, `cl_te`, `te_cl`, `te_te`, `h2_smuggling`, `http2_smuggling`, `h2_cl`, `h2_te`, `h2_crlf`, `smuggling`, `http_smuggling`, `http_desync`, `desync`, `request_smuggling_collector`, `request_smuggling_detector`).
2. **Plugin Fallback (`argus/runtime/plugins.py`)**:
   - Added dynamic fallback in `PluginExecutorAdapter._instantiate_specialist_fallback()` returning `HTTPRequestSmugglingCollector()`.
3. **Task Generator DAG (`argus/planning/task_generator.py`)**:
   - Added `request_smuggling` template to `_RECON_TEMPLATES` with dependency `["Discover API Endpoints"]`.
   - Updated `_resolve_template_for_gap` to map smuggling keywords to the recon template.
   - Updated `from_gaps` to supply discovered endpoints as task inputs.
4. **Attack Surface Graph (`argus/graph/attack_surface.py`)**:
   - Added category 20 handling in `build_from_evidence()` to create `live_host`, `endpoint`, and `vulnerability` nodes and connect them with `HAS_ENDPOINT` and `HAS_VULNERABILITY` edges.
5. **CVSS & CWE Taxonomy (`argus/reporting/cvss.py`)**:
   - Mapped all smuggling categories and techniques to `CWE-444` ("Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling')").
   - Configured calibrated CVSS preset vectors: Critical 9.8 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) and High 8.2 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N`).

---

## 3. Test Suite & Verification Audit

### 3.1 New Tests Added (39 Tests)
- `tests/collectors/test_request_smuggling.py` (27 tests):
  - Unit tests for payload generators (CL.TE, TE.CL, TE.TE, H2 downgrade).
  - Unit tests for raw stream probers and response parsers.
  - Unit tests for security analyzer (differential timing, pipeline confirmation, hardened rejection).
  - Integration tests for `HTTPRequestSmugglingCollector` with mock transports.
  - Verification tests for tool registry, plugin fallback, DAG generation, graph builder, and CVSS/CWE mappings.
- `tests/collectors/test_request_smuggling_adversarial.py` (12 tests):
  - High-jitter latency differential threshold resilience.
  - Chunk extension and hex mutation coverage.
  - CRLF header folding obfuscation.
  - Dual conflicting headers.
  - Hop-by-hop Connection header stripping.
  - HTTP/2 :path pseudo-header CRLF injection.
  - Status inversion (404/405) with canary reflection.
  - Hardened RFC compliance error suppression.
  - Socket connection reset and timeout error resilience.
  - ControlledMission wrapper finding publishing.
  - Custom ports and IPv6 candidate endpoint discovery.

### 3.2 Verification Results
- **New Tests Run**:
  ```bash
  python -m pytest tests/collectors/test_request_smuggling.py tests/collectors/test_request_smuggling_adversarial.py -v
  ```
  Result: `39 passed in 12.05s` (0 failures).
- **Full Workspace Regression Run**:
  ```bash
  python -m pytest tests/ --ignore=tests/workspace -x -q
  ```
  Result: `1515 passed, 28699 warnings in 65.25s` (1,476 baseline + 39 new tests, 0 failures, 0 regressions).
