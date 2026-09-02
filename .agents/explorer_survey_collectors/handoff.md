# Comprehensive Architecture Survey Report: ARGUS Vulnerability Collectors & Pipeline Integration

**Author**: Survey Explorer 1 (Collector Architecture Researcher)  
**Sprint**: Sprint 17 — GraphQL Security Detection Module  
**Working Directory**: `/home/varun/argus/.agents/explorer_survey_collectors/`  
**Target Reference**: `/home/varun/argus/.agents/ORIGINAL_REQUEST.md`

---

## Executive Summary

This survey report provides an exhaustive architectural decomposition of vulnerability collectors in the ARGUS defensive security platform. The investigation audited existing high-maturity collectors (`argus/collectors/deserialization.py`, `xml_parser.py`, `ssrf.py`, `access_control.py`, `oauth.py`), the HTTP execution layer (`argus/http/client.py`), data models (`argus/evidence/model.py`, `argus/models/attack_surface.py`, `test_identity.py`), runtime registration (`argus/runtime/registry.py`, `argus/runtime/plugins.py`), DAG task planning (`argus/planning/task_generator.py`), attack surface graph builder (`argus/graph/attack_surface.py`), and CVSS/CWE heuristics (`argus/reporting/cvss.py`).

The findings establish clear, reusable architectural blueprints for designing and implementing the Sprint 17 **GraphQL Security Collector** (`argus/collectors/graphql.py` / `argus/collectors/graphql_security.py`).

---

## 1. Collector Architecture & The Modular Triad Pattern

ARGUS active vulnerability collectors follow a standardized **Three-Tier Modular Architecture**:

```
+-------------------------------------------------------------------------+
|                          <Vulnerability>Collector                       |
|  - Inherits from BaseCollector (argus/collectors/base.py)               |
|  - Implements collect(mission) -> List[Evidence] and execute(mission)   |
|  - Manages target/endpoint extraction & parameter fuzzing loops         |
|  - Dispatches HTTP requests via polymorphic _execute_request()          |
|  - Handles mission state updates & KnowledgeGraph attack surface edges  |
+------------------------------------+------------------------------------+
                                     |
           +-------------------------+-------------------------+
           |                                                   |
           v                                                   v
+-----------------------------------+   +-----------------------------------+
|     <Vulnerability>PayloadGenerator |   |      <Vulnerability>Analyzer      |
| - Generates base probes           |   | - Compiles signature regexes      |
| - Generates mutation strategies   |   | - Executes baseline subtraction   |
| - Implements encoding/bypasses    |   | - Applies echo guards/reflection  |
| - Returns structured probe dicts  |   | - Measures differential timing    |
+-----------------------------------+   | - Returns <Vuln>Result / None     |
                                        +-----------------------------------+
```

### 1.1 Base Collector Contract
Defined in `argus/collectors/base.py:1-10`:
```python
from abc import ABC, abstractmethod

class BaseCollector(ABC):
    @abstractmethod
    def collect(self, mission):
        """Collect information and update the mission."""
        pass
```

### 1.2 Plugin & Specialist Interface Compatibility
Every collector also implements an `execute(mission)` adapter method for compatibility with `PluginExecutorAdapter` (`argus/runtime/plugins.py:49-50`):
```python
def execute(self, mission: Any) -> List[Evidence]:
    """Plugin / Specialist adapter interface."""
    return self.collect(mission)
```

---

## 2. Target & Mission Asset Extraction Patterns

Collectors must robustly handle heterogeneous mission representations, including raw `Mission` objects and `ControlledMission` wrappers.

### 2.1 Extraction and Fallback Synthesis
Examined in `argus/collectors/deserialization.py:1007-1024`:
```python
raw_mission = getattr(mission, "_mission", mission)
endpoints = list(getattr(raw_mission, "endpoints", []) or [])
live_hosts = list(getattr(raw_mission, "live_hosts", []) or [])
target = str(getattr(raw_mission, "target", "") or "")

# Fallback target synthesis if endpoints is empty
if not endpoints:
    if live_hosts:
        for lh in live_hosts:
            url = lh.get("url", lh) if isinstance(lh, dict) else str(lh)
            if url:
                endpoints.append({"url": url, "method": "GET"})
    elif target:
        endpoints.append({"url": target if target.startswith("http") else f"http://{target}", "method": "GET"})
```

### 2.2 Endpoint Dictionary vs String Normalization
Endpoints in ARGUS may be strings or structured dictionaries (`argus/collectors/deserialization.py:1032-1046`):
```python
if isinstance(ep, dict):
    target_url = ep.get("url") or ""
    ep_method = (ep.get("method") or "GET").upper()
    body = ep.get("body")
    headers = ep.get("headers") or {}
    cookies = ep.get("cookies") or {}
    query_params = ep.get("params") or {}
else:
    target_url = str(ep)
    ep_method = "GET"
    body = None
    headers = {}
    cookies = {}
    query_params = {}
```

### 2.3 GraphQL Discovery Integration
In addition to general endpoints, `AttackSurface` (`argus/models/attack_surface.py:19`) defines `graphql: list[dict] = field(default_factory=list)`, and `GraphQLDiscovery` (`argus/plugins/graphql/discovery.py:14-17`) enumerates candidate paths:
- `/graphql`, `/api/graphql`, `/v1/graphql`, `/v2/graphql`, `/query`, `/gql`, `/graphql/`

The GraphQL collector should probe discovered `graphql` endpoints, general `endpoints` matching GraphQL paths, and probe standard default GraphQL paths against `live_hosts`.

---

## 3. HTTP Client Layer & Request Dispatching

### 3.1 `AuthenticatedHttpClient` Capabilities (`argus/http/client.py`)
- Inherits from `AuthorizedHttpClient` and uses `httpx.Client`.
- Enforces strict **Scope Checks** (`ScopeResolver.check_scope()`) before transmitting credentials (`argus/http/client.py:377-389`).
- Enforces **Authorization Gate** checks (`authorization_gate.can_execute_action()`) (`argus/http/client.py:392-406`).
- Injects identity headers and cookies from `TestIdentity` (`argus/http/client.py:408-421`).
- Provides exponential backoff retries on `httpx.TimeoutException` and `httpx.RequestError` (`argus/http/client.py:433-497`).
- Redacts sensitive parameters and headers (`Authorization`, `Cookie`, `X-API-Key`, `token`) in logs via `sanitize_headers()` and `sanitize_url()`.
- Automatically captures and syncs session cookies into `active_identity.update_session()` (`argus/http/client.py:450`).
- Returns structured `HttpResponse` containing `success`, `status_code`, `headers`, `request_headers`, `body`, `raw_body`, `url`, `method`, `elapsed`, and `error`.

### 3.2 Polymorphic Request Dispatcher Pattern
To support both production execution with `AuthenticatedHttpClient` and fast unit testing with mock clients, all modern ARGUS collectors implement a polymorphic execution helper (`argus/collectors/deserialization.py:907-1001`):
```python
def _execute_request(
    self,
    mission: Any,
    method: str,
    url: str,
    params: Optional[Dict[str, Any]] = None,
    data: Optional[Union[str, bytes, Dict[str, Any]]] = None,
    json_data: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
    cookies: Optional[Dict[str, str]] = None,
) -> Optional[HttpResponse]:
    method = method.upper()
    req_headers = dict(headers or {})
    req_cookies = dict(cookies or {})

    try:
        if self.http_client is not None:
            client = self.http_client
            # 1. client.get(...) / client.post(...)
            if method == "GET" and hasattr(client, "get"):
                try:
                    return client.get(mission, url, params=params, headers=req_headers, cookies=req_cookies, timeout=self.timeout)
                except TypeError:
                    return client.get(url, params=params, headers=req_headers, cookies=req_cookies)
            if method == "POST" and hasattr(client, "post"):
                kwargs = {"headers": req_headers, "cookies": req_cookies}
                if params: kwargs["params"] = params
                if json_data is not None: kwargs["json"] = json_data
                if data is not None: kwargs["data"] = data
                try:
                    return client.post(mission, url, timeout=self.timeout, **kwargs)
                except TypeError:
                    return client.post(url, **kwargs)
            if hasattr(client, "request"):
                try:
                    return client.request(mission, method=method, url=url, params=params, data=data, json=json_data, headers=req_headers, cookies=req_cookies, timeout=self.timeout)
                except TypeError:
                    return client.request(method=method, url=url, params=params, data=data, json=json_data, headers=req_headers, cookies=req_cookies)
            if callable(client):
                return client(method=method, url=url, params=params, data=data, json=json_data, headers=req_headers, cookies=req_cookies)

        # Fallback to AuthenticatedHttpClient context manager
        with AuthenticatedHttpClient(timeout=self.timeout, max_retries=1) as client:
            if method == "GET":
                return client.get(mission, url, params=params, headers=req_headers, cookies=req_cookies, timeout=self.timeout)
            elif method == "POST":
                return client.post(mission, url, data=data, json=json_data, headers=req_headers, cookies=req_cookies, timeout=self.timeout)
            else:
                return client.request(mission, method, url, params=params, data=data, json=json_data, headers=req_headers, cookies=req_cookies, timeout=self.timeout)
    except Exception as e:
        logger.debug(f"HTTP request to {url} failed: {e}")
    return None
```

---

## 4. Detection Routines, Mutation Engines & Vulnerability Categories

### 4.1 Mutation / Bypass Strategies
Sprint 17 Requirement R3 requires at least 5 distinct GraphQL bypass/mutation strategies. Looking at how `deserialization.py` (6 strategies) and `xml_parser.py` (6 strategies) organize them:

| Strategy Enum | Description in GraphQL Context |
|---|---|
| `METHOD_SWAPPING` | Swapping `POST` to `GET` (query string parameters `?query=...`) or `PUT` |
| `CONTENT_TYPE_MANIPULATION` | Switching between `application/json`, `application/graphql`, `application/x-www-form-urlencoded`, `multipart/form-data` |
| `QUERY_OBFUSCATION` | Whitespace randomization, comment injection (`# comment\n`), tab/newline manipulation, unicode escapes |
| `ALIAS_MULTIPLEXING` | Alias pollution (`q1: field, q2: field`) to bypass query batch limits or rate limiting |
| `OPERATION_NAME_TAMPERING` | Multi-operation payloads with custom or omitted `operationName` |
| `FRAGMENT_CYCLE_MUTATION` | Recursive fragment spread definitions (`fragment F on User { ...F }`) |

### 4.2 Detection Result Dataclass Pattern
Every collector defines a specific `<Vuln>Result` dataclass to encapsulate probe outcomes:
```python
@dataclass
class GraphQLSecurityResult:
    vulnerability_type: str  # introspection, suggestion_leak, depth_dos, batching_abuse, field_auth_bypass
    mutation_strategy: str
    severity: str
    confidence: float
    payload: str
    matched_signature: str
    evidence_snippet: str
    endpoint_url: str
    status_code: int = 200
    delay_delta: float = 0.0
    baseline_elapsed: float = 0.0
    injected_elapsed: float = 0.0
    is_valid_finding: bool = True
    template_id: str = "graphql-security"
```

---

## 5. False Positive Suppression & Baseline Subtraction

ARGUS mandates zero tolerance for false positives. Collectors use three primary suppression layers:

### 5.1 Baseline Subtraction
1. Send a clean baseline probe before testing injections (e.g. `{ __typename }` or benign query).
2. Record baseline status code, response body, and elapsed duration (`baseline_elapsed`).
3. If an injected probe response is identical to baseline, discard.
4. If an error signature was already present in the baseline response body, discard.

### 5.2 Echo Guard / Verbatim Reflection Check
If the server merely echoes the request payload verbatim in an error page or search result without executing GraphQL:
```python
if payload_str and payload_str in body:
    cleaned_body = body.replace(payload_str, "")
    is_real_error = any(pattern.search(cleaned_body) for pattern in signatures.values())
    if not is_real_error:
        return None  # Suppress reflection
```

### 5.3 Hardened Endpoint Rejection
When an endpoint responds with:
- Introspection disabled: `{"errors":[{"message":"GraphQL introspection is not allowed"}]}` or `{"errors":[{"message":"Cannot query field '__schema' on type 'Query'."}]}`
- Query depth limit enforced: `{"errors":[{"message":"Query depth exceeded maximum allowed depth"}]}`
- Complexity limits enforced: `{"errors":[{"message":"Query complexity limit exceeded"}]}`

These responses indicate **proper defense-in-depth security** and must NOT produce confirmed vulnerability findings.

---

## 6. Evidence Creation & Attack Surface Graph Wiring

### 6.1 `Evidence` Object Creation Contract (`argus/evidence/model.py`)
```python
ev = Evidence(
    mission_id=getattr(raw_mission, "id", ""),
    source_type="LOG",
    created_by="SYSTEM_GENERATED",
    title=title,
    description=description,
    category="graphql_security",  # or "graphql"
    value=target_url,
    source=target_url,
    status="CONFIRMED",
    confidence=confidence,
    severity=severity,
    provenance=ProvenanceData(step_id="graphql_security_collector"),
    tags=["graphql", "graphql_security", vuln_type, mutation_strategy, template_id],
    metadata={
        "url": target_url,
        "host": base_url,
        "category": "graphql_security",
        "severity": severity,
        "confidence": confidence,
        "vulnerability_type": vuln_type,
        "mutation_strategy": mutation_strategy,
        "matched_signature": result.matched_signature,
        "template_id": template_id,
        "status_code": status_code,
        "evidence_snippet": snippet[:250],
        "cwe_id": cwe_id,
        "cvss_score": cvss_score,
    },
)
```

### 6.2 Quadruple State Update
When a finding is confirmed, the collector updates 4 state targets:
1. **`raw_mission.evidence`**: Appends `ev` via `.add(ev)` or `.append(ev)`.
2. **`raw_mission.vulnerabilities`**: Appends finding dict to list.
3. **`raw_mission.attack_surface_graph` / `raw_mission.graph`**:
   - Adds `Node(id="live_host:<host>", type="live_host", ...)`
   - Adds `Node(id="endpoint:<url>", type="endpoint", ...)`
   - Adds `Node(id="vulnerability:<template_id>:<url>", type="vulnerability", ...)`
   - Connects `lh -> ep` with `HAS_ENDPOINT`
   - Connects `lh -> vuln` with `HAS_VULNERABILITY`
   - Connects `ep -> vuln` with `HAS_VULNERABILITY`
4. **`ControlledMission.publish_finding()`**: Safely calls wrapper method if available.

### 6.3 Attack Surface Graph Builder Support (`argus/graph/attack_surface.py`)
The `AttackSurfaceGraphBuilder.build_from_evidence()` method must have a designated section processing category `"graphql_security"` / `"graphql"` to parse evidence items and construct the corresponding nodes and `HAS_VULNERABILITY` edges.

---

## 7. Pipeline Wiring, Registry & DAG Integration

### 7.1 Tool Registry (`argus/runtime/registry.py`)
Collectors must be registered in `ToolRegistry` with:
- `id="graphql_security"` (with aliases like `"graphql_collector"`, `"graphql_scanner"`, `"graphql_vulnerability"`)
- `supported_tasks=["GraphQL Security Validation", "GraphQL Analysis", "Vulnerability Scanning", "Evidence Correlation", "API Discovery"]`
- `required_inputs=["endpoints"]`
- `produced_outputs=["vulnerabilities", "observations", "evidence"]`
- `capabilities=["graphql_security_validator", "graphql_security_collector"]`
- `priority=95`

### 7.2 Task Generator DAG (`argus/planning/task_generator.py`)
In `_RECON_TEMPLATES`:
```python
"graphql_security": {
    "title": "Validate GraphQL Security",
    "goal": "Actively test discovered GraphQL endpoints for introspection leakage, query depth DoS, batching multiplexing, and authorization bypasses using AuthenticatedHttpClient.",
    "category": TaskCategory.EVIDENCE_CORRELATION, # or GRAPHQL_ANALYSIS
    "required_inputs": ["endpoints"],
    "expected_outputs": ["vulnerabilities", "observations", "evidence"],
    "dependencies": ["Discover API Endpoints"],
    "required_specialists": [],
    "metadata": {"tool_id": "graphql_security"},
    "estimated_duration_minutes": 10,
    "priority": 0.81,
}
```

### 7.3 Plugin Executor Adapter (`argus/runtime/plugins.py`)
In `_instantiate_specialist_fallback()`:
```python
elif "graphql_security" in plugin_id or "graphql_collector" in plugin_id:
    from argus.collectors.graphql import GraphQLSecurityCollector
    return GraphQLSecurityCollector()
```

### 7.4 CVSS & CWE Mapping (`argus/reporting/cvss.py`)
- `graphql_introspection` -> `CWE-200` (CVSS 5.3 / 7.5 depending on severity)
- `graphql_depth_dos` -> `CWE-799` / `CWE-400` (CVSS 7.5)
- `graphql_batching_bypass` -> `CWE-799` / `CWE-287` (CVSS 7.5 / 8.2)
- `graphql_access_control` -> `CWE-284` / `CWE-285` (CVSS 8.1 / 9.8)

---

## 8. Test Harness & Mocking Conventions

From analyzing `tests/collectors/test_deserialization.py` (649 lines) and `test_xml_parser.py`:
A standard collector test file contains 8 dedicated test suites:
1. **Enums and Data Models Tests**: Test all enum strings, default dataclass fields.
2. **Signature Catalog Verification**: Test compiled regexes against positive and negative sample text.
3. **Payload Generator Tests**: Verify base payloads and all >= 5 mutation strategies.
4. **Collector Detection Tests across Channels**:
   - Introspection detection test
   - Field suggestion leakage test
   - Query depth recursion limit DoS test
   - Batch query / alias multiplexing test
   - Field-level access control discrepancy test
5. **False Positive Suppression & Baseline Subtraction Tests**:
   - Verbatim query reflection rejection test
   - Baseline error noise subtraction test
   - Hardened GraphQL response rejection test (properly disabled introspection returns no evidence)
6. **Mission & ControlledMission Compatibility Tests**: Test with empty mission, raw `Mission`, and `ControlledMission`.
7. **DAG, Registry & PluginExecutor Integration Tests**: Verify registry lookup, aliases, DAG task generation from coverage gaps, and plugin adapter instantiation.
8. **AttackSurfaceGraphBuilder & CVSS Verification**: Verify `HAS_VULNERABILITY` graph edges, CVSS score calculation, and CWE ID resolution.

---

## 9. 5-Component Handoff Protocol

### 1. Observation
- **Existing Collectors**: `argus/collectors/deserialization.py` (1,401 lines), `argus/collectors/xml_parser.py` (1,378 lines), `argus/collectors/ssrf.py` (1,665 lines), `argus/collectors/access_control.py` (397 lines), `argus/collectors/oauth.py` (1,472 lines).
- **HTTP Client**: `argus/http/client.py` lines 300–587 define `AuthenticatedHttpClient` with `login()`, `request()`, scope verification via `ScopeResolver`, and credential sanitization.
- **Evidence Model**: `argus/evidence/model.py` lines 25–57 define `Evidence` with slots, UUID generation, `ProvenanceData`, and metadata dictionaries.
- **Existing GraphQL Plugin**: `argus/plugins/graphql/` currently implements static discovery and schema inference, but lacks active vulnerability fuzzing, multi-vulnerability detection (introspection, depth DoS, batching, field access control), mutation strategies, and attack surface vulnerability edge generation.
- **Test Suite Baseline**: Verified passing `1352 passed, 27008 warnings in 53.01s` via `pytest tests/ --ignore=tests/workspace -q`.

### 2. Logic Chain
- ARGUS vulnerability collectors follow a well-established tripartite pattern: Payload Generator + Analyzer + Collector.
- The Sprint 17 GraphQL Security Collector must be created under `argus/collectors/graphql.py` (or `graphql_security.py`) and exported in `argus/collectors/__init__.py`.
- To satisfy R1, R2, and R3, the collector must test all 4 core risk categories (Introspection/Suggestions, Query Depth DoS, Batching/Multiplexing, Field-Level Access Control) across at least 5 mutation strategies.
- To satisfy R4, the collector must be registered in `argus/runtime/registry.py`, wired into `_RECON_TEMPLATES` in `argus/planning/task_generator.py`, wired into `argus/runtime/plugins.py`, and have graph edge creation in `argus/graph/attack_surface.py`.
- To satisfy R5, at least 20 new tests must be written adhering to the established test patterns, ensuring 0 regressions across the 1,352 baseline tests.

### 3. Caveats
- No caveats. The collector interfaces, HTTP execution patterns, graph node models, registry structures, and DAG configurations are completely explicit, consistent across all existing modules, and thoroughly verified.

### 4. Conclusion
The architecture survey is 100% complete. The implementation plan for Sprint 17 can proceed with clear specifications for `GraphQLSecurityCollector`, `GraphQLPayloadGenerator`, `GraphQLSecurityAnalyzer`, `GraphQLSecurityResult`, graph edge construction, DAG task generator templates, tool registry aliases, and test coverage.

### 5. Verification Method
1. Inspect the handoff file: `view_file /home/varun/argus/.agents/explorer_survey_collectors/handoff.md`
2. Run baseline tests: `python -m pytest tests/ --ignore=tests/workspace -q` (1,352 passing)
3. Invalidation condition: Any architectural divergence between the proposed collector structure and `argus/collectors/deserialization.py` or `argus/collectors/xml_parser.py`.

