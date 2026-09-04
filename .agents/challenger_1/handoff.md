# Empirical Challenger 1 Handoff Report: Scope, Recon & Pipeline Adversarial Review

## 1. Challenge Summary
- **Target Subsystems**: Scope Defaulting (`Mission.scope`, `_derive_default_scope`), `ScopeResolver`, Python-Native Recon Fallbacks (`subfinder`, `httpx`, `katana`, `nuclei`), Downstream Vulnerability Pipeline Execution (`ScanEngine`, `ScanDAG`, `AuthenticatedHttpClient`, `OAuthCollector`).
- **Overall Risk Assessment**: **HIGH**
- **Verdict**: **REQUEST_CHANGES**

---

## 2. Observation

### Observation 1: Scope Defaulting on Bracketed IPv6 Addresses with Ports (`argus/runtime/mission.py`)
- **Location**: `argus/runtime/mission.py:110-147`
- **Verbatim Code**:
```python
        # Handle host:port notation (excluding pure IPv6 addresses)
        if ":" in host and not host.startswith("["):
            try:
                ipaddress.ip_address(host)
            except ValueError:
                # Check if it has a port at the end (e.g., api.example.com:8080)
                parts = host.rsplit(":", 1)
                if len(parts) == 2 and parts[1].isdigit():
                    host = parts[0]
...
    # Strip IPv6 enclosing brackets if present
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]

    # Check if host is a valid IP address (IPv4 or IPv6)
    try:
        ipaddress.ip_address(host)
        return [host]
    except ValueError:
        pass
...
    # Domain or hostname
    return [host, f"*.{host}"]
```
- **Execution & Output**:
  When `target = "[::1]:9000"` or `target = "[2001:db8::1]:443"`:
  `host` starts with `[` so `host.startswith("[")` skips port stripping.
  Then `host.startswith("[") and host.endswith("]")` evaluates to `False` because `host` ends with the port digits (e.g. `9000` or `443`).
  `ipaddress.ip_address("[::1]:9000")` fails with `ValueError`.
  The function falls through to domain defaulting and returns `['[::1]:9000', '*.[::1]:9000']` instead of `['::1']` or `['2001:db8::1']`.
- **Reproducing Test**:
  `pytest tests/authorization/test_adversarial_scope_recon.py::test_ipv6_with_port_bracket_notation` -> `FAILED: assert ['[::1]:9000', '*.[::1]:9000'] == ['::1']`

---

### Observation 2: Port & Path Distortion in Recon Fallback Modules (`argus/collectors/httpx.py` & `katana.py`)
- **Locations**:
  - `argus/collectors/httpx.py:51-64`
  - `argus/collectors/katana.py:27-56`
- **Verbatim Behavior**:
  - In `HttpxCollector._derive_host_dict("[::1]:9000")`: `":" in item and not item.startswith("[")` skips port extraction because of `startswith("[")`. The resulting dictionary has `host="[::1]:9000"`, `port=443`, ignoring the target's explicit port `9000`.
  - In `KatanaCollector._derive_endpoint_dict`: When a string host without scheme `[::1]:9000` or `example.com/api/v1` is provided, `urlparse` parses the entire string into `path`. Concatenating `clean_host` with `path` results in `'[::1]:9000/[::1]:9000'` or duplicate path segments (e.g. `http://example.com:8080/api/v1/api/v1`).

---

### Observation 3: `OAuthCollector` Crashes on `status_code is None` (`argus/collectors/oauth.py`)
- **Location**: `argus/collectors/oauth.py:478, 561, 672, 704, 735, 771, 810, 952`
- **Verbatim Error**:
  ```
  TypeError: '<=' not supported between instances of 'int' and 'NoneType'
  ```
- **Root Cause**:
  When `AuthenticatedHttpClient` or `AuthorizedHttpClient` encounters an error (scope block, connection error, unreachable host, timeout), it returns `HttpResponse(success=False, status_code=None, ...)`.
  `OAuthAnalyzer` methods extract `status = response.status_code` and immediately execute comparisons such as `if 300 <= status < 400:` or `if 200 <= status < 300:` without verifying `status is not None`.
- **Reproducing Test**:
  `pytest tests/authorization/test_adversarial_scope_recon.py::test_downstream_collectors_under_path_empty` -> `FAILED: Failed collectors: ["oauth ('<=' not supported between instances of 'int' and 'NoneType')"]`

---

### Observation 4: `ScanEngine.run(mission)` Missing Mission Registration in `mission_manager`
- **Location**: `argus/scanning/engine.py:183-205` and `argus/http/client.py:109-122`
- **Behavior**:
  When `ScanEngine.run(mission)` is invoked with an independently instantiated `Mission` object (such as in programmatic invocations or unit tests), the mission is not registered into `mission_manager._active_missions`.
  During collector execution, `AuthenticatedHttpClient` calls `self.scope_resolver.check_scope(url, mission.id)`, which looks up `mission_manager.get_mission(mission_id)`.
  Because the mission is missing from `mission_manager`, `get_mission` returns `None`, and `check_scope` evaluates every outgoing HTTP request as `ScopeState.UNKNOWN` (`source="MissionNotFound"`), blocking 100% of HTTP traffic with:
  `HTTP_REQUEST_BLOCKED_SCOPE: Target '...' is out of scope for mission '...'`

---

## 3. Logic Chain

1. **Premise 1**: Requirements R2 and interface contracts in `PROJECT.md` specify that `Mission.scope` must auto-derive authorized boundaries for domains, wildcards, IPv4, IPv6, CIDRs, and URLs with ports/paths so that `ScopeResolver` never falsely blocks authorized targets.
2. **Premise 2**: Observation 1 proves that `_derive_default_scope("[::1]:9000")` yields `['[::1]:9000', '*.[::1]:9000']`. `ScopeResolver.resolve_target("[::1]:9000")` resolves to `"::1"`. Matching `"::1"` against `['[::1]:9000', '*.[::1]:9000']` evaluates to `False`. Thus, `ScopeResolver.check_scope` returns `OUT_OF_SCOPE` for authorized requests against bracketed IPv6 services.
3. **Premise 3**: Observation 2 proves that Python-native fallback seeding in `HttpxCollector` and `KatanaCollector` corrupts host ports and URL paths for bracketed IPv6 and raw path targets.
4. **Premise 4**: Observation 3 proves that `OAuthCollector` crashes whenever an HTTP probe fails or is blocked by scope, violating the requirement of graceful fallback execution with zero unhandled exceptions.
5. **Premise 5**: Observation 4 proves that direct `ScanEngine.run(mission)` execution fails to register the mission with `mission_manager`, causing `ScopeResolver` to reject all HTTP requests across downstream collectors.
6. **Conclusion**: The implementation contains 4 high-severity defects that compromise scope enforcement, IPv6 support, recon fallbacks, and downstream vulnerability assessment. Changes are required before Sprint 30 completion.

---

## 4. Challenges & Concrete Mitigations

### Challenge 1: Bracketed IPv6 Port Stripping in `_derive_default_scope` [HIGH]
- **Assumption Challenged**: Bracketed IPv6 targets with ports (e.g., `[::1]:9000`, `[2001:db8::1]:443`) are properly parsed into IP address scope rules.
- **Attack Scenario**: User scans an IPv6 endpoint on port 9000 (`[::1]:9000`). Scope defaults to `['[::1]:9000', '*.[::1]:9000']`. All legitimate HTTP requests to `http://[::1]:9000/api` are rejected by `ScopeResolver` as out-of-scope.
- **Blast Radius**: Complete scanning failure against IPv6 services with explicit ports.
- **Mitigation**:
  In `argus/runtime/mission.py:_derive_default_scope`:
  ```python
  if host.startswith("[") and "]" in host:
      host = host[1:host.index("]")]
  ```
  before checking `ipaddress.ip_address(host)`.

### Challenge 2: `OAuthAnalyzer` Unchecked Status Code Comparisons [HIGH]
- **Assumption Challenged**: Downstream vulnerability collectors handle unreachable or blocked targets without raising unhandled exceptions.
- **Attack Scenario**: An endpoint is offline or blocked by scope during a full scan. `AuthenticatedHttpClient` returns `HttpResponse(status_code=None)`. `OAuthCollector` raises `TypeError: '<=' not supported between instances of 'int' and 'NoneType'` and marks the scan task as `FAILED`.
- **Blast Radius**: Unhandled collector crash terminating OAuth/OIDC vulnerability assessments.
- **Mitigation**:
  In `argus/collectors/oauth.py`, guard all status code checks with `if status is not None and ...`:
  ```python
  status = response.status_code
  if status is not None and 300 <= status < 400 and location:
  ...
  if status is not None and 200 <= status < 300:
  ```

### Challenge 3: Fallback Port and Path Extraction in `httpx.py` and `katana.py` [MEDIUM]
- **Assumption Challenged**: Python-native fallbacks generate valid URLs when given bracketed IPv6 and complex paths.
- **Attack Scenario**: Scanning `[::1]:9000` or `example.com/api` under `PATH=""` yields corrupted endpoints like `'[::1]:9000/[::1]:9000'` or live host port `443` instead of `9000`.
- **Blast Radius**: Downstream collectors receive invalid URLs and cannot scan target endpoints.
- **Mitigation**:
  - In `argus/collectors/httpx.py:_derive_host_dict`: Normalize bracketed IPv6 with ports by extracting `parts = item.rsplit("]:", 1)` -> `host = parts[0] + "]"`, `port = int(parts[1])`.
  - In `argus/collectors/katana.py:_derive_endpoint_dict`: Cleanly parse path from host URL without double-prefixing.

### Challenge 4: Missing Mission Registration in `ScanEngine.run` [MEDIUM]
- **Assumption Challenged**: `ScanEngine.run(mission)` can be invoked independently from any caller.
- **Attack Scenario**: Programmatic invocations of `ScanEngine.run(mission)` cause `AuthorizedHttpClient` to fail with `ScopeState.UNKNOWN` for every HTTP request because `mission_manager` has no reference to `mission`.
- **Blast Radius**: All HTTP-based vulnerability collectors fail during programmatic or embedded engine scans.
- **Mitigation**:
  In `argus/scanning/engine.py:ScanEngine.run`:
  ```python
  from argus.runtime.manager import mission_manager
  if mission.id not in mission_manager._active_missions:
      mission_manager._active_missions[mission.id] = mission
  ```

---

## 5. Stress Test Results

| Test Scenario | Input Target | Expected Behavior | Actual Behavior | Verdict |
|---|---|---|---|---|
| Complex URL with Auth/Port/Path/Query/Frag | `http://user:pass@sub.domain.co.uk:8443/api/v1?x=1#frag` | `["sub.domain.co.uk", "*.sub.domain.co.uk"]`, `IN_SCOPE` | `["sub.domain.co.uk", "*.sub.domain.co.uk"]`, `IN_SCOPE` | **PASS** |
| IPv4 with Port | `127.0.0.1:8080` | `["127.0.0.1"]`, `IN_SCOPE` | `["127.0.0.1"]`, `IN_SCOPE` | **PASS** |
| IPv6 Bracket Port | `[::1]:9000` | `["::1"]`, `IN_SCOPE` | `['[::1]:9000', '*.[::1]:9000']`, `OUT_OF_SCOPE` | **FAIL (Defect 1)** |
| IPv6 Global Port | `[2001:db8::1]:443` | `["2001:db8::1"]`, `IN_SCOPE` | `['[2001:db8::1]:443', '*.[2001:db8::1]:443']`, `OUT_OF_SCOPE` | **FAIL (Defect 1)** |
| CIDR /24 Matching | `10.0.0.0/24` | `["10.0.0.0/24"]`, `10.0.0.1` -> `IN_SCOPE`, `10.0.1.1` -> `OUT_OF_SCOPE` | Match within subnet, block outside | **PASS** |
| CIDR /28 Matching | `192.168.1.0/28` | `["192.168.1.0/28"]`, `.15` -> `IN_SCOPE`, `.16` -> `OUT_OF_SCOPE` | Match within subnet, block outside | **PASS** |
| Lookalike Domain Attack | `evilexample.com`, `example.com.attacker.com` | `OUT_OF_SCOPE` for `example.com` target | Blocked `OUT_OF_SCOPE` | **PASS** |
| Suffix Subdomain Legitimate | `sub.example.com`, `a.b.c.example.com` | `IN_SCOPE` for `example.com` target | Allowed `IN_SCOPE` | **PASS** |
| Recon Fallbacks (`PATH=""`) | `http://api.example.com:8080/v1/users` | Subfinder -> host, Httpx -> host dict, Katana -> endpoint, Nuclei -> `[]` | Clean fallback seeding without Go tools | **PASS** |
| Full 26-Task Scan (`PATH=""`) | `http://api.example.com:8080/v1/users?id=1` | 26 collectors run with 0 failures | OAuth collector crashes with `TypeError` | **FAIL (Defect 3)** |

---

## 6. Caveats
- Baseline test suite (2,102 tests) currently passes because existing unit tests do not test bracketed IPv6 with ports, nor do they exercise `OAuthCollector` with an unreachable target (`status_code=None`).
- The 4 defects identified were verified by creating and executing standalone pytest test cases in `tests/authorization/test_adversarial_scope_recon.py`.

---

## 7. Conclusion & Verdict
- **Verdict**: **REQUEST_CHANGES**
- **Actionable Next Steps**:
  1. Update `_derive_default_scope` in `argus/runtime/mission.py` to extract IPv6 from bracketed host:port strings (`[::1]:9000` -> `::1`).
  2. Update `argus/collectors/httpx.py:_derive_host_dict` and `argus/collectors/katana.py:_derive_endpoint_dict` to handle bracketed IPv6 and raw path targets.
  3. Guard all status code comparisons in `argus/collectors/oauth.py` with `if status is not None and ...`.
  4. Ensure `ScanEngine.run(mission)` registers `mission` in `mission_manager._active_missions`.
  5. Re-run `pytest tests/authorization/test_adversarial_scope_recon.py` to achieve 100% passing rate.

---

## 8. Verification Method
Execute the following verification command:
```bash
python3 -m pytest tests/authorization/test_adversarial_scope_recon.py -v
```
- **Invalidation Condition**: If `test_ipv6_with_port_bracket_notation`, `test_ipv6_global_with_port`, and `test_downstream_collectors_under_path_empty` fail, the codebase remains defective. When all 8 tests pass, the system is fully hardened.
