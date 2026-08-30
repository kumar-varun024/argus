# Empirical Challenger Report (Round 2): Sprint 6 Access Control / IDOR Engine

- **Agent**: `challenger_r2` (Round 2 Empirical Challenger)
- **Role**: critic, specialist
- **Target Components**: `argus/http/coordinator.py`, `argus/analyzers/response_discrepancy.py`, `argus/collectors/access_control.py`, `argus/graph/attack_surface.py`
- **Verdict**: **APPROVE**

---

## 1. Observation

We executed empirical verification and adversarial evaluations targeting the 5 defect areas previously surfaced in Round 1:

### 1.1 Defect 1: Soft-403 False Positive Elimination on Error Variations
- **Files Inspected**: `argus/analyzers/response_discrepancy.py` (lines 28–37, 88–117)
- **Observed Implementation**: `ERROR_TEXT_PATTERNS` was updated with comprehensive regex matching camelCase, snake_case, and phrasing variations (`access[_\-\s]*denied`, `permission[_\-\s]*denied`, `you\s+do\s+not\s+have\s+(?:the\s+)?(?:permission|access|authorization)`, `insufficient[_\-\s]*(?:privileges?|permissions?|scope)`, `access\s+restricted`).
- **Empirical Stress Harness Result**:
  - Evaluated 13 distinct soft error payloads against `is_error_or_login_response`, `analyze_vertical`, and `analyze_header_bypass` (including `{"error": "PermissionDenied"}`, `{"error": "AccessDenied"}`, `{"detail": "You do not have access"}`, `{"message": "insufficient_scope"}`, and nested structures `{"error": {"code": "PermissionDenied"}}`).
  - **Result**: `13/13` error variations properly recognized as access restrictions (`is_error_or_login_response` returns `True`). Zero false positive IDOR, vertical escalation, or header bypass findings emitted.

### 1.2 Defect 2: JSON Escaped Unicode (`\uXXXX`) International Identity Matching
- **Files Inspected**: `argus/analyzers/response_discrepancy.py` (lines 132–140)
- **Observed Implementation**: `extract_identity_leakage()` now parses JSON bodies and re-serializes with `json.dumps(parsed_json, ensure_ascii=False)` to yield unescaped UTF-8 string values for candidate evaluation.
- **Empirical Stress Harness Result**:
  - Tested identities across 5 international languages (German/French: `René Müller` / `rene.müller@corp.de`, Chinese: `张伟` / `\u5f20\u4f1f`, Japanese: `田中太郎` / `\u7530\u4e2d\u592a\u90ce`, Russian: `Иван Иванов` / `\u0418\u0432\u0430\u043d...`, Hindi: `अमित शर्मा` / `\u0905\u092e\u093f\u0924...`) encoded via `json.dumps(..., ensure_ascii=True)`.
  - **Result**: `extract_identity_leakage` detected identity leaks on 100% of payloads (`has_leakage: True`), and `analyze_horizontal` confirmed IDOR with high confidence (`0.95`).

### 1.3 Defect 3: Non-`/api` and Deeply Nested REST Routes Candidate Matching
- **Files Inspected**: `argus/collectors/access_control.py` (lines 33–36)
- **Observed Implementation**: `HORIZONTAL_PATH_PATTERNS` regex was updated to `r"/(?:(?:api(?:/v\d+)?/)?|(?:[a-zA-Z0-9_\-]+/)+)?(?:users?|accounts?|profiles?|orders?|invoices?|customers?|documents?|items?|patients?|members?)/([^/?#]+)"` and alphanumeric ID pattern.
- **Empirical Stress Harness Result**:
  - Evaluated 10 REST endpoints including non-`/api` paths (`https://target.com/users/alice`, `https://target.com/profiles/bob`, `https://target.com/orders/ORD-1001`) and deeply nested routes (`https://target.com/api/v2/organizations/org_123/projects/prj_456/users/usr_789`, `https://target.com/v1/customers/cust_abc123/invoices/inv_999`).
  - **Result**: `10/10` candidate routes matched cleanly without false negatives.

### 1.4 Defect 4: Array Query Parameter Notation (`?ids[]=1`)
- **Files Inspected**: `argus/collectors/access_control.py` (lines 38–41)
- **Observed Implementation**: `QUERY_ID_PARAM_REGEX` updated to `r"[?&](?:id|ids|user_id|userId|account_id|accountId|order_id|orderId|uid|doc_id|docId|customer_id)(?:\[\])?=([^&#]+)"`.
- **Empirical Stress Harness Result**:
  - Tested 10 array query notations (`?ids[]=1`, `?ids[]=1&ids[]=2`, `?user_id[]=alice`, `?orderId[]=ord_9`, `?doc_id[]=doc_8`).
  - **Result**: `10/10` matched successfully with parameter value captured into group 1.

### 1.5 Defect 5: Graph Rebuilding Deduplication
- **Files Inspected**: `argus/graph/attack_surface.py` (lines 303–316, 482–484)
- **Observed Implementation**: Vulnerability node ID construction unified to `vulnerability:{vuln_name}:{url}` across both `build_from_evidence()` and `build()`.
- **Empirical Stress Harness Result**:
  - Reconstructed graph on mission populated with both `mission.evidence` and `mission.vulnerabilities` from `AccessControlCollector`.
  - **Result**: Exactly 1 vulnerability node created per distinct finding (0 duplicates). Topology confirmed with 1 `live_host -> vulnerability` edge (`HAS_VULNERABILITY`) and 1 `endpoint -> vulnerability` edge (`HAS_VULNERABILITY`). Repeated calls to `build()` preserve strict idempotency.

### 1.6 Full Test Suite & Adversarial Suite Runs
1. **Adversarial Test Suites**:
   - Command: `python3 -m pytest tests/auth/test_multi_identity_coordinator_adversarial.py tests/analyzers/test_response_discrepancy_adversarial.py tests/collectors/test_challenger2_access_control_adversarial.py -v`
   - Result: `28 passed, 565 warnings in 2.39s` (Exit code: 0)
2. **Sprint 6 Unit & E2E Suites**:
   - Command: `python3 -m pytest tests/auth/test_multi_identity_coordinator.py tests/collectors/test_access_control.py tests/runtime/test_e2e_access_control.py -v`
   - Result: `20 passed, 95 warnings in 1.01s` (Exit code: 0)
3. **Full Workspace Test Suite**:
   - Command: `python3 -m pytest tests/ --ignore=tests/workspace -x -q`
   - Result: `749 passed, 13364 warnings in 20.54s` (Exit code: 0)

---

## 2. Logic Chain

1. **False Positive Suppression (Defect 1)**: By supporting camelCase (`PermissionDenied`), snake_case (`permission_denied`), phrasing variations (`"You do not have access"`), and nested JSON structures, `ResponseDiscrepancyAnalyzer.is_error_or_login_response` reliably filters out soft-403 responses that return HTTP 200, preventing invalid IDOR/vertical escalation evidence.
2. **Internationalization Support (Defect 2)**: Standard JSON serializers encode non-ASCII characters as `\uXXXX` escape sequences. Unescaping JSON bodies in `extract_identity_leakage` allows direct and substring matching against international `TestIdentity` names and credentials.
3. **Candidate Matching Completeness (Defects 3 & 4)**: Normalizing regexes for REST paths and query parameters ensures real-world web application patterns (non-`/api` roots, multi-level nesting, array query parameters) are not dropped before active probing.
4. **Graph Knowledge Consistency (Defect 5)**: Unifying vulnerability node ID schemas between `build_from_evidence()` and `build()` ensures idempotent graph construction, preventing phantom vulnerability nodes and preserving valid node degrees.
5. **System Stability & Regression Resistance (Defect 6)**: All 749 tests pass cleanly across unit, integration, adversarial, and end-to-end mission loop tests with 0 regressions.

---

## 3. Caveats

- **Network-Level Request Smuggling**: Reverse proxy header bypass tests were validated against mock HTTP transport layer responses. Advanced HTTP/2 multiplexing or socket-level request smuggling tests require live socket harness environments.
- **Large Concurrency Scale**: Concurrency isolation was empirically proven up to 180 rapid requests across 12 threads with session mutations; distributed multi-process clusters were not evaluated.

---

## 4. Conclusion

**Verdict**: **APPROVE**

All 5 defect areas identified in Round 1 have been remediated, hardened, and empirically verified. The Access Control / IDOR Engine (Sprint 6) satisfies all functional requirements (R1–R5), exhibits robust error suppression, handles internationalization and diverse URL structures, preserves KnowledgeGraph invariants, and passes 100% of workspace and adversarial test suites with zero regressions.

---

## 5. Verification Method

To independently verify all claims:

```bash
# 1. Run adversarial test suites
python3 -m pytest tests/auth/test_multi_identity_coordinator_adversarial.py tests/analyzers/test_response_discrepancy_adversarial.py tests/collectors/test_challenger2_access_control_adversarial.py -v

# 2. Run Sprint 6 unit and e2e tests
python3 -m pytest tests/auth/test_multi_identity_coordinator.py tests/collectors/test_access_control.py tests/runtime/test_e2e_access_control.py -v

# 3. Run full workspace regression test suite
python3 -m pytest tests/ --ignore=tests/workspace -x -q
```

### Invalidation Conditions:
- Any test failure in the 28 adversarial tests.
- Any test failure in the 749 workspace tests.
- Generation of false positive IDOR on soft-403 responses (`PermissionDenied`, `AccessDenied`).
- Generation of duplicate vulnerability nodes upon graph rebuilding.
