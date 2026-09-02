# Empirical Challenger 1 Handoff Report — CORS & HTTP Security Header Audit Module

**Verdict**: `REQUEST_CHANGES`

---

## 1. Observation

Empirical testing was executed across `CORSSecurityCollector`, `CORSProber`, `CORSAnalyzer`, `CORSMutationGenerator`, and `HTTPHeaderAuditor` using the test suite `tests/collectors/test_cors_headers.py` (39 passing baseline unit tests) and a dedicated 37-scenario adversarial stress suite in `tests/collectors/test_cors_headers_adversarial.py`.

The stress harness uncovered **4 concrete defects** (2 High/Critical, 1 Medium, 1 Low):

### Defect 1 (HIGH — Unhandled Crash on Malformed Candidate Endpoint Ports)
- **File**: `argus/collectors/cors_headers.py:253`
- **Code**:
  ```python
  def _extract_host_parts(self, target_url: str) -> Tuple[str, str, str]:
      parsed = urllib.parse.urlparse(target_url)
      scheme = parsed.scheme or "https"
      host = parsed.hostname or "example.com"
      port = f":{parsed.port}" if parsed.port else ""
      return scheme, host, port
  ```
- **Observed Error**:
  When `target_url` contains a malformed or fuzz port (e.g., `https://target.com:abc/invalid/port` or discovered endpoints from web crawl with non-integer ports), accessing `parsed.port` raises:
  ```text
  ValueError: Port could not be cast to integer value as 'abc'
  ```
- **Impact**: The exception is unhandled and propagates out of `CORSPayloadGenerator` through `CORSSecurityCollector.collect()`, crashing the collector and terminating scanning for all remaining discovered endpoints.

---

### Defect 2 (CRITICAL — False Negative / Vulnerability Drop on Whitespaced `Access-Control-Allow-Credentials`)
- **File**: `argus/collectors/cors_headers.py:178`
- **Code**:
  ```python
  @property
  def allow_credentials(self) -> bool:
      return self.get_header("access-control-allow-credentials").lower() == "true"
  ```
- **Observed Behavior**:
  When a web server returns `Access-Control-Allow-Credentials: true ` (with trailing or leading whitespace, standard in many HTTP servers/proxies), `get_header("access-control-allow-credentials").lower()` returns `" true "`, which evaluates to `False`.
- **Impact**:
  1. For `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true `, `CORSAnalyzer.evaluate_probe` falsely treats the response as an unauthenticated public wildcard and returns `None` (suppressed as a false positive). A **CRITICAL (CVSS 9.8) vulnerability is silently dropped**.
  2. For origin reflection and null origin findings, severity is downgraded from `HIGH` to `MEDIUM` and `allow_credentials` is falsely marked `False`.

---

### Defect 3 (MEDIUM — HSTS Low Max-Age Bypass on Quoted Header Values)
- **File**: `argus/collectors/cors_headers.py:1133`
- **Code**:
  ```python
  hsts_lower = hsts.lower()
  max_age_match = re.search(r"max-age\s*=\s*(\d+)", hsts_lower)
  ```
- **Observed Behavior**:
  When a server formats HSTS with quotes around the max-age directive (e.g., `Strict-Transport-Security: max-age="300"; includeSubDomains`), `re.search(r"max-age\s*=\s*(\d+)", hsts_lower)` returns `None`.
- **Impact**: Insecure HSTS headers with low max-age (< 1 year) formatted with quotes completely bypass the `security-header-weak-hsts-low-max-age` audit check.

---

### Defect 4 (LOW — Permissions-Policy Wildcard Detection Fails on Parenthesized W3C Syntax)
- **File**: `argus/collectors/cors_headers.py:1350`
- **Code**:
  ```python
  if re.search(r"(camera|microphone|geolocation|payment)\s*=\s*\*", perm_lower):
  ```
- **Observed Behavior**:
  In modern W3C Permissions Policy / Structured Header format (e.g., `Permissions-Policy: camera=(*), microphone=(*)`), the regex fails to match because the wildcard is parenthesized.
- **Impact**: Permissions-Policy wildcards configured as `camera=(*)` are not flagged by `security-header-weak-permissions-policy`.

---

## 2. Logic Chain

1. **Host Extraction Robustness**: Discovered candidate endpoints originate from multiple unverified inputs (katana crawl, network reconnaissance, mission target, user input). Because `urllib.parse.urlparse` dynamically attempts integer conversion upon accessing `.port`, any non-numeric port raises `ValueError`. Wrapping hostname/port resolution in `try...except` guarantees crash immunity.
2. **HTTP Header Value Sanitization**: RFC 7230 §3.2.4 allows optional whitespace (`OWS`) around header field values. Comparing raw strings without `.strip()` causes boolean predicate failures on valid HTTP responses, directly triggering severe false negatives (e.g. dropping CVSS 9.8 wildcard with credentials).
3. **Header Directive Regex Precision**: Quoted values and structured header parentheses are common in production web applications. Regex matchers for `max-age` and `Permissions-Policy` must account for optional quotes and parentheses to prevent bypasses.

---

## 3. Caveats

- In accordance with the Review-Only constraint for Challenger roles, no implementation files were modified directly.
- The 37-test adversarial suite was saved to `tests/collectors/test_cors_headers_adversarial.py` to allow the worker and orchestrator to reproduce the failures directly.
- Note: `tests/graph/test_cors_graph_pipeline_adversarial.py` contains a pre-existing collection import error (`from argus.planning.gap_analysis import IdentifiedGap` instead of `CoverageGap`), which was isolated during repository-wide regression validation.

---

## 4. Conclusion

**Verdict: `REQUEST_CHANGES`**

The implementation is well-architected and features comprehensive coverage, but requires targeted fixes for the 4 identified issues before production approval:

### Required Remediations:

1. **Fix `_extract_host_parts` in `argus/collectors/cors_headers.py:250-255`**:
   ```python
   def _extract_host_parts(self, target_url: str) -> Tuple[str, str, str]:
       """Extracts scheme, hostname, and port from target URL."""
       try:
           parsed = urllib.parse.urlparse(target_url)
           scheme = parsed.scheme or "https"
           try:
               host = parsed.hostname or "example.com"
           except Exception:
               host = "example.com"
           try:
               port = f":{parsed.port}" if parsed.port else ""
           except Exception:
               port = ""
           return scheme, host, port
       except Exception:
           return "https", "example.com", ""
   ```

2. **Fix `allow_credentials` in `argus/collectors/cors_headers.py:178`**:
   ```python
   @property
   def allow_credentials(self) -> bool:
       return self.get_header("access-control-allow-credentials").strip().lower() == "true"
   ```

3. **Fix HSTS regex in `argus/collectors/cors_headers.py:1133`**:
   ```python
   max_age_match = re.search(r"max-age\s*=\s*[\"']?(\d+)[\"']?", hsts_lower)
   ```

4. **Fix Permissions-Policy regex in `argus/collectors/cors_headers.py:1350`**:
   ```python
   if re.search(r"(camera|microphone|geolocation|payment)\s*=\s*(\*|\(\s*\*|\(\s*\"\*\"\s*\))", perm_lower):
   ```

---

## 5. Verification Method

To independently reproduce and verify all 4 findings:

```bash
# 1. Run the empirical adversarial test suite
python -m pytest tests/collectors/test_cors_headers_adversarial.py -v

# 2. Run minimal reproduction script for Defect 1 (Crash on Malformed Port)
python -c "
from argus.collectors.cors_headers import CORSSecurityCollector
from argus.runtime.mission import Mission
collector = CORSSecurityCollector()
m = Mission(target='example.com')
m.endpoints = ['https://target.com:abc/invalid']
collector.collect(m)
"

# 3. Run minimal reproduction script for Defect 2 (Wildcard + Creds Dropped on Whitespace)
python -c "
from argus.collectors.cors_headers import CORSProbeResponse, CORSAnalyzer, CORSProbe
resp = CORSProbeResponse(
    status_code=200,
    headers={'access-control-allow-origin': '*', 'access-control-allow-credentials': ' true '}
)
analyzer = CORSAnalyzer()
probe = CORSProbe(probe_id='p1', target_url='https://target.com/api', origin='https://evil.com')
res = analyzer.evaluate_probe(probe, resp, 'https://target.com/api')
print('Evaluation result (Expected finding, Got None):', res)
"

# 4. Run minimal reproduction script for Defect 3 (Quoted HSTS max-age)
python -c "
from argus.collectors.cors_headers import CORSProbeResponse, HTTPHeaderAuditor
resp = CORSProbeResponse(status_code=200, headers={'strict-transport-security': 'max-age=\"300\"; includeSubDomains'})
findings = HTTPHeaderAuditor().audit_headers('https://secure.example.com/', resp)
hsts_findings = [f for f in findings if f.header_name == 'Strict-Transport-Security']
print('HSTS weak max-age findings (Expected 1, Got 0):', len(hsts_findings))
"
```
