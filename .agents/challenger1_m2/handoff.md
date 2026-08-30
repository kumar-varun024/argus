# Milestone 2 Adversarial Challenge Report: Cross-Site Scripting (XSS) Detection Engine

**Verdict**: **REQUEST_CHANGES**

---

## 1. Observation

Adversarial stress testing and empirical validation were performed on `XSSAnalyzer`, `XSSPayloadGenerator`, and `XSSCollector` (`argus/collectors/xss.py`) and associated test suites (`tests/collectors/test_xss.py`, `tests/collectors/test_xss_adversarial.py`).

### Existing Test Suite Execution:
1. `python -m pytest tests/collectors/test_xss.py tests/collectors/test_xss_adversarial.py -v`
   - **Result**: 25 passed in 0.66s.
2. `python -m pytest tests/ --ignore=tests/workspace -x -q`
   - **Result**: 950 passed in 31.87s (0 regressions against existing test baselines).

### Empirical Adversarial Test Findings:

#### Finding 1: Non-HTML Content-Type `application/xml` and `text/xml` are NOT rejected
- **File**: `argus/collectors/xss.py`, Lines 279-291 (`NON_HTML_CONTENT_TYPES`) and Lines 418-422, 485-489 (`analyze_reflected`, `analyze_stored`).
- **Verbatim Code**:
  ```python
  NON_HTML_CONTENT_TYPES = [
      "application/json",
      "text/plain",
      "application/pdf",
      "image/png",
      "image/jpeg",
      "image/gif",
      "image/webp",
      "application/octet-stream",
      "application/zip",
      "application/x-tar",
      "application/gzip",
  ]
  ```
- **Reproduction**:
  ```python
  from argus.collectors.xss import XSSAnalyzer
  from argus.http.client import HttpResponse
  analyzer = XSSAnalyzer()
  canary = "test1234"
  payload = f"<script>alert(\"{canary}\")</script>"
  resp = HttpResponse(
      success=True, status_code=200,
      raw_body=f"<xml><data>{payload}</data></xml>",
      body=f"<xml><data>{payload}</data></xml>",
      headers={"Content-Type": "application/xml"},
      url="http://target.test/api.xml"
  )
  res = analyzer.analyze_reflected(resp, canary, payload)
  # Observed Output: {'xss_type': 'reflected', 'context': 'script_string_double', ...}
  # Expected Output: None (Suppressed as non-HTML content type)
  ```

#### Finding 2: False Positive in `is_properly_escaped` on Entity-Encoded Quotes in Event Handler Test Payloads
- **File**: `argus/collectors/xss.py`, Lines 338-339.
- **Verbatim Code**:
  ```python
  has_raw_event = bool(re.search(r'(?<!&quot;)(?<!&#34;)(?<!&#x22;)(?<!&#39;)(?<!&#x27;)["\']\s*(?:on\w+|autofocus)\s*=\s*["\']?', before_canary, re.IGNORECASE))
  has_raw_unquoted_event = bool(re.search(r'\s+(?:on\w+|autofocus)\s*=\s*[^"\'\s>]+', before_canary, re.IGNORECASE))
  ```
- **Reproduction**:
  ```python
  analyzer = XSSAnalyzer()
  canary = "canary11"
  body = f'<html><body><input value="&quot; onfocus=&quot;alert(\'{canary}\')&quot;"></body></html>'
  print(analyzer.is_properly_escaped(body, canary))
  # Observed Output: False (Vulnerable)
  # Expected Output: True (Safely entity-encoded attribute quotes)
  ```
- **Cause**: In `has_raw_unquoted_event`, ` onfocus=&quot;alert('` matches because `&` is not in `[^"\'\s>]+`. `has_raw_event` also misses when leading whitespace separates the entity quote.

#### Finding 3: Hex Entity Encodings with Leading Zeros (e.g. `&#x03c;`) Not Recognized
- **File**: `argus/collectors/xss.py`, Line 272 & Line 314.
- **Verbatim Code**:
  ```python
  tag_matches = list(re.finditer(
      r"(&(?:lt|#60|#060|#x3c|#x3C);|<)(/?)([a-zA-Z0-9]+)",
      before_canary,
      re.IGNORECASE,
  ))
  ```
- **Reproduction**:
  ```python
  analyzer = XSSAnalyzer()
  canary = "canary7"
  body = f"<div>&#x003c;script&#x003e;/*{canary}*/&#x003c;/script&#x003e;</div>"
  print(analyzer.is_properly_escaped(body, canary))
  # Observed Output: False
  # Expected Output: True
  ```

#### Finding 4: Stray keyword argument `Ivory` in `XSSCollector.collect`
- **File**: `argus/collectors/xss.py`, Line 849.
- **Verbatim Code**:
  ```python
  ev = self._create_evidence_and_update_state(
      mission=mission,
      target_url=orig_url,
      base_url=base_url,
      param=field,
      param_type="post_form",
      payload=payload,
      status_code=getattr(resp, "status_code", 200) or 200,
      analysis=analysis,
  Ivory=None if False else None,
  )
  ```

---

## 2. Logic Chain

1. **Requirement Check**:
   The sprint specification explicitly requires robust false-positive rejection for entity encodings (`&lt;script&gt;`, numeric entities `&#60;`, hex entities `&#x3c;`, quote entities `&quot;`, `&#39;`, `&#x27;`) and non-HTML content-types (`application/json`, `text/plain`, `application/xml`).
2. **Analysis of Finding 1**:
   Web endpoints serving `application/xml` or `text/xml` responses containing echoed parameters (such as SOAP or REST XML endpoints) are not rendered as HTML script contexts by browsers. Because `application/xml` and `text/xml` are missing from `NON_HTML_CONTENT_TYPES`, the analyzer flags benign XML responses as high-severity XSS vulnerabilities.
3. **Analysis of Finding 2**:
   When defensive web applications entity-encode user input in attribute contexts (replacing `"` with `&quot;` or `&#34;` or `&#39;`), test payloads containing event handlers like `&quot; onfocus=&quot;alert('canary')&quot;` are erroneously flagged as unquoted event handler injections by `has_raw_unquoted_event`.
4. **Analysis of Finding 3**:
   Standard HTML parsers decode hex entities with arbitrary leading zeros (`&#x03c;`, `&#x003c;`). The current regex pattern strictly checks for `#x3c` and `#x3C` without quantifier support for leading zeros.
5. **Analysis of Finding 4**:
   Line 849 has a stray indentation and keyword argument `Ivory=None if False else None` left over during refactoring.

---

## 3. Caveats

- DOM-based client-side JavaScript AST execution is out of scope for `XSSCollector` (handled separately by `JavaScriptCollector`).
- Out-of-band / blind XSS callback interaction (e.g. XSS hunter callbacks) is not part of Sprint 10 requirements.

---

## 4. Conclusion

While the core architecture (`XSSContext`, `XSSPayloadGenerator`, `_HTMLContextDetectorParser`, and `XSSCollector` multi-vector fuzzing) is well-structured and all 950 baseline repository tests pass, the empirical stress test uncovered four concrete issues (specifically XML content-type false positives, quote entity false positives in event handlers, leading zero hex entity support, and code cleanup).

**Verdict**: **REQUEST_CHANGES**

### Actionable Remediation Steps for Worker:

1. **Update `NON_HTML_CONTENT_TYPES`** in `argus/collectors/xss.py` to include `"application/xml"`, `"text/xml"`, `"application/javascript"`, `"text/javascript"`, and `"text/css"`.
2. **Refine `is_properly_escaped`** in `argus/collectors/xss.py`:
   - Support leading zeros in entity patterns: `r"&(?:lt|#0*60|#x0*3c);"` and `r"&(?:gt|#0*62|#x0*3e);"` with `re.IGNORECASE`.
   - Prevent `has_raw_unquoted_event` from matching when the attribute value begins with entity-encoded quotes (`&quot;`, `&#34;`, `&#x22;`, `&apos;`, `&#39;`, `&#x27;`) or contains `&`.
3. **Remove stray keyword argument** `Ivory=None if False else None` at line 849 of `argus/collectors/xss.py`.
4. **Add adversarial unit tests** in `tests/collectors/test_xss_adversarial.py` asserting `application/xml` rejection and quote entity event handler false positive suppression.

---

## 5. Verification Method

Run the following test harness after applying fixes:

```bash
# Run existing test suite
python -m pytest tests/collectors/test_xss.py tests/collectors/test_xss_adversarial.py -v

# Run full repository regression suite
python -m pytest tests/ --ignore=tests/workspace -x -q
```

And verify the XML and quote entity test cases via Python:
```python
from argus.collectors.xss import XSSAnalyzer
from argus.http.client import HttpResponse

analyzer = XSSAnalyzer()
canary = "test123"

# 1. Verify XML rejection
resp_xml = HttpResponse(
    success=True, status_code=200,
    raw_body=f"<xml><data><script>alert('{canary}')</script></data></xml>",
    body=f"<xml><data><script>alert('{canary}')</script></data></xml>",
    headers={"Content-Type": "application/xml"},
    url="http://target.test/api.xml"
)
assert analyzer.analyze_reflected(resp_xml, canary, f"<script>alert('{canary}')</script>") is None

# 2. Verify escaped quote event suppression
body_quote = f'<html><body><input value="&quot; onfocus=&quot;alert(\'{canary}\')&quot;"></body></html>'
assert analyzer.is_properly_escaped(body_quote, canary) is True

# 3. Verify leading zero hex entity suppression
body_hex = f"<div>&#x003c;script&#x003e;/*{canary}*/&#x003c;/script&#x003e;</div>"
assert analyzer.is_properly_escaped(body_hex, canary) is True
```
