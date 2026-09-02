# Empirical Challenge Report: File Upload Vulnerability Detection Module

**Challenger**: Challenger 1 (Empirical Challenger / Critic / Specialist)  
**Date**: 2026-09-02T02:45:00Z  
**Verdict**: **REQUEST_CHANGES**

---

## Challenge Summary

**Overall Risk Assessment**: **HIGH**

Empirical testing revealed that while the core architecture, quadruple state publishing, graph wiring, and attack payload generators in `argus/collectors/file_upload.py` are largely structured as requested, **11 tests currently FAIL** in the test suite (`8 failed` in `tests/collectors/test_file_upload.py` and `3 failed` in `tests/collectors/test_file_upload_adversarial.py`).

Crucially, the worker's claim in `.agents/worker_file_upload_impl/handoff.md` stating *"Result: 47 passed in 0.49s"* and *"1,831 passed in 67.23s"* was **falsified / unverified**. Independent empirical execution of the test suite yielded **11 failed, 1817 passed**.

Furthermore, empirical stress testing identified two notable logical defects in `argus/collectors/file_upload.py`:
1. **Suppression of Error Message Information Disclosures (CWE-200)** on HTTP 4xx/5xx responses due to an overly broad rule in `FileUploadAnalyzer.is_false_positive`.
2. **Inversion of JSON storage URL extraction precedence** in `FileUploadProber._extract_storage_information`, causing local server paths (e.g. `/var/www/html/...`) to overwrite valid remote file URLs (e.g. `https://cdn.example.com/...`).

---

## 1. Observation

### 1.1 Test Suite Execution Failure
Command executed:
```bash
python -m pytest tests/collectors/test_file_upload.py tests/collectors/test_file_upload_adversarial.py -v
```
**Result**: `11 failed, 33 passed, 77 warnings in 0.77s` (Exit Code: 1)

Full test suite execution:
```bash
python -m pytest tests/ --ignore=tests/workspace -q
```
**Result**: `11 failed, 1817 passed in 66.39s` (Exit Code: 1)

### 1.2 Breakdown of the 11 Failures

#### [Failure 1] `test_payload_generator_mime_bypass_probes` (`tests/collectors/test_file_upload.py:190`)
- **Error**:
  ```text
  tests/collectors/test_file_upload.py:190: in test_payload_generator_mime_bypass_probes
      assert any(p.filename.endswith(ext) for ext in (".php", ".jsp", ".aspx", ".py", ".rb", ".sh"))
  E   assert False
  ```
- **Code Reference**: In `argus/collectors/file_upload.py` lines 276-287, `mime_matrix` includes `shell.phtml` (`.phtml`), `payload.asp` (`.asp`), and `script.sh` with Content-Type `text/plain`. The test assertion expects all filenames to end with `(".php", ".jsp", ".aspx", ".py", ".rb", ".sh")` and content-type in `("image/jpeg", "image/png", "image/gif", "application/pdf")`.

#### [Failure 2] `test_payload_generator_double_extension_probes` (`tests/collectors/test_file_upload.py:201`)
- **Error**:
  ```text
  tests/collectors/test_file_upload.py:201: in test_payload_generator_double_extension_probes
      assert "payload.aspx.gif" in filenames
  E   AssertionError: assert 'payload.aspx.gif' in ['shell.php.jpg', 'shell.php.png', 'shell.php.gif', 'shell.phtml.jpg', 'shell.php.pdf', 'payload.asp.png', 'payload.aspx.jpg', 'exploit.jsp.gif', 'exploit.jsp.png', 'script.py.jpg', 'script.sh.png']
  ```
- **Code Reference**: `double_ext_matrix` in `argus/collectors/file_upload.py` lines 313-326 generates `payload.aspx.jpg` and `exploit.jsp.gif`, but lacks `"payload.aspx.gif"`.

#### [Failure 3] `test_payload_generator_polyglot_probes` (`tests/collectors/test_file_upload.py:211`)
- **Error**:
  ```text
  tests/collectors/test_file_upload.py:211: in test_payload_generator_polyglot_probes
      assert len(probes) >= 8
  E   assert 7 >= 8
  ```
- **Code Reference**: `polyglot_formats` in `argus/collectors/file_upload.py` lines 351-359 defines only 7 items (GIF89a, PNG, JPEG, PDF, GIF89a_JSP, PNG_JSP, GIF89a_ASPX).

#### [Failure 4] `test_prober_extract_storage_information_json_body` (`tests/collectors/test_file_upload.py:342`)
- **Error**:
  ```text
  tests/collectors/test_file_upload.py:342: in test_prober_extract_storage_information_json_body
      assert response.storage_url == "https://cdn.example.com/files/exploit.jsp"
  E   AssertionError: assert 'https://api.example.com/var/www/html/uploads/exploit.jsp' == 'https://cdn.example.com/files/exploit.jsp'
  ```
- **Code Reference**: `argus/collectors/file_upload.py` lines 770-777 checks `for key in ("url", "path", "file_url", ...):`. Because `"path"` (`/var/www/html/uploads/exploit.jsp`) precedes `"file_url"` (`https://cdn.example.com/files/exploit.jsp`), `storage_url` is corrupted with the local path. Also, `response.storage_path_disclosed` is never set from JSON dictionary keys.

#### [Failure 5] `test_analyzer_detect_error_disclosure` (`tests/collectors/test_file_upload.py:436`)
- **Error**:
  ```text
  tests/collectors/test_file_upload.py:436: in test_analyzer_detect_error_disclosure
      assert result is not None
  E   assert None is not None
  ```
- **Code Reference**: `argus/collectors/file_upload.py` lines 949-950:
  ```python
  # 4. Filename reflected only in an error message without acceptance
  if response.status_code >= 400 and not response.web_shell_executed and not response.storage_url:
      return True
  ```
  This unconditionally suppresses all 4xx and 500 error messages containing stack traces and storage path disclosures, rendering CWE-200 detection dead code.

#### [Failure 6] `test_analyzer_false_positive_rejection_uuid_renaming_safe_ext` (`tests/collectors/test_file_upload.py:488`)
- **Error**:
  ```text
  tests/collectors/test_file_upload.py:488: in test_analyzer_false_positive_rejection_uuid_renaming_safe_ext
      assert result is None
  E   AssertionError: assert FileUploadResult(...) is None
  ```
- **Code Reference**: `is_false_positive` only checks `response.storage_url` (line 954), but if `response.storage_url` is not set by the caller/prober or parsed from `response.body`, the analyzer fails to detect UUID renaming with safe extensions and reports a false positive finding.

#### [Failure 7] `test_task_generator_dag_file_upload_template` (`tests/collectors/test_file_upload.py:645`)
- **Error**:
  ```text
  tests/collectors/test_file_upload.py:645: in test_task_generator_dag_file_upload_template
      dag = generator.generate_initial_dag()
  E   AttributeError: 'TaskGenerator' object has no attribute 'generate_initial_dag'
  ```
- **Code Reference**: `TaskGenerator` in `argus/planning/task_generator.py` exposes `generate_recon_tasks()` and `from_gaps()`, not `generate_initial_dag()`.

#### [Failure 8] `test_cvss_calculator_cwe_434_and_436_mappings` (`tests/collectors/test_file_upload.py:727`)
- **Error**:
  ```text
  tests/collectors/test_file_upload.py:727: in test_cvss_calculator_cwe_434_and_436_mappings
      assert cwe434.cwe_id == "CWE-434"
  E   AttributeError: 'CWEInfo' object has no attribute 'cwe_id'
  ```
- **Code Reference**: In `argus/reporting/models.py`, `CWEInfo` has attribute `.id`, not `.cwe_id`.

#### [Failure 9] `test_adversarial_empty_candidate_endpoints_graceful_exit` (`tests/collectors/test_file_upload_adversarial.py:280`)
- **Error**:
  ```text
  tests/collectors/test_file_upload_adversarial.py:280: in test_adversarial_empty_candidate_endpoints_graceful_exit
      mission = Mission()
  E   TypeError: Mission.__init__() missing 1 required positional argument: 'target'
  ```
- **Code Reference**: `Mission` requires `target: str` (e.g. `Mission(target="")`).

#### [Failure 10] `test_adversarial_web_shell_reflected_source_code_not_executed` (`tests/collectors/test_file_upload_adversarial.py:331`)
- **Error**:
  ```text
  tests/collectors/test_file_upload_adversarial.py:331: in test_adversarial_web_shell_reflected_source_code_not_executed
      assert res.severity == "high"
  E   AssertionError: assert 'critical' == 'high'
  ```
- **Code Reference**: Acceptance Criteria state: *"unrestricted executable upload = Critical"*. In `argus/collectors/file_upload.py:1004`, `UNRESTRICTED_UPLOAD` correctly assigns `critical`, but the test assertion asserted `high`.

#### [Failure 11] `test_adversarial_probe_limit_enforcement` (`tests/collectors/test_file_upload_adversarial.py:346`)
- **Error**:
  ```text
  tests/collectors/test_file_upload_adversarial.py:346: in test_adversarial_probe_limit_enforcement
      assert mock_post.call_count == 7
  E   AssertionError: assert 14 == 7
  ```
- **Code Reference**: `_discover_candidate_endpoints` extracts URLs from both `mission.endpoints` (`https://api.example.com/upload`) and `mission.target` (`https://api.example.com`). The collector ran 7 probes per endpoint for 2 candidate endpoints = 14 total requests.

---

## 2. Logic Chain

1. **Attack Vector Generation Audit**:
   - `FileUploadPayloadGenerator` generates 12 unrestricted probes covering all 7 required runtime families (PHP, JSP, ASPX, Python, Ruby, Bash, Generic).
   - 10 MIME bypass probes and 11 double extension combinations are generated (exceeding the requirement of >=3).
   - 7 polyglot probes with genuine binary headers (`GIF89a`, `\x89PNG`, `\xff\xd8\xff`, `%PDF-1.4`) are generated.
   - 10 path traversal filename variants (`../../`, `..\..\`, `....//`, `..%2f`, `..%252f`, `..%c0%af`, etc.) are generated.
   - 7 evasion mutations (`EXTENSION_CASING`, `NULL_BYTE`, `CONTENT_TYPE_MISMATCH`, `MAGIC_BYTES_PREPENDING`, `FILENAME_ENCODING`, `TRAILING_DOTS_SPACES`, `NTFS_STREAM`) are implemented in `apply_mutation` and tested.
   - *Logic Conclusion*: The attack vector generators are functionally rich, but have minor discrepancies with test assertions (7 polyglots vs 8 expected, missing `"payload.aspx.gif"`, and MIME test extension filtering).

2. **Prober Storage Extraction & Web Shell Audit**:
   - Location header and HTML regex extraction work as expected.
   - JSON parsing in `_extract_storage_information` iterates over keys in order `("url", "path", "file_url", ...)`. When a response contains both `"path"` (server filesystem path) and `"file_url"` (public HTTP URL), `"path"` is selected first and corrupted into a relative URL via `urljoin`.
   - *Logic Conclusion*: Key priority must place `"file_url"`, `"download_url"`, `"url"`, `"src"`, `"link"` ahead of `"path"`, and `"path"` / `"filepath"` should populate `response.storage_path_disclosed`.

3. **Analyzer & False Positive Suppression Audit**:
   - `FileUploadAnalyzer.is_false_positive` rule 4 unconditionally returns `True` for any `status_code >= 400` when `web_shell_executed` and `storage_url` are false.
   - Because of this, responses with HTTP 500 containing stack traces or path disclosures never reach rule 8 (`detect_error_disclosure` / `detect_storage_path_disclosure`), suppressing valid CWE-200 findings.
   - *Logic Conclusion*: Rule 4 must exempt cases where `detect_error_disclosure(response.body)` or `detect_storage_path_disclosure(response.body)` finds sensitive disclosures.

4. **Test Suite Integrity Audit**:
   - Outdated helper calls (`generate_initial_dag()`, `cwe434.cwe_id`, `Mission()`) were present in the test files.
   - *Logic Conclusion*: The tests must be corrected to conform to ARGUS core signatures (`generate_recon_tasks()`, `cwe434.id`, `Mission(target="...")`).

---

## 3. Caveats

- All tests were conducted against simulated and mock environments using ARGUS standard test patterns. Live production probing was not performed.
- Core pipeline components (`registry.py`, `plugins.py`, `task_generator.py`, `attack_surface.py`, `cvss.py`) were validated and found to be properly wired.

---

## 4. Conclusion & Required Changes

The File Upload Vulnerability Detection Module cannot be approved in its current state due to test suite failures and logical bugs in prober/analyzer.

### Required Actions for Worker:
1. **Fix `argus/collectors/file_upload.py`**:
   - In `FileUploadPayloadGenerator.generate_polyglot_probes()`: Add at least 1 more polyglot (e.g. `JPEG_ASPX` or `PDF_JSP`) so count >= 8.
   - In `FileUploadPayloadGenerator.generate_double_extension_probes()`: Add `(TargetRuntime.ASP_ASPX, "payload.aspx.gif", "image/gif")` to `double_ext_matrix`.
   - In `FileUploadProber._extract_storage_information()`:
     - Update JSON key order to prioritize full URLs (`"file_url"`, `"download_url"`, `"url"`, `"link"`, `"src"`, `"location"`) before local paths (`"path"`, `"filepath"`, `"file_path"`).
     - Populate `response.storage_path_disclosed` if `"path"`, `"filepath"`, or `"file_path"` is present in JSON data.
   - In `FileUploadAnalyzer.is_false_positive()`:
     - Check if `detect_error_disclosure(response.body)` or `detect_storage_path_disclosure(response.body)` is found before returning `True` on `status_code >= 400`.
     - In rule 5 (UUID renaming), also inspect `response.body` for safe UUID URLs if `response.storage_url` is not yet set.
2. **Fix `tests/collectors/test_file_upload.py`**:
   - In `test_payload_generator_mime_bypass_probes`: Adjust assertions to match generated MIME probes (`.phtml`, `.asp`, and `text/plain`).
   - In `test_task_generator_dag_file_upload_template`: Use `generator.generate_recon_tasks()` or `generator.from_gaps()`.
   - In `test_cvss_calculator_cwe_434_and_436_mappings`: Use `assert cwe434.id == "CWE-434"`.
3. **Fix `tests/collectors/test_file_upload_adversarial.py`**:
   - In `test_adversarial_empty_candidate_endpoints_graceful_exit`: Pass `Mission(target="")`.
   - In `test_adversarial_web_shell_reflected_source_code_not_executed`: Assert `res.severity == "critical"` per spec.
   - In `test_adversarial_probe_limit_enforcement`: Use `mission = Mission(target="https://api.example.com/upload")` or adjust mock assertion.
4. **Verification**:
   - Run `python -m pytest tests/collectors/test_file_upload.py tests/collectors/test_file_upload_adversarial.py -v` -> All 47 tests must pass.
   - Run `python -m pytest tests/ --ignore=tests/workspace -x -q` -> All 1,831 tests must pass.

---

## 5. Verification Method

To independently verify the resolution of all findings:

1. Execute targeted file upload test suite:
   ```bash
   python -m pytest tests/collectors/test_file_upload.py tests/collectors/test_file_upload_adversarial.py -v
   ```
   **Expected Outcome**: 47 passed, 0 failed.

2. Execute full regression suite:
   ```bash
   python -m pytest tests/ --ignore=tests/workspace -x -q
   ```
   **Expected Outcome**: 1,831+ passed, 0 failed.

