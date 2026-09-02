# Original User Request

## 2026-09-02T01:52:21+05:30

Build the File Upload Vulnerability Detection Module for the ARGUS authorized defensive security assessment platform. This module actively discovers and validates file upload vulnerabilities across discovered endpoints and live hosts. All testing targets user-owned infrastructure with explicit authorization.

Working directory: /home/varun/argus
Integrity mode: benchmark

## Requirements

### R1. File Upload Security Collector & Prober
Implement an active collector inheriting from `BaseCollector` that uses `AuthenticatedHttpClient` to probe file upload endpoints by sending crafted multipart/form-data requests with malicious file payloads and analyzing server responses for acceptance, execution, or storage of dangerous file types.

### R2. Multi-Vector Upload Detection Modes
1. Unrestricted File Upload: Detect endpoints that accept executable file types (.php, .jsp, .asp, .aspx, .py, .rb, .sh, .exe) without validation.
2. MIME Type Bypass: Detect servers that validate only Content-Type headers but not file content (e.g., uploading PHP with image/jpeg Content-Type).
3. Double Extension Bypass: Detect acceptance of files like `shell.php.jpg`, `payload.asp.png`, `exploit.jsp.gif`.
4. Polyglot File Detection: Detect acceptance of files that are valid in multiple formats (e.g., GIF89a header + PHP code).
5. Path Traversal in Filenames: Detect acceptance of filenames containing `../`, `..\\`, or URL-encoded traversal sequences.
6. Web Shell Detection: Detect if uploaded files are accessible and executable via HTTP at predictable URLs.

### R3. Upload Response Analysis
Analyze server responses for:
- Successful upload indicators (200/201 with file URL, storage path disclosure)
- File content reflection (uploaded content accessible without transformation)
- Error message information disclosure (stack traces, path disclosure, technology fingerprinting)
- Content-Disposition and storage behavior analysis
- Antivirus/WAF bypass detection via response timing and error patterns

### R4. Mutation & Evasion Strategies
Include at least 5 distinct upload bypass strategies:
- Extension Casing Variations (.pHp, .PhP, .PHP)
- Null Byte Injection (shell.php%00.jpg, shell.php\x00.jpg)
- Content-Type Mismatch (executable content with benign MIME type)
- Magic Bytes Prepending (GIF89a, PNG header, JPEG SOI before payload)
- Filename Encoding Variations (URL-encoded, Unicode normalization, overlong UTF-8)

### R5. Pipeline Connectivity
Wire the collector into the TaskGenerator DAG after endpoint discovery. Register as an internal plugin in the tool registry. Confirmed findings must create HAS_VULNERABILITY edges on the attack surface graph. Map findings to CWE-434 (Unrestricted Upload) and CWE-436 (Interpretation Conflict).

### R6. Zero Regression & E2E Validation
All 1,784+ currently passing tests must continue to pass. Write at least 25 new tests covering upload detection modes, response analysis logic, false positive rejection, mutation strategies, and pipeline connectivity.
Write handoff to .agents/sprint26_file_upload/handoff.md.

## Acceptance Criteria

### Upload Detection
- [ ] When an endpoint accepts an executable file type without validation, Evidence is generated with Critical severity.
- [ ] MIME type bypass (Content-Type mismatch) is detected and generates a finding.
- [ ] Double extension bypass detection works for at least 3 extension combinations.
- [ ] Path traversal in filenames is detected when the server accepts traversal sequences.
- [ ] False positive rejection: legitimate image uploads with proper validation do NOT generate evidence.

### Response Analysis
- [ ] Storage path disclosure in upload responses is detected.
- [ ] Web shell accessibility check verifies uploaded file is reachable via HTTP.
- [ ] Severity calibration: unrestricted executable upload = Critical, MIME bypass = High, double extension = High, path traversal = High, missing validation on non-executable = Medium.

### Mutations
- [ ] At least 5 distinct upload bypass strategies implemented and tested.

### Pipeline
- [ ] Collector registered in registry.py and scheduled in TaskGenerator DAG.
- [ ] Confirmed findings create HAS_VULNERABILITY edges in the attack surface graph.
- [ ] CWE-434 mapped for upload findings, CWE-436 for interpretation conflicts in cvss.py.

### Regression
- [ ] python -m pytest tests/ --ignore=tests/workspace -x -q exits 0 (1,784+ passing, 0 regressions).
- [ ] At least 25 new tests added.
- [ ] Handoff written to .agents/sprint26_file_upload/handoff.md.

## Follow-up — 2026-09-02T02:19:05+05:30

Continue and complete the File Upload Vulnerability Detection Module for the ARGUS authorized defensive security assessment platform. A previous run was interrupted and left PARTIAL work. You must audit what exists, fix issues, and complete the remaining work.

Working directory: /home/varun/argus
Integrity mode: benchmark

## EXISTING PARTIAL STATE (AUDIT FIRST)

The following files were partially created by a prior interrupted run. READ THEM FIRST and fix any issues:

1. `argus/collectors/file_upload.py` — Collector exists but may be incomplete. Verify it follows the tripartite pattern (Collector + PayloadGenerator + Analyzer) used by other collectors like `argus/collectors/cache_security.py` and `argus/collectors/cors_security.py`.
2. `argus/reporting/cvss.py` — CWE-434 mapping already added. Verify CWE-436 is also present.
3. `argus/runtime/registry.py` — Entry exists as `file_upload_specialist`. May need alias updates.
4. `argus/runtime/plugins.py` — Fallback imports from WRONG path `argus.plugins.file_upload.agent`. Must be fixed to import from `argus.collectors.file_upload`.

## REMAINING WORK NEEDED

1. **Fix plugin fallback** in `argus/runtime/plugins.py` to import `FileUploadCollector` (or whatever the class name is) from `argus.collectors.file_upload`.
2. **Add DAG template** in `argus/planning/task_generator.py` — add `file_upload` entry to `_RECON_TEMPLATES` with dependency `["Discover API Endpoints"]`. Also add keyword matching in `_resolve_template_for_gap`.
3. **Add graph builder section** in `argus/graph/attack_surface.py` — add evidence processing for `file_upload` category creating HAS_VULNERABILITY edges.
4. **Create test files**:
   - `tests/collectors/test_file_upload.py` — at least 15 unit tests
   - `tests/collectors/test_file_upload_adversarial.py` — at least 10 adversarial tests
5. **Verify the collector** follows the Quadruple State Publishing pattern (evidence store, vulnerabilities list, attack surface graph, ControlledMission wrapper).
6. **Write handoff** to `.agents/sprint26_file_upload/handoff.md`.

## Requirements

### R1. File Upload Security Collector & Prober
Implement an active collector inheriting from `BaseCollector` that uses `AuthenticatedHttpClient` to probe file upload endpoints by sending crafted multipart/form-data requests with malicious file payloads and analyzing server responses for acceptance, execution, or storage of dangerous file types.

### R2. Multi-Vector Upload Detection Modes
1. Unrestricted File Upload: Detect endpoints that accept executable file types (.php, .jsp, .asp, .aspx, .py, .rb, .sh, .exe) without validation.
2. MIME Type Bypass: Detect servers that validate only Content-Type headers but not file content.
3. Double Extension Bypass: Detect acceptance of files like `shell.php.jpg`, `payload.asp.png`, `exploit.jsp.gif`.
4. Polyglot File Detection: Detect acceptance of files valid in multiple formats (e.g., GIF89a header + PHP code).
5. Path Traversal in Filenames: Detect acceptance of filenames containing `../`, `..\\`, or URL-encoded traversal sequences.
6. Web Shell Detection: Detect if uploaded files are accessible and executable via HTTP.

### R3. Mutation & Evasion Strategies
At least 5 distinct upload bypass strategies:
- Extension Casing Variations (.pHp, .PhP, .PHP)
- Null Byte Injection (shell.php%00.jpg)
- Content-Type Mismatch (executable content with benign MIME type)
- Magic Bytes Prepending (GIF89a, PNG header, JPEG SOI before payload)
- Filename Encoding Variations (URL-encoded, Unicode normalization)

### R4. Pipeline Connectivity
Wire the collector into the TaskGenerator DAG after endpoint discovery. Register as an internal plugin in the tool registry. Confirmed findings must create HAS_VULNERABILITY edges on the attack surface graph. Map findings to CWE-434 and CWE-436.

### R5. Zero Regression & E2E Validation
All 1,784+ currently passing tests must continue to pass. Write at least 25 new tests. Write handoff to .agents/sprint26_file_upload/handoff.md.

## Acceptance Criteria

### Upload Detection
- [ ] When an endpoint accepts an executable file type without validation, Evidence is generated with Critical severity.
- [ ] MIME type bypass is detected and generates a finding.
- [ ] Double extension bypass detection works for at least 3 extension combinations.
- [ ] Path traversal in filenames is detected.
- [ ] False positive rejection: legitimate image uploads with proper validation do NOT generate evidence.

### Mutations
- [ ] At least 5 distinct upload bypass strategies implemented and tested.

### Pipeline
- [ ] Collector registered in registry.py and scheduled in TaskGenerator DAG.
- [ ] Confirmed findings create HAS_VULNERABILITY edges in the attack surface graph.
- [ ] CWE-434 mapped for upload findings, CWE-436 for interpretation conflicts in cvss.py.

### Regression
- [ ] python -m pytest tests/ --ignore=tests/workspace -x -q exits 0 (1,784+ passing, 0 regressions).
- [ ] At least 25 new tests added.
- [ ] Handoff written to .agents/sprint26_file_upload/handoff.md.

## 2026-09-02T03:03:48+05:30

Build the API Security Testing Module (REST/gRPC) for the ARGUS authorized defensive security assessment platform. This module actively discovers and validates API-specific vulnerabilities across discovered endpoints and live hosts. All testing targets user-owned infrastructure with explicit authorization.

Working directory: /home/varun/argus
Integrity mode: benchmark

## Requirements

### R1. API Security Collector & Prober
Implement an active collector inheriting from `BaseCollector` that uses `AuthenticatedHttpClient` to probe REST API endpoints for common API security vulnerabilities including parameter tampering, mass assignment, rate limiting bypass, BOLA/IDOR, and excessive data exposure.

### R2. Multi-Vector API Detection Modes
1. Parameter Tampering: Detect APIs that accept modified parameter values (price, quantity, role) without server-side validation.
2. Mass Assignment: Detect APIs that accept unexpected fields in request bodies (e.g., `isAdmin`, `role`, `balance`) and persist them.
3. Rate Limiting Bypass: Detect APIs missing rate limiting or where rate limits can be bypassed via header manipulation (X-Forwarded-For rotation, API key rotation).
4. BOLA/IDOR: Detect Broken Object Level Authorization where accessing resources with different user IDs returns unauthorized data.
5. Excessive Data Exposure: Detect API responses that return sensitive fields (passwords, tokens, SSNs, internal IDs) beyond what the client needs.
6. Method Tampering: Detect APIs that respond differently to unexpected HTTP methods (PUT/DELETE/PATCH on read-only endpoints).

### R3. API Response Analysis
Analyze API responses for:
- Schema violations and unexpected field exposure
- Authorization boundary failures across different user contexts
- Rate limit header analysis (X-RateLimit-*, Retry-After)
- Error message information disclosure (stack traces, internal paths, debug info)
- Pagination bypass and bulk data extraction indicators

### R4. Mutation & Evasion Strategies
Include at least 5 distinct API bypass strategies:
- Content-Type Switching (JSON to XML, form-data, URL-encoded)
- Parameter Pollution (duplicate parameters, array injection)
- Header-Based Auth Bypass (X-Forwarded-For, X-Original-URL, X-Rewrite-URL)
- Version Downgrade (switching API versions /v2/ to /v1/)
- Encoding Variations (Unicode, double URL-encoding, JSON Unicode escapes)

### R5. Pipeline Connectivity
Wire the collector into the TaskGenerator DAG after endpoint discovery. Register as an internal plugin in the tool registry. Confirmed findings must create HAS_VULNERABILITY edges on the attack surface graph. Map findings to CWE-639 (BOLA/IDOR), CWE-915 (Mass Assignment), CWE-770 (Rate Limiting).

### R6. Zero Regression & E2E Validation
All 1,828+ currently passing tests must continue to pass. Write at least 25 new tests covering API detection modes, response analysis logic, false positive rejection, mutation strategies, and pipeline connectivity.
Write handoff to .agents/sprint27_api_security/handoff.md.

## 2026-09-02T05:48:17Z

Build the Authentication Bypass & Credential Attack Detection Module for the ARGUS authorized defensive security assessment platform. This module actively discovers and validates authentication weaknesses and credential attack vectors across discovered endpoints and live hosts. All testing targets user-owned infrastructure with explicit authorization.

Working directory: /home/varun/argus
Integrity mode: benchmark

## Requirements

### R1. Authentication Security Collector & Prober
Implement an active collector inheriting from `BaseCollector` that uses `AuthenticatedHttpClient` to probe authentication endpoints for bypass vulnerabilities, credential weaknesses, and session management flaws.

### R2. Multi-Vector Authentication Detection Modes
1. Brute Force Analysis: Detect login endpoints lacking account lockout, rate limiting, or CAPTCHA after repeated failed attempts.
2. Password Reset Abuse: Detect insecure password reset flows (predictable tokens, token reuse, host header injection in reset links, no expiration).
3. MFA Bypass: Detect MFA implementations that can be skipped (direct endpoint access, response manipulation, missing enforcement on sensitive operations).
4. Session Fixation: Detect session IDs that persist across authentication boundaries (pre-auth session accepted post-auth).
5. JWT Manipulation: Detect JWT implementations vulnerable to algorithm confusion (alg:none, RS256→HS256), missing signature verification, expired token acceptance, and key confusion attacks.
6. Default Credentials: Detect common default username/password combinations on admin panels and management interfaces.

### R3. Session & Token Analysis
Analyze authentication responses for:
- Session token entropy and predictability assessment
- Cookie security flags (Secure, HttpOnly, SameSite) on session cookies
- Token expiration and rotation behavior
- Authentication state leakage in error messages
- Credential stuffing resistance indicators

### R4. Mutation & Evasion Strategies
Include at least 5 distinct authentication bypass strategies:
- Case Sensitivity Manipulation (admin vs Admin vs ADMIN)
- Unicode Normalization Attacks (homoglyph substitution in usernames)
- Authentication Header Manipulation (X-Forwarded-For, X-Original-URL for IP-based auth bypass)
- Token Format Manipulation (JWT header/payload tampering, base64 variants)
- Response Manipulation Detection (status code vs body content discrepancy)

### R5. Pipeline Connectivity
Wire the collector into the TaskGenerator DAG after endpoint discovery. Register as an internal plugin in the tool registry. Confirmed findings must create HAS_VULNERABILITY edges on the attack surface graph. Map findings to CWE-287 (Improper Authentication), CWE-307 (Brute Force), CWE-384 (Session Fixation), CWE-640 (Password Reset).

### R6. Zero Regression & E2E Validation
All 1,862+ currently passing tests must continue to pass. Write at least 25 new tests covering authentication detection modes, session analysis logic, false positive rejection, mutation strategies, and pipeline connectivity.
Write handoff to .agents/sprint28_auth_bypass/handoff.md.

## Acceptance Criteria

### Authentication Detection
- [ ] When a login endpoint lacks account lockout after 10+ failed attempts, Evidence is generated with High severity.
- [ ] Insecure password reset flows (predictable tokens, no expiration) are detected.
- [ ] JWT algorithm confusion (alg:none) is detected with Critical severity.
- [ ] Session fixation (session ID unchanged after login) is detected.
- [ ] False positive rejection: properly implemented auth with lockout, MFA, and secure tokens do NOT generate evidence.

### Session Analysis
- [ ] Weak session token entropy is detected.
- [ ] Missing cookie security flags (Secure, HttpOnly, SameSite) are reported.
- [ ] Severity calibration: JWT alg:none = Critical, brute force = High, session fixation = High, MFA bypass = High, weak tokens = Medium.

### Mutations
- [ ] At least 5 distinct authentication bypass strategies implemented and tested.

### Pipeline
- [ ] Collector registered in registry.py and scheduled in TaskGenerator DAG.
- [ ] Confirmed findings create HAS_VULNERABILITY edges in the attack surface graph.
- [ ] CWE-287/CWE-307/CWE-384/CWE-640 mapped in cvss.py.

### Regression
- [ ] python -m pytest tests/ --ignore=tests/workspace -x -q exits 0 (1,862+ passing, 0 regressions).
- [ ] At least 25 new tests added.
- [ ] Handoff written to .agents/sprint28_auth_bypass/handoff.md.

## Acceptance Criteria

### API Detection
- [ ] When an API accepts modified price/quantity parameters without validation, Evidence is generated with High severity.
- [ ] Mass assignment is detected when unexpected fields are accepted and persisted.
- [ ] BOLA/IDOR is detected when accessing resources with different user IDs returns unauthorized data.
- [ ] Excessive data exposure is detected when sensitive fields appear in API responses.
- [ ] False positive rejection: properly validated APIs with correct authorization do NOT generate evidence.

### Response Analysis
- [ ] Error message information disclosure is detected.
- [ ] Severity calibration: BOLA/IDOR = High, Mass Assignment = High, Rate Limiting Bypass = Medium, Excessive Data Exposure = Medium, Parameter Tampering = High.

### Mutations
- [ ] At least 5 distinct API bypass strategies implemented and tested.

### Pipeline
- [ ] Collector registered in registry.py and scheduled in TaskGenerator DAG.
- [ ] Confirmed findings create HAS_VULNERABILITY edges in the attack surface graph.
- [ ] CWE-639/CWE-915/CWE-770 mapped in cvss.py.

### Regression
- [ ] python -m pytest tests/ --ignore=tests/workspace -x -q exits 0 (1,828+ passing, 0 regressions).
- [ ] At least 25 new tests added.
- [ ] Handoff written to .agents/sprint27_api_security/handoff.md.
