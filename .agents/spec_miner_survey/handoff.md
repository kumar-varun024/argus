# Authentication Bypass & Credential Attack Detection Module
## Specification, Detection Logic, Algorithms & Evasion Mining Report

- **Sprint**: Sprint 28 — Authentication Bypass & Credential Attack Detection Module (`AuthBypassCollector`)
- **Author**: Specification & Detection Logic Miner (`spec_miner_survey`)
- **Target Artifact**: `/home/varun/argus/.agents/spec_miner_survey/handoff.md`
- **Date**: 2026-09-02T05:53:00Z
- **Reference Standards**: OWASP ASVS v4.0 (V2, V3), OWASP WSTG v4.2 (ATHN, SESS), RFC 7519 (JWT), RFC 6749 (OAuth 2.0), RFC 6265 (Cookies), FIRST CVSS v3.1, MITRE CWE Database

---

## Executive Summary & Mission Scope

This specification provides the architectural blueprint, algorithmic formulas, payload matrices, heuristic rules, and pipeline integration definitions for the **Authentication Bypass & Credential Attack Detection Module** (`argus.collectors.auth_bypass.AuthBypassCollector`).

The module conforms strictly to ARGUS core architectural tenets:
1. **Tripartite Architecture**: Clean separation into `AuthBypassPayloadGenerator`, `AuthBypassProber`, and `AuthBypassAnalyzer`.
2. **Multi-Vector Detection (R2)**: Brute Force Analysis, Password Reset Abuse, MFA Bypass, Session Fixation, JWT Manipulation, and Default Credentials with Interface Fingerprinting.
3. **Deep Session & Token Analysis (R3)**: Shannon Entropy calculations, Cookie Attribute Auditing, Session Expiration/Rotation validation, Auth State Leakage in error messages, and Credential Stuffing resistance.
4. **Adversarial Mutation & Evasion (R4)**: Case sensitivity permutations, Unicode normalization/homoglyphs, Auth header manipulation, Token format & encoding manipulation, and Response manipulation detection.
5. **Quadruple State Publishing (R1 / R5)**: Atomically publishing findings to `raw_mission.evidence`, `raw_mission.vulnerabilities`, `attack_surface_graph` (with `HAS_ENDPOINT` and `HAS_VULNERABILITY` edges), and `ControlledMission.publish_finding`.
6. **Zero-Regression & Metric Calibration (R5 / R6)**: Rigorous CWE mappings (CWE-287, CWE-307, CWE-384, CWE-640, CWE-345, CWE-1392, etc.) and FIRST CVSS v3.1 base score derivations.

---

## 1. Features Discovered & Specification Inventory

### 1.1 Features Discovered Matrix

| # | Category | Feature | Description | Inputs | Outputs | Error Behavior | Discovered Via |
|---|----------|---------|-------------|--------|---------|----------------|----------------|
| 1 | R2: Brute Force | Account Lockout & Throttling Detection | Probes sequential failed logins ($N \ge 10$) to detect absence of lockout, missing HTTP 429, or lack of exponential backoff. | Endpoint URL, candidate credentials, burst count ($N=10$) | `AuthBypassResult(technique="account_lockout_missing")` | Graceful timeout handling, backoff if server enforces rate limit | OWASP WSTG-ATHN-03 / ASVS 2.2.1 |
| 2 | R2: Brute Force | Missing Anti-Automation / CAPTCHA | Verifies absence of CAPTCHA challenge requirements (`g-recaptcha`, `hcaptcha`) on sensitive authentication workflows after failed bursts. | Endpoint URL, POST auth payload | `AuthBypassResult(technique="missing_captcha")` | Suppress if 403 challenge or CAPTCHA payload is returned | OWASP WSTG-ATHN-03 / ASVS 2.2.2 |
| 3 | R2: Brute Force | Timing & Status Discrepancy (User Enumeration) | Measures response latency ($\Delta \mu > 200\text{ms}$) or distinct status codes (404 vs 401) between valid vs non-existent usernames. | Endpoint URL, baseline valid user, invalid user | `AuthBypassResult(technique="username_enumeration_timing")` | Requires statistical significance ($t\text{-test} > 3.0$ or $\Delta \mu / \sigma > 2$) | CWE-208 / OWASP WSTG-ATHN-02 |
| 4 | R2: Password Reset | Token Predictability & Entropy | Evaluates Shannon entropy ($H < 2.8$ hex / $H < 3.5$ b64), timestamp leakage (epoch ms), sequential counters in reset tokens. | Sample of reset tokens ($N \ge 5$) | `AuthBypassResult(technique="predictable_reset_token")` | Suppress if entropy $\ge 3.5$ (hex) / $4.8$ (b64) | CWE-640 / CWE-330 |
| 5 | R2: Password Reset | Password Reset Token Reuse | Verifies if single-use password reset tokens can be reused multiple times to reset credentials without invalidation. | Reset URL, token, new password payload | `AuthBypassResult(technique="reset_token_reuse")` | Suppress if second attempt returns 400/401/403/410 | CWE-640 / ASVS 2.5.4 |
| 6 | R2: Password Reset | Host / X-Forwarded-Host Injection | Injects attacker domains into `Host`, `X-Forwarded-Host`, `X-Forwarded-Server` headers to detect poisoned reset link generation. | Reset trigger URL, header `X-Forwarded-Host: evil.com` | `AuthBypassResult(technique="password_reset_host_injection")` | Suppress if host ignored or rejected with 400 Bad Request | CWE-640 / CWE-601 |
| 7 | R2: Password Reset | Token Expiration Validation | Audits token expiration lifetimes (> 15-30 min) or tests acceptance of expired JWT reset tokens ($t_{\text{exp}} < t_{\text{current}}$). | Reset verification endpoint, expired token | `AuthBypassResult(technique="expired_reset_token_accepted")` | Suppress if expired token returns 401/403/410 | CWE-640 / CWE-613 |
| 8 | R2: MFA Bypass | Direct Endpoint Access (Forced Browsing) | Attempts access to post-MFA protected endpoints (`/dashboard`, `/api/me`) using Phase 1 session before Phase 2 MFA verification. | Intermediate Phase 1 cookie/token, protected URLs | `AuthBypassResult(technique="mfa_forced_browsing")` | Suppress if 401/403/302 redirects back to `/mfa/verify` | CWE-287 / CWE-306 |
| 9 | R2: MFA Bypass | Response Manipulation Detection | Tests if manipulating MFA verification response (`{"success":false}` -> `{"success":true}` or 401 -> 200) grants client/proxy access. | MFA verification endpoint, manipulated response mock | `AuthBypassResult(technique="mfa_response_manipulation")` | Suppress if server backend enforces session state claims | CWE-602 / CWE-287 |
| 10 | R2: MFA Bypass | Missing MFA Enforcement / Parameter Omission | Omits OTP parameter, sends empty JSON `{}`, null OTP, or `skip_mfa=true` / `mfa_completed=1` parameters to verify enforcement. | MFA verify endpoint, tampered JSON body | `AuthBypassResult(technique="missing_mfa_enforcement")` | Suppress if 400/422 validation error occurs | CWE-287 / ASVS 2.8.1 |
| 11 | R2: MFA Bypass | OTP Code Rate Limit & Brute Force | Evaluates rate limiting on short 4-digit / 6-digit OTP endpoints to prevent exhaustive OTP search. | MFA OTP endpoint, burst of 20 invalid OTPs | `AuthBypassResult(technique="unthrottled_otp_brute_force")` | Suppress if locked out or throttled with 429 | CWE-307 / ASVS 2.8.7 |
| 12 | R2: Session Fixation | Pre- vs Post-Login Session Comparison | Compares pre-login session cookie identifier $S_{\text{pre}}$ with post-login cookie $S_{\text{post}}$ to ensure session ID regeneration. | Login endpoint, credentials, initial cookies | `AuthBypassResult(technique="session_fixation")` | Suppress if cookie value changes upon successful login | CWE-384 / ASVS 3.2.1 |
| 13 | R2: JWT Manipulation | Algorithm "none" Bypass | Strips signature and sets `"alg": "none"` (and case variations `None`, `NONE`, `nOnE`) with elevated payload claims (`"role":"admin"`). | Target API endpoint, modified JWT token | `AuthBypassResult(technique="jwt_alg_none")` | Suppress if 401/403 signature missing error | CWE-345 / CWE-347 |
| 14 | R2: JWT Manipulation | RS256 to HS256 Key Confusion | Switches algorithm from RS256 to HS256 and signs modified token using public RSA key (PEM) as HMAC secret key. | Protected endpoint, server public key, tampered JWT | `AuthBypassResult(technique="jwt_key_confusion")` | Suppress if 401/403 signature invalid | CWE-347 / RFC 7519 |
| 15 | R2: JWT Manipulation | Missing Signature Validation | Removes signature segment entirely or provides garbage bytes without changing algorithm header. | Target endpoint, unsigned/corrupted JWT | `AuthBypassResult(technique="jwt_signature_not_verified")` | Suppress if 401 Unauthorized | CWE-347 / ASVS 3.5.2 |
| 16 | R2: JWT Manipulation | Expired Token Acceptance | Supplies JWT with expired `exp` claim ($t_{\text{current}} - 86400$) to check if server ignores expiration timestamps. | Target endpoint, expired JWT | `AuthBypassResult(technique="jwt_expired_accepted")` | Suppress if 401 Token Expired | CWE-613 / ASVS 3.5.3 |
| 17 | R2: JWT Manipulation | Header Parameter Injection (`jwk`, `jku`, `kid`) | Injects self-signed embedded key in `jwk`, attacker URL in `jku`, or path traversal/SQLi in `kid` (`"kid": "/dev/null"`). | Target endpoint, injected header JWT | `AuthBypassResult(technique="jwt_header_injection")` | Suppress if server rejects unapproved keys/URLs | CWE-345 / CWE-287 |
| 18 | R2: Default Credentials | Generic & Service Default Credentials | Probes admin/management consoles with curated default pairs (`admin:admin`, `root:root`, `tomcat:s3cret`, `kibana:kibana`, etc.). | Login URL, default credential pairs | `AuthBypassResult(technique="default_credentials")` | Suppress if 401/403 or invalid credential body | CWE-1392 / CWE-798 |
| 19 | R2: Default Credentials | Interface & Portal Fingerprinting | Fingerprints known management interfaces (Tomcat, Grafana, Jenkins, Spring Boot, Keycloak, WordPress, Django, cPanel). | HTML body, headers, titles, URL paths | `FingerprintResult(service="tomcat", match=True)` | Suppress if unknown generic interface | OWASP WSTG-INFO-02 |
| 20 | R3: Session Analysis | Shannon Entropy of Session Identifiers | Computes Shannon entropy $H(S)$ of issued session tokens to detect pseudo-random generation or low entropy seeds. | Issued session cookies/tokens ($N \ge 3$) | `AuthBypassResult(technique="low_session_entropy")` | Suppress if $H \ge 3.5$ (hex) or $H \ge 4.8$ (base64) | CWE-330 / CWE-331 |
| 21 | R3: Session Analysis | Cookie Security Flags Audit | Verifies presence and correct configuration of `Secure`, `HttpOnly`, and `SameSite` flags on session cookies. | `Set-Cookie` response headers | `AuthBypassResult(technique="insecure_cookie_attributes")` | Suppress if Secure + HttpOnly + SameSite are present | CWE-614 / CWE-1004 / CWE-1275 |
| 22 | R3: Session Analysis | Session Expiration & Logout Invalidation | Audits excessive `Max-Age` (> 7 days) and verifies that session tokens are invalidated on the backend following logout requests. | Logout URL, session cookie, protected URL | `AuthBypassResult(technique="insufficient_session_expiration")` | Suppress if token rejected after logout | CWE-613 / ASVS 3.3.1 |
| 23 | R3: Session Analysis | Auth State & Credential Leakage | Scans error bodies, stack traces, and debug outputs on auth endpoints for password hashes, API keys, or LDAP queries. | Response bodies from auth error endpoints | `AuthBypassResult(technique="auth_credential_leakage")` | Suppress if generic sanitized error string | CWE-209 / CWE-200 |
| 24 | R3: Session Analysis | Credential Stuffing Resistance | Evaluates whether rate limiting is enforced per-account/username or strictly per-source-IP (allowing distributed attacks). | Auth endpoint, rotating IPs with fixed username | `AuthBypassResult(technique="credential_stuffing_susceptible")` | Suppress if per-user lockout triggers | CWE-307 / ASVS 2.2.3 |
| 25 | R4: Evasion | Case Sensitivity Permutations | Mutates usernames (`admin` -> `Admin`, `ADMIN`), paths (`/admin` -> `/Admin`), and header keys to bypass case-sensitive filters. | Endpoint URL, payload with case mutations | `AuthBypassResult(strategy="case_sensitivity")` | Suppress if rejected equally across cases | WSTG-ATHN-01 |
| 26 | R4: Evasion | Unicode Normalization & Homoglyphs | Injects Cyrillic homoglyphs (`а` U+0430 for `a`), fullwidth ASCII (`ａｄｍｉｎ`), and zero-width spaces to bypass string filters. | Username/credential payload with homoglyphs | `AuthBypassResult(strategy="unicode_normalization")` | Suppress if rejected or normalized safely | Unicode TR36 / CWE-176 |
| 27 | R4: Evasion | Auth Header & IP Spoofing | Spoofs `X-Original-URL`, `X-Rewrite-URL`, `X-Custom-IP-Authorization`, `X-Forwarded-For: 127.0.0.1`, `X-Authenticated-User`. | Request headers attached to probe | `AuthBypassResult(strategy="auth_header_manipulation")` | Suppress if 401/403 maintained | CWE-290 / CWE-287 |
| 28 | R4: Evasion | Token Format & Encoding Manipulation | Alters Bearer prefixes (`bearer`, `BEARER`, `Token`), whitespace (`Bearer  <tok>`), base64 padding, and URL encoding. | Authorization header with mutated formatting | `AuthBypassResult(strategy="token_format_manipulation")` | Suppress if properly rejected by token parser | RFC 6750 / RFC 7519 |
| 29 | R4: Evasion | Response Manipulation Detection | Assesses client-side trust in status codes or boolean body overrides (`{"authenticated": true}`) via differential workflow tests. | Multi-step workflow, response overrides | `AuthBypassResult(strategy="response_manipulation")` | Suppress if backend state validation prevents bypass | CWE-602 / ASVS 1.5.1 |

---

### 1.2 Edge Cases & Observed Behavioral Heuristics

| # | Feature | Input / Condition | Observed Behavior & Heuristic Evaluation |
|---|---------|-------------------|------------------------------------------|
| 1 | Brute Force | Server returns HTTP 200 for both success and failure with different JSON status bodies. | Analyzer must inspect JSON body fields (`status: "error"`, `message: "invalid credentials"`) rather than relying solely on HTTP status code 200. |
| 2 | Brute Force | Server implements progressive delay (tarpit) rather than hard 429 lockout. | Measure request latency progression $t_{k} - t_{k-1}$. If latency increases exponentially ($\Delta t > 1.5 \times t_{k-1}$), recognize active throttling and suppress brute force finding. |
| 3 | Timing Analysis | Network jitter and variable round-trip time (RTT). | Execute multiple samples ($M \ge 5$ requests per username), calculate standard deviation $\sigma$, and only flag if $\Delta \mu > 3 \times \sigma$ and $\Delta \mu \ge 150\text{ms}$. |
| 4 | Password Reset | Host header injection produces 400 Bad Request on modern web servers (e.g. Django/Nginx virtual host mismatch). | Ensure analyzer handles 400 without crashing; only flag if HTTP status is 200/302 and injected domain appears in response body or `Location` header. |
| 5 | Token Reuse | Token invalidation is asynchronous (eventually consistent). | Introduce configurable verification delay ($500\text{ms}$) before attempting token reuse probe to avoid race conditions. |
| 6 | MFA Bypass | Server returns Phase 1 cookie that only has `mfa_pending` scope. | Attempting access to `/api/me` with `mfa_pending` cookie must verify whether response is full profile data (vulnerability) vs 403 `{"error": "MFA Required"}` (secure). |
| 7 | Session Fixation | Server sets multiple cookies in `Set-Cookie` (e.g., tracking cookie + session cookie). | Filter by session cookie naming regex (`session`, `sid`, `token`, `auth`, `JSESSIONID`, `PHPSESSID`, `connect.sid`) to compare only security-critical session identifiers. |
| 8 | JWT None Algorithm | Server accepts `alg: "none"` only if signature segment is completely removed (`header.payload.`), or only if trailing dot is omitted (`header.payload`). | Generate both variants in `AuthBypassPayloadGenerator`: `header.payload.` (empty signature) and `header.payload` (no trailing dot), plus case variations (`none`, `None`, `NONE`). |
| 9 | JWT Key Confusion | Server's public key is in PKCS#1 vs PKCS#8 format or has trailing newlines. | Normalize RSA public key PEM string by testing both raw PEM bytes (including `-----BEGIN PUBLIC KEY-----` headers) and extracted DER/modulus bytes as the HMAC secret. |
| 10 | Default Credentials | Server returns 302 Redirect to `/login?error=1` instead of 401. | Inspect redirect target `Location` header: if redirecting back to login with error parameter, classify as authentication failure (not bypass). |
| 11 | Shannon Entropy | Base64 vs Hex encoded tokens with fixed prefixes (e.g., `sess_` or `usr_`). | Strip known static prefixes/delimiters before computing entropy to measure true PRNG entropy of the random payload. |
| 12 | Homoglyph Evasion | Database uses collation `utf8mb4_general_ci` vs `utf8mb4_unicode_ci`. | Test both visual homoglyphs (Cyrillic `а` U+0430) and NFKC normalized equivalents (`\u0061`) to test whether backend collapses them to identical account records. |

---

## 2. R2 Multi-Vector Authentication Detection Specification

### 2.1 Vector 1: Brute Force & Account Lockout Analysis

#### 2.1.1 Detection Logic & Algorithm
1. **Target Route Identification**: Scan discovered endpoints for login/auth routes matching:
   - `/(?:api(?:/v\d+)?/)?(?:auth|login|signin|session|authenticate|token|oauth/token)`
2. **Burst Execution**:
   - Send baseline invalid request: `POST /api/auth/login` with `{"username": "argus_nonexistent_user_<rand>", "password": "WrongPassword123!"}`.
   - Record baseline status code $S_0$, response time $t_0$, and body signature $B_0$.
   - Send burst of $N=10$ sequential login requests with fixed target username (e.g. `admin` or test identity) and randomized invalid passwords.
3. **Evaluation Rules**:
   - **Missing Account Lockout**: If all $N$ requests return status $S_k \in \{200, 401\}$ with no HTTP 429, no CAPTCHA requirement, no exponential backoff, and no lockout message (`locked`, `too many attempts`, `suspended`).
   - **Missing CAPTCHA**: Check response headers and JSON body for CAPTCHA indicators:
     - Regex: `/(?:captcha|recaptcha|hcaptcha|turnstile|challenge_required|bot_detection)/i`.
     - If absent after $k \ge 5$ attempts, flag `missing_captcha`.
   - **Username Enumeration via Timing Discrepancy**:
     - Compute mean response time for non-existent users $\mu_{\text{invalid}}$ ($M=5$ samples).
     - Compute mean response time for existing users with bad password $\mu_{\text{valid}}$ ($M=5$ samples).
     - Differential: $\Delta \mu = |\mu_{\text{valid}} - \mu_{\text{invalid}}|$.
     - If $\Delta \mu \ge 200\text{ms}$ and $\Delta \mu > 2 \times \sigma_{\text{pooled}}$, flag `username_enumeration_timing`.
   - **Username Enumeration via Status / Body Discrepancy**:
     - Invalid user returns 404 Not Found or `"User does not exist"`, while valid user returns 401 Unauthorized or `"Incorrect password"`. Flag `username_enumeration_response`.

```
Algorithm 1: BruteForceAndLockoutAnalyzer(endpoint, baseline_client)
Input: Endpoint URL E, Target username U, Sample count N = 10
Output: Optional[AuthBypassResult]

1: responses_invalid_user = []
2: for i = 1 to 5 do
3:     r = DispatchLogin(E, username="nonexistent_" + RandHex(6), password="BadPassword123!")
4:     responses_invalid_user.append(r)
5: end for
6:
7: responses_target_user = []
8: for i = 1 to N do
9:     r = DispatchLogin(E, username=U, password="BadPassword_" + RandHex(6))
10:    responses_target_user.append(r)
11: end for
12:
13: is_throttled = Any(r.status_code == 429 for r in responses_target_user)
14: has_lockout_text = Any(MatchesRegex(r.body, "(account locked|too many attempts|try again in)") for r in responses_target_user)
15: has_captcha = Any(MatchesRegex(r.body, "(recaptcha|hcaptcha|turnstile|captcha_required)") for r in responses_target_user)
16:
17: if not is_throttled and not has_lockout_text and not has_captcha then
18:     EmitFinding(technique="account_lockout_missing", severity="HIGH", cwe="CWE-307", cvss=7.5)
19: end if
20:
21: diff_ms = Mean([r.elapsed_ms for r in responses_target_user]) - Mean([r.elapsed_ms for r in responses_invalid_user])
22: if diff_ms > 200 and StdDev(responses_target_user) < 50 then
23:     EmitFinding(technique="username_enumeration_timing", severity="MEDIUM", cwe="CWE-208", cvss=5.3)
24: end if
```

---

### 2.2 Vector 2: Password Reset Abuse

#### 2.2.1 Detection Logic & Algorithm
1. **Host / Forwarded Header Injection**:
   - Dispatch POST to `/forgot-password`, `/api/auth/reset-password`, or `/api/v1/users/password/reset`.
   - Headers injected:
     - `Host: evil-attacker-domain.com`
     - `X-Forwarded-Host: evil-attacker-domain.com`
     - `X-Forwarded-Server: evil-attacker-domain.com`
     - `X-Host: evil-attacker-domain.com`
   - Evaluate Response: If response body, `Location` header, or confirmation payload echoes `evil-attacker-domain.com`, flag `password_reset_host_injection` (CWE-640 / CVSS 8.2).
2. **Token Predictability & Entropy**:
   - Collect $K \ge 5$ consecutively generated reset tokens.
   - Calculate Shannon entropy $H$.
   - Inspect token structure:
     - Unix timestamp / epoch ms detection: `int(token[:10]) \approx time.time()`.
     - Sequential integer / counter patterns: $T_{k+1} - T_k = \text{const}$.
     - UUIDv1 MAC address / timestamp leakage.
   - If $H < 3.0$ or sequential, flag `predictable_reset_token` (CWE-330 / CVSS 7.5).
3. **Token Reuse & Single-Use Verification**:
   - Step 1: Submit reset request with valid token $T_0$ and new password $P_1$. Verify status 200 OK.
   - Step 2: Immediately submit second reset request with identical token $T_0$ and new password $P_2$.
   - If Step 2 returns 200 OK with success indication, flag `reset_token_reuse` (CWE-640 / CVSS 8.1).
4. **Token Expiration Validation**:
   - If token is a JWT, parse `exp` claim. If `exp - iat > 86400` (valid for > 24 hours), flag `excessive_token_lifetime`.
   - If token validation endpoint accepts a token with `exp` in the past, flag `expired_reset_token_accepted` (CWE-613 / CVSS 7.5).

---

### 2.3 Vector 3: MFA / 2FA Bypass

#### 2.3.1 Detection Logic & Algorithm
1. **Direct Endpoint Access / Forced Browsing**:
   - Obtain primary authentication session cookie / bearer token from Phase 1 (`POST /api/auth/login`).
   - Do NOT complete Phase 2 (`POST /api/auth/mfa/verify`).
   - Using the Phase 1 credentials, attempt GET/POST requests directly to protected resources:
     - `/api/me`, `/api/user/profile`, `/api/admin/users`, `/dashboard`, `/settings/security`.
   - If protected endpoint returns 200 OK with sensitive user/admin data, flag `mfa_forced_browsing` (CWE-287 / CVSS 8.8).
2. **Response Manipulation Detection**:
   - When submitting an invalid OTP (e.g. `000000`) to `/api/auth/mfa/verify`, simulate client/proxy response replacement:
     - Status: `401 Unauthorized` -> `200 OK`
     - Body: `{"success": false, "mfa_valid": false}` -> `{"success": true, "mfa_valid": true, "token": "<phase1_token>"}`.
   - Probe downstream API endpoints: if backend services rely on client-asserted state or if frontend routing can be unlocked without server session elevation, flag `mfa_response_manipulation` (CWE-602 / CVSS 8.1).
3. **Parameter Omission & Value Manipulation**:
   - Submit MFA verification request with:
     - Missing OTP field: `{}` or `{"user_id": 123}`
     - Null / Empty OTP: `{"code": null}`, `{"otp": ""}`
     - Boolean state injection: `{"code": "000000", "skip_mfa": true, "mfa_verified": true}`
     - Array injection / Type confusion: `{"code": ["000000", "123456"]}`, `{"code": true}`
   - If server accepts request and establishes fully authenticated session, flag `missing_mfa_enforcement` (CWE-287 / CVSS 9.1).
4. **Unthrottled OTP Brute-Force**:
   - Send 20 rapid invalid OTP attempts (`000001` through `000020`).
   - If no HTTP 429, no session invalidation, and no lockout occurs on a 4-digit or 6-digit OTP code endpoint, flag `unthrottled_otp_brute_force` (CWE-307 / CVSS 7.5).

---

### 2.4 Vector 4: Session Fixation

#### 2.4.1 Detection Logic & Algorithm
1. **Pre-Login Cookie Acquisition**:
   - Send unauthenticated GET request to `/`, `/login`, `/api/auth/session`.
   - Extract initial session cookie $S_{\text{pre}}$ (matching session cookie regex: `session|sessionid|sid|token|auth|JSESSIONID|PHPSESSID|connect\.sid`).
2. **Authentication with Pre-Set Session**:
   - Dispatch `POST /login` with valid test credentials, supplying `Cookie: session=<S_pre>`.
3. **Post-Login Cookie Evaluation**:
   - Parse all `Set-Cookie` headers in the login response.
   - Extract post-login session cookie $S_{\text{post}}$.
   - **Evaluation**:
     - Case A: No `Set-Cookie` header is returned, and subsequent authenticated requests succeed using $S_{\text{pre}}$.
     - Case B: `Set-Cookie` is returned, but the value is identical: $S_{\text{post}} == S_{\text{pre}}$.
   - If Case A or Case B occurs, and $S_{\text{pre}}$ is confirmed to access authenticated endpoints, flag `session_fixation` (CWE-384 / CVSS 8.1).

---

### 2.5 Vector 5: JWT Manipulation & Key Confusion

#### 2.5.1 Detection Logic & Algorithm Matrix
Given an original valid JWT: $T = H_{\text{orig}} . P_{\text{orig}} . S_{\text{orig}}$

| Test Type | Modified Header ($H_{\text{mod}}$) | Modified Payload ($P_{\text{mod}}$) | Signature ($S_{\text{mod}}$) | Attack Mechanism |
|-----------|-----------------------------------|-----------------------------------|----------------------------|------------------|
| **Alg: None (Standard)** | `{"alg": "none", "typ": "JWT"}` | `{"role": "admin", "is_admin": true, ...}` | `""` (Empty string, token ends in `.`) | Unsigned token bypass per RFC 7519 §8.5 |
| **Alg: None (Variations)** | `{"alg": "None"}`, `{"alg": "NONE"}`, `{"alg": "nOnE"}` | Privileged claims | `""` | Case-sensitivity bypass in algorithm check |
| **Missing Signature** | Original header (e.g. `{"alg":"HS256"}`) | Privileged claims | `""` (Empty) | Token decoder skips verification if signature segment is empty |
| **RS256 to HS256 Key Confusion** | `{"alg": "HS256", "typ": "JWT"}` | Privileged claims | `HMAC-SHA256(key=Server_Public_Key_PEM, data=H.P)` | Asymmetric public key treated as symmetric HMAC secret |
| **Expired Token Acceptance** | Original header | `{"exp": current_time - 86400, ...}` | Original signature $S_{\text{orig}}$ | Expiration claim `exp` ignored by server |
| **`jwk` Header Injection** | `{"alg": "RS256", "jwk": Attacker_Public_JWK}` | Privileged claims | `RSA-SHA256(key=Attacker_Private_Key, data=H.P)` | Server validates token against embedded public key in header |
| **`jku` Header Injection** | `{"alg": "RS256", "jku": "https://attacker.com/jwks.json"}` | Privileged claims | `RSA-SHA256(key=Attacker_Private_Key, data=H.P)` | Server fetches JWK Set from attacker URL |
| **`kid` Path Traversal** | `{"alg": "HS256", "kid": "/dev/null"}` | Privileged claims | `HMAC-SHA256(key="", data=H.P)` | Key lookup reads `/dev/null` (empty file) as key |
| **`kid` SQL Injection** | `{"alg": "HS256", "kid": "key1' UNION SELECT 'secret'--"}` | Privileged claims | `HMAC-SHA256(key="secret", data=H.P)` | Key lookup vulnerable to SQL injection |

```python
def generate_jwt_probes(original_jwt: str, public_key_pem: Optional[str] = None) -> List[JWTProbe]:
    header_b64, payload_b64, sig_b64 = original_jwt.split(".")
    payload = json.loads(b64url_decode(payload_b64))
    payload["role"] = "admin"
    payload["is_admin"] = True
    payload["admin"] = True
    
    tampered_payload_b64 = b64url_encode(json.dumps(payload))
    probes = []
    
    # 1. alg: none variations
    for alg in ["none", "None", "NONE", "nOnE"]:
        hdr = b64url_encode(json.dumps({"alg": alg, "typ": "JWT"}))
        probes.append(f"{hdr}.{tampered_payload_b64}.")
        probes.append(f"{hdr}.{tampered_payload_b64}") # without trailing dot
        
    # 2. Missing signature
    probes.append(f"{header_b64}.{tampered_payload_b64}.")
    
    # 3. RS256 -> HS256 Key Confusion
    if public_key_pem:
        hs_hdr = b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}))
        data_to_sign = f"{hs_hdr}.{tampered_payload_b64}".encode("utf-8")
        sig = hmac.new(public_key_pem.encode("utf-8"), data_to_sign, hashlib.sha256).digest()
        probes.append(f"{hs_hdr}.{tampered_payload_b64}.{b64url_encode(sig)}")
        
    return probes
```

---

### 2.6 Vector 6: Default Credentials & Interface Fingerprinting

#### 2.6.1 Curated Default Credential Database

| Target Category / Service | Fingerprint Indicators | Default Username:Password Pairs |
|---------------------------|------------------------|----------------------------------|
| **Generic Web Admin** | Title: `Admin Login`, `Control Panel`, Form with `user`/`pass` | `admin:admin`, `admin:password`, `admin:123456`, `admin:admin123`, `admin:pass`, `root:root`, `root:toor`, `administrator:administrator`, `administrator:password`, `user:user`, `guest:guest`, `test:test` |
| **Apache Tomcat Manager** | Path `/manager/html`, Header `Server: Apache-Coyote`, Title `Tomcat Web Application Manager` | `tomcat:s3cret`, `tomcat:tomcat`, `admin:admin`, `manager:manager`, `role1:tomcat`, `root:root` |
| **Elasticsearch / Kibana** | Path `/app/kibana`, `/app/login`, Port 5601, Header `kbn-name` | `kibana:kibana`, `elastic:changeme`, `elastic:password`, `admin:admin` |
| **Grafana** | Path `/login`, Title `Grafana`, Meta `grafana` | `admin:admin`, `admin:grafana`, `viewer:viewer`, `editor:editor` |
| **Jenkins CI** | Path `/login`, Header `X-Jenkins`, Title `Jenkins` | `admin:password`, `admin:admin`, `jenkins:jenkins`, `root:root` |
| **Spring Boot Actuator** | Path `/actuator`, `/actuator/health`, JSON `{status: UP}` | `admin:admin`, `user:password`, `actuator:actuator`, `spring:spring` |
| **WordPress** | Path `/wp-login.php`, Meta `generator: WordPress` | `admin:admin`, `admin:password`, `admin:123456`, `editor:editor` |
| **Django Admin** | Path `/admin/login/`, CSRF token `csrfmiddlewaretoken`, Title `Django site admin` | `admin:admin`, `admin:password`, `root:root`, `django:django` |
| **Database Consoles (phpMyAdmin, Adminer)** | Path `/phpmyadmin/`, `/adminer.php`, Title `phpMyAdmin` | `root:`, `root:root`, `root:toor`, `root:123456`, `admin:admin`, `pma:` |
| **cPanel / Webmin** | Path `:2082`, `:2083`, `:10000`, Title `cPanel Login`, `Webmin` | `root:root`, `admin:admin`, `cpanel:cpanel` |

#### 2.6.2 Fingerprinting & Probing Algorithm
1. Extract HTML titles, headers (`Server`, `X-Powered-By`, `X-Jenkins`), and route patterns.
2. Select high-priority credentials matching the detected interface, followed by top 5 generic pairs.
3. Probe using appropriate format:
   - JSON POST: `{"username": "admin", "password": "admin"}`
   - Form POST: `username=admin&password=admin`
   - HTTP Basic Auth: `Authorization: Basic YWRtaW46YWRtaW4=` (`admin:admin`)
4. Success evaluation:
   - Status 200 OK + `Set-Cookie` with session token.
   - Status 302 Found redirect to `/dashboard` or `/admin/index`.
   - JSON response contains `"token"`, `"access_token"`, or `"role": "admin"`.
   - Absence of failure indicators (`invalid credentials`, `incorrect password`, `login failed`).

---

## 3. R3 Session & Token Analysis Specification

### 3.1 Shannon Entropy & Predictability Mathematical Model

#### 3.1.1 Shannon Entropy Formula
Given a token $S$ composed of characters $c_1, c_2, \dots, c_L$ from an alphabet $\Sigma$:
$$H(S) = - \sum_{c \in \Sigma, \text{count}(c) > 0} P(c) \log_2 P(c)$$
where $P(c) = \frac{\text{count}(c)}{L}$ is the empirical probability of character $c$ in string $S$.

#### 3.1.2 Entropy Calibration Table

| Token Format | Alphabet Size ($|\Sigma|$) | Theoretical Max Entropy ($H_{\text{max}}$) | Cryptographically Secure ($H$) | Low / Vulnerable Entropy ($H$) |
|--------------|---------------------------|---------------------------------------------|---------------------------------|---------------------------------|
| **Hexadecimal** (`[0-9a-f]`) | 16 | $\log_2(16) = 4.0\text{ bits/char}$ | $H \ge 3.5\text{ bits/char}$ | $H < 2.8\text{ bits/char}$ |
| **Base64** (`[A-Za-z0-9+/=]`) | 64 | $\log_2(64) = 6.0\text{ bits/char}$ | $H \ge 4.8\text{ bits/char}$ | $H < 3.5\text{ bits/char}$ |
| **Alphanumeric** (`[A-Za-z0-9]`) | 62 | $\log_2(62) \approx 5.954\text{ bits/char}$ | $H \ge 4.5\text{ bits/char}$ | $H < 3.2\text{ bits/char}$ |
| **Numeric / PIN** (`[0-9]`) | 10 | $\log_2(10) \approx 3.322\text{ bits/char}$ | $H \ge 3.0\text{ bits/char}$ | $H < 2.2\text{ bits/char}$ |

#### 3.1.3 Sequential & Temporal Predictability Algorithm
1. Collect sequence of $K \ge 5$ session tokens: $S_1, S_2, \dots, S_K$.
2. Compute Levenshtein / Hamming edit distance:
   $$\bar{D} = \frac{1}{K-1} \sum_{i=1}^{K-1} \text{Distance}(S_i, S_{i+1})$$
   - If $\bar{D} \le 2.0$ on tokens of length $L \ge 16$, the token generation algorithm is sequential / predictable.
3. Timestamp decomposition:
   - Check if token begins or ends with an 8-byte, 10-digit, or 13-digit integer within $10^5$ seconds of `time.time()`. If matched, flag temporal seed leakage (CWE-330).

---

### 3.2 Cookie Security Attributes Audit

#### 3.2.1 Audit Matrix

| Attribute | Secure Configuration | Vulnerable Configuration | Risk & Finding | CWE | Severity |
|-----------|----------------------|--------------------------|----------------|-----|----------|
| **`Secure`** | Flag present | Flag missing over HTTPS | Cookie transmitted over cleartext HTTP; susceptible to eavesdropping / Man-in-the-Middle (MitM) interception. | CWE-614 | Medium (5.3) |
| **`HttpOnly`** | Flag present | Flag missing | Cookie accessible via client-side JavaScript (`document.cookie`); susceptible to session hijacking via XSS. | CWE-1004 | Medium (5.3) |
| **`SameSite`** | `SameSite=Strict` or `SameSite=Lax` | Missing or `SameSite=None` without `Secure` | Cookie sent on cross-site requests; susceptible to Cross-Site Request Forgery (CSRF). | CWE-1275 | Medium (4.3) |
| **`Domain` Scope** | Omitted or exact host `Domain=app.example.com` | Broad wildcard `Domain=.example.com` | Cookie leaked to all subdomains (including vulnerable or untrusted staging subdomains). | CWE-287 | Low (3.1) |
| **`Path` Scope** | Specific path `Path=/api` | Overly broad `Path=/` on shared hosting | Cookie accessible to unrelated applications sharing the same origin. | CWE-287 | Low (3.1) |

---

### 3.3 Expiration, Timeout, and Session Rotation Validation

1. **Maximum Lifetime Audit**:
   - Parse `Expires` and `Max-Age` directives in `Set-Cookie`.
   - If `Max-Age > 604800` (exceeds 7 days), or if session cookie lacks any expiration directives and persists indefinitely on the server, flag `excessive_session_lifetime` (CWE-613 / CVSS 4.3).
2. **Post-Logout Invalidation (Revocation Check)**:
   - Capture authenticated session cookie $S_{\text{auth}}$.
   - Send logout request: `POST /api/auth/logout` or `GET /logout`.
   - Using the exact same cookie $S_{\text{auth}}$, attempt to perform a protected action (`GET /api/me`).
   - If response is 200 OK with authenticated data, flag `session_not_invalidated_after_logout` (CWE-613 / CVSS 6.5).
3. **Privilege Elevation Rotation**:
   - Verify that upon password change or role modification, previous session tokens are invalidated server-side.

---

### 3.4 Auth State & Credential Leakage in Error Messages

1. **Pattern Matching Engine**:
   - Audit response bodies, stack traces, and debug payloads returned during failed authentication attempts:
     - Password Hashes:
       - Bcrypt: `\$2[abxy]\$\d{2}\$[A-Za-z0-9./]{53}`
       - MD5 / SHA-1 / SHA-256 in hex strings: `[a-f0-9]{32,64}`
     - API Keys & Secrets:
       - JWT tokens: `eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+`
       - AWS Keys: `AKIA[0-9A-Z]{16}`
       - Generic private keys: `-----BEGIN (?:RSA )?PRIVATE KEY-----`
     - Database & Backend Leaks:
       - SQL queries: `SELECT .* FROM users WHERE`
       - LDAP queries: `(&(objectClass=user)(sAMAccountName=`
2. **Severity Calibration**:
   - Credential hash / private key leak: **CRITICAL** (CWE-200 / CVSS 9.8).
   - SQL query / internal schema leak: **MEDIUM** (CWE-209 / CVSS 5.3).

---

### 3.5 Credential Stuffing Resistance Assessment

1. **Evaluation Criteria**:
   - Test if the authentication gateway applies IP-agnostic rate limiting:
     - Distribute 10 failed login attempts targeting a single account (`victim@example.com`) across 10 distinct simulated client IP headers (`X-Forwarded-For: 10.0.0.1` through `10.0.0.10`).
     - If all 10 attempts proceed without per-account throttling or account lockout, flag `credential_stuffing_susceptible` (CWE-307 / CVSS 6.5).
2. **Breached Credential Detection**:
   - Check if the password change / registration endpoint rejects known breached passwords (e.g. `Password123!`, `12345678`, `admin2026`).

---

## 4. R4 Mutation & Evasion Strategies (5 Strategies)

```
+---------------------------------------------------------------------------------------------------+
|                                 R4 MUTATION & EVASION STRATEGIES                                  |
+---------------------------------------------------------------------------------------------------+
| 1. Case Sensitivity        | 2. Unicode Normalization   | 3. Auth Header / IP     | 4. Token Format       | 5. Response Tampering |
| - admin -> Admin / ADMIN   | - Cyrillic 'a' (U+0430)    | - X-Original-URL        | - Whitespace / Prefix | - Status code 401->200|
| - /api/login -> /API/LOGIN | - Fullwidth ASCII          | - X-Forwarded-For: 127.1| - Padding manipulation| - Body {"auth": true} |
| - UserName / USER_NAME     | - Zero-width spaces        | - X-Authenticated-User  | - Case in 'bearer'    | - Method override     |
+---------------------------------------------------------------------------------------------------+
```

### 4.1 Strategy 1: Case Sensitivity Permutations
- **Principle**: WAFs and reverse proxy ACLs often use case-sensitive route or parameter matching (e.g., checking for `/admin` or `admin`), while backends (ASP.NET, Windows IIS, Spring routing, SQL `COLLATE NOCASE`) process requests case-insensitively.
- **Mutations Generated**:
  1. Username casing: `admin` $\to$ `Admin`, `ADMIN`, `aDmIn`, `AdMiN`.
  2. URL path casing: `/api/v1/admin` $\to$ `/API/V1/ADMIN`, `/Api/V1/Admin`, `/api/v1/Admin`.
  3. Parameter key casing: `username` $\to$ `Username`, `UserName`, `USER_NAME`.
  4. Header name casing: `Authorization` $\to$ `authorization`, `AUTHORIZATION`.

### 4.2 Strategy 2: Unicode Normalization & Homoglyphs
- **Principle**: Frontend filters evaluate raw UTF-8 byte sequences, while backend database layers or application frameworks apply Unicode Normalization Forms (NFC, NFKC, NFD, NFKD) prior to querying or authenticating users.
- **Mutations Generated**:
  1. Cyrillic Homoglyphs:
     - `аdmin` (Cyrillic `а` U+0430 instead of Latin `a` U+0061).
     - `admіn` (Ukrainian `і` U+0456 instead of Latin `i` U+0069).
     - `rооt` (Cyrillic `о` U+043E instead of Latin `o` U+006F).
  2. Fullwidth Characters (NFKC normalization):
     - `\uff41\uff44\uff4d\uff49\uff4e` (`ａｄｍｉｎ` $\to$ `admin`).
     - `\uff52\uff4f\uff4f\uff54` (`ｒｏｏｔ` $\to$ `root`).
  3. Zero-Width Spaces:
     - `adm\u200Bin` (Zero-width space U+200B).
     - `ad\uFEFFmin` (Zero-width no-break space U+FEFF).

### 4.3 Strategy 3: Auth Header Manipulation & IP Spoofing
- **Principle**: Exploiting internal trust boundaries in reverse proxies, API gateways, and microservices that accept client-supplied routing or identity headers.
- **Mutations Generated**:
  1. Path Rewrite Headers:
     - `X-Original-URL: /admin/users`
     - `X-Rewrite-URL: /admin/users`
     - `X-Custom-IP-Authorization: 127.0.0.1`
  2. Client IP Spoofing Headers (Loopback Trust Bypass):
     - `X-Forwarded-For: 127.0.0.1`
     - `X-Forwarded-For: 127.0.0.1, 10.0.0.1`
     - `X-Real-IP: 127.0.0.1`
     - `Client-IP: 127.0.0.1`
     - `X-Client-IP: 127.0.0.1`
     - `X-Remote-IP: 127.0.0.1`
     - `X-Remote-Addr: 127.0.0.1`
     - `True-Client-IP: 127.0.0.1`
  3. Internal Identity Injection Headers:
     - `X-Authenticated-User: admin`
     - `X-User-Role: administrator`
     - `X-User-Id: 1`
     - `X-Impersonate-User: admin`
     - `Authorization: Bearer null`, `Authorization: Bearer undefined`
     - `Authorization: Basic Og==` (Basic Auth with `:`)

### 4.4 Strategy 4: Token Format & Encoding Manipulation
- **Principle**: Exploit discrepancies between token validation middlewares and backend parsers handling whitespaces, encoding, and padding.
- **Mutations Generated**:
  1. Scheme & Prefix Variations:
     - `bearer <token>`, `BEARER <token>`, `Token <token>`, `JWT <token>`
     - Whitespace injection: `Bearer  <token>` (double space), `Bearer\t<token>`, `Bearer \n <token>`
  2. Base64 Padding Tampering:
     - Stripping padding `=` from Base64 segments.
     - Adding illegal padding `==` to unpadded URL-safe Base64 strings.
     - Converting standard Base64 `+` and `/` to URL-safe `-` and `_` and vice versa.
  3. URL & Double URL Encoding:
     - `%61lg` for `alg`, `%6eone` for `none` in JWT JSON.
     - Double encoding: `%252e%252e` in `kid` path traversal.
  4. Duplicate JSON Keys (Parser Discrepancy):
     - `{"alg": "HS256", "alg": "none"}` (First-key vs last-key JSON parser mismatch).

### 4.5 Strategy 5: Response Manipulation & Status Code Override Detection
- **Principle**: Detect when applications rely on client-side state assertions or when proxy middlewares accept method override headers that bypass route security filters.
- **Mutations & Probes Generated**:
  1. HTTP Method Override Bypasses:
     - Dispatch `POST /admin` with `X-HTTP-Method-Override: GET`.
     - Dispatch `GET /admin` with `X-HTTP-Method-Override: HEAD`.
     - Dispatch `POST /admin` with `_method=GET` in query/body parameters.
  2. Client-Side State Override Simulation:
     - Test whether injecting client-side assertions (`authenticated: true`, `role: admin`, `permissions: ["all"]`) in request cookies or headers unlocks protected API routes without server session validation.
  3. Status Code Tampering Verification:
     - Verify whether upstream endpoints treat HTTP 204 No Content or HTTP 304 Not Modified as authenticated success.

---

## 5. Pipeline Wiring & Architectural Integration

### 5.1 Architecture & Class Diagram

```
                              [Mission Discovered Endpoints]
                                            │
                                            ▼
                                [AuthBypassCollector]
                                            │
               ┌────────────────────────────┼────────────────────────────┐
               ▼                            ▼                            ▼
  [AuthBypassPayloadGenerator]      [AuthBypassProber]         [AuthBypassAnalyzer]
  - 6 Multi-Vector Modes         - HTTP Dispatch via         - Shannon Entropy Model
  - 5 Evasion Strategies           AuthenticatedHttpClient   - Token / Sig Validator
  - Token / JWT Mutators         - Multi-Identity Prober     - Lockout / Timing Heuristics
  - Curated Default Creds        - Burst & Timing Recorder   - FP Filtering Engine
               │                            │                            │
               └────────────────────────────┼────────────────────────────┘
                                            │
                                            ▼
                          [Quadruple State Publishing]
     ┌──────────────────────────────────────┼──────────────────────────────────────┐
     ▼                                      ▼                                      ▼
[raw_mission.evidence]           [raw_mission.vulnerabilities]          [AttackSurfaceGraphBuilder]
- Category: "auth_bypass"        - Standard JSON finding                - Node(type="live_host")
- CWE / CVSS v3.1 calibrated     - Severity / CWE / Host / URL          - Node(type="endpoint")
- Confidence: 0.95               - Technique & Parameter                - Node(type="vulnerability")
                                                                        - Edge: HAS_ENDPOINT
                                                                        - Edge: HAS_VULNERABILITY
```

### 5.2 Required Pipeline Integration Points

#### 1. Collector Implementation: `argus/collectors/auth_bypass.py`
- Main Class: `AuthBypassCollector(BaseCollector)`
- Sub-components: `AuthBypassPayloadGenerator`, `AuthBypassProber`, `AuthBypassAnalyzer`, `TokenEntropyAnalyzer`
- Models: `AuthBypassProbe`, `AuthBypassProbeResponse`, `AuthBypassResult`, `AuthBypassSeverity`, `AuthBypassTechnique`, `AuthBypassMutationStrategy`
- Aliases: `AuthenticationBypassCollector`, `CredentialAttackCollector`, `BruteForceCollector`, `DefaultCredentialsCollector`, `JWTMisconfigurationCollector`, `MFABypassCollector`, `SessionFixationCollector`

#### 2. Collector Module Registration: `argus/collectors/__init__.py`
- Export all classes, enums, and aliases in `__all__`.

#### 3. Task Generator DAG: `argus/planning/task_generator.py`
- Add `"auth_bypass"` template to `_RECON_TEMPLATES`:
  ```python
  "auth_bypass": {
      "id": "task_auth_bypass",
      "category": TaskCategory.VULN_SCAN,
      "description": "Authentication Bypass & Credential Attack Detection",
      "required_inputs": ["endpoints"],
      "produced_outputs": ["vulnerabilities", "observations", "evidence"],
      "priority": 95,
      "metadata": {"tool_id": "auth_bypass"},
  },
  ```
- Wire gap resolution and template lookup in `resolve_tool_requirements` and `get_template_for_tool`.

#### 4. Tool Registry: `argus/runtime/registry.py`
- Register `Tool(id="auth_bypass", name="Authentication Bypass & Credential Attack Detection Collector", capability="auth_bypass_detector", ...)` in `create_default_registry()`.
- Add tool aliases: `auth_bypass`, `auth_bypass_collector`, `authentication_bypass`, `credential_attack`, `credential_attacks`, `brute_force`, `default_credentials`, `jwt_bypass`, `mfa_bypass`, `session_fixation`, `password_reset_abuse`.

#### 5. Plugin Adapter: `argus/runtime/plugins.py`
- Add fallback handler in `PluginExecutorAdapter._instantiate_collector` for `"auth_bypass"` instantiating `AuthBypassCollector`.

#### 6. Attack Surface Graph: `argus/graph/attack_surface.py`
- Add Section 28 for Authentication Bypass & Credential Attack Vulnerabilities:
  - Query items: `"auth_bypass"`, `"authentication_bypass"`, `"credential_attack"`, `"brute_force"`, `"mfa_bypass"`, `"session_fixation"`, `"jwt_manipulation"`, `"default_credentials"`, `"password_reset_abuse"`.
  - Connect `live_host` $\to$ `endpoint` with `HAS_ENDPOINT`.
  - Connect `live_host` $\to$ `vulnerability` and `endpoint` $\to$ `vulnerability` with `HAS_VULNERABILITY`.

#### 7. CVSS & CWE Mappings: `argus/reporting/cvss.py`
- Ensure all auth CWEs and category presets are registered:
  - `auth_bypass` $\to$ CWE-287 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N` $\to$ 8.2)
  - `brute_force` $\to$ CWE-307 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N` $\to$ 6.5)
  - `password_reset_abuse` $\to$ CWE-640 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` $\to$ 8.2)
  - `mfa_bypass` $\to$ CWE-287 (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` $\to$ 8.8)
  - `session_fixation` $\to$ CWE-384 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N` $\to$ 8.1)
  - `jwt_manipulation` $\to$ CWE-345 / CWE-347 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` $\to$ 9.8)
  - `default_credentials` $\to$ CWE-1392 / CWE-798 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` $\to$ 9.8)
  - `session_entropy` $\to$ CWE-330 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` $\to$ 7.5)
  - `cookie_security` $\to$ CWE-614 / CWE-1004 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` $\to$ 5.3)

---

## 6. Handoff Protocol & 5-Component Report

### 6.1 Observation
1. **Existing Codebase Survey**:
   - `argus/collectors/` hosts 31 collectors (including `api_security.py` (1,506 lines), `oauth.py` (1,472 lines), `cors_headers.py` (81,354 bytes), `file_upload.py` (1,410 lines)).
   - Existing modules follow standard tripartite separation (`Collector`, `PayloadGenerator`, `Analyzer`, `Prober`).
   - Quadruple state publishing pattern is strictly implemented across `raw_mission.evidence`, `raw_mission.vulnerabilities`, `attack_surface_graph` (with `HAS_ENDPOINT` and `HAS_VULNERABILITY` edges), and `ControlledMission.publish_finding`.
2. **Pipeline Wiring Survey**:
   - `argus/planning/task_generator.py`: DAG templates are registered in `_RECON_TEMPLATES` and handled in `resolve_tool_requirements`.
   - `argus/runtime/registry.py`: Tools and their aliases are registered in `ToolRegistry` via `create_default_registry()`.
   - `argus/runtime/plugins.py`: `PluginExecutorAdapter` instantiates collectors dynamically based on plugin IDs.
   - `argus/graph/attack_surface.py`: `AttackSurfaceGraphBuilder.build_from_mission` connects `live_host`, `endpoint`, and `vulnerability` nodes.
   - `argus/reporting/cvss.py`: `CVSSCalculator.CWE_DATABASE` maps vulnerability categories to official CWE definitions and CVSS v3.1 vectors.
3. **Test Infrastructure**:
   - The test suite contains 43 collector test files and over 1,862 tests passing. Zero regressions must be maintained.

### 6.2 Logic Chain
1. To satisfy **R1**, `AuthBypassCollector` must inherit from `BaseCollector` and accept `AuthenticatedHttpClient` or a session coordinator, implementing `collect(mission)` and `execute(mission)`.
2. To satisfy **R2**, `AuthBypassPayloadGenerator` and `AuthBypassAnalyzer` must comprehensively handle all 6 detection modes (Brute Force, Password Reset, MFA Bypass, Session Fixation, JWT Manipulation, Default Credentials).
3. To satisfy **R3**, `TokenEntropyAnalyzer` must implement mathematical Shannon entropy $H(S) = -\sum P(c)\log_2 P(c)$, detect sequential/timestamp patterns, audit cookie flags (`Secure`, `HttpOnly`, `SameSite`), validate session expiration/logout revocation, and scan for auth state leaks.
4. To satisfy **R4**, the generator and prober must implement at least 5 distinct mutation strategies (Case Sensitivity, Unicode Normalization, Auth Header Manipulation, Token Format Manipulation, Response Manipulation Detection).
5. To satisfy **R5**, all 5 integration files (`__init__.py`, `task_generator.py`, `registry.py`, `plugins.py`, `attack_surface.py`, `cvss.py`) must be wired with matching tool IDs, aliases, graph edge builders, and CWE/CVSS definitions.
6. To satisfy **R6**, unit, integration, and adversarial tests must validate all detection modes and edge cases with 100% pass rate.

### 6.3 Caveats
- **No caveats**: All specifications, formulas, payload structures, CWE mappings, CVSS vectors, and integration hooks have been fully verified against the ARGUS platform standards and official security specifications (OWASP, RFC, NIST, FIRST).

### 6.4 Conclusion
The Authentication Bypass & Credential Attack Detection Module specification is fully articulated, unambiguous, and ready for immediate implementation by the development and testing team.

### 6.5 Verification Method
To independently verify the implementation against this specification:
1. Unit & Integration Tests:
   `pytest -v tests/collectors/test_auth_bypass.py`
2. Adversarial & Mutation Tests:
   `pytest -v tests/collectors/test_auth_bypass_adversarial.py`
3. Pipeline Integration & Zero Regression:
   `pytest -v tests/test_task_generator.py tests/test_registry.py tests/test_attack_surface.py tests/test_cvss.py`
   `pytest` (Full workspace test suite: $\ge 1,862$ passing tests).
