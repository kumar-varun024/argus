# Original User Request

## Initial Request — 2026-09-02T05:49:33Z

You are the Project Orchestrator for the ARGUS platform sprint: Authentication Bypass & Credential Attack Detection Module.

Working directory: /home/varun/argus
Agent working directory: /home/varun/argus/.agents/orchestrator
Original request: /home/varun/argus/.agents/ORIGINAL_REQUEST.md
Final handoff location: /home/varun/argus/.agents/sprint28_auth_bypass/handoff.md

Your mission is to orchestrate and execute the complete implementation of the Authentication Bypass & Credential Attack Detection Module across the codebase, adhering strictly to the multi-agent orchestration protocol and zero-regression requirement (1,862+ passing tests).

## Requirements Overview
- R1: Active collector inheriting from BaseCollector using AuthenticatedHttpClient to probe auth endpoints, following the tripartite pattern (Collector + PayloadGenerator + Analyzer) and Quadruple State Publishing.
- R2: Multi-Vector Authentication Detection Modes:
  1. Brute Force Analysis (account lockout / rate limit / CAPTCHA missing)
  2. Password Reset Abuse (predictable tokens, token reuse, host header injection, no expiration)
  3. MFA Bypass (direct endpoint access, response manipulation, missing enforcement)
  4. Session Fixation (session ID unchanged after login)
  5. JWT Manipulation (alg:none, RS256->HS256, missing signature, expired tokens, key confusion)
  6. Default Credentials (common default credentials on admin/management interfaces)
- R3: Session & Token Analysis (entropy/predictability, cookie flags Secure/HttpOnly/SameSite, expiration/rotation, auth state leakage in error messages, credential stuffing resistance)
- R4: Mutation & Evasion Strategies (5+ strategies: Case Sensitivity, Unicode Normalization, Auth Header Manipulation, Token Format Manipulation, Response Manipulation Detection)
- R5: Pipeline Connectivity (TaskGenerator DAG entry and gap resolution, registry.py plugin registration, attack surface graph HAS_VULNERABILITY edges, cvss.py CWE mappings for CWE-287, CWE-307, CWE-384, CWE-640)
- R6: Zero Regression & E2E Validation (1,862+ existing tests passing + >=25 new unit & adversarial tests, handoff to .agents/sprint28_auth_bypass/handoff.md)

Execute through structured multi-agent phases (Survey & Implementation Plan, Specialist Workers, Reviewers/Challengers, and Verification). Maintain your progress.md and BRIEFING.md. When 100% complete and verified with pytest, send your final completion report.

## 2026-09-02T13:41:25Z

Build the Prototype Pollution & Client-Side Attack Detection Module for the ARGUS authorized defensive security assessment platform. This module actively discovers and validates client-side and prototype pollution vulnerabilities across discovered endpoints and live hosts. All testing targets user-owned infrastructure with explicit authorization.

Working directory: /home/varun/argus
Integrity mode: benchmark

## Requirements

### R1. Client-Side Attack Collector & Prober
Implement an active collector inheriting from `BaseCollector` that uses `AuthenticatedHttpClient` to probe endpoints for prototype pollution, DOM clobbering, open redirect chains, and clickjacking vulnerabilities.

### R2. Multi-Vector Client-Side Detection Modes
1. Server-Side Prototype Pollution: Detect Node.js/Express prototype pollution via JSON body injection (__proto__, constructor.prototype) causing observable side effects (status code changes, new response headers/properties, error state changes).
2. Client-Side Prototype Pollution: Detect DOM-based prototype pollution via URL fragment/query parameter gadgets (location.hash, URLSearchParams) that modify Object.prototype and trigger observable DOM mutations or XSS sinks.
3. DOM Clobbering: Detect HTML injection points where named elements (id/name attributes) can shadow DOM API properties (document.cookie, document.body, document.getElementById) leading to logic corruption or XSS.
4. Open Redirect Chains: Detect unvalidated redirect parameters (url=, next=, redirect=, return_to=, continue=) that allow redirection to attacker-controlled domains, including multi-hop redirect chain detection.
5. Clickjacking / UI Redressing: Detect pages lacking frame-busting defenses (missing X-Frame-Options, missing/permissive CSP frame-ancestors) on sensitive pages (login, settings, payment, state-changing forms).

### R3. Prototype Pollution Gadget Analysis
Analyze pollution impact through:
- Property injection verification (polluted properties appear in responses or affect control flow)
- Gadget chain detection (known framework gadgets: Express, Lodash, jQuery, Handlebars)
- Denial-of-service via toString/valueOf pollution
- RCE gadget detection (child_process.exec options pollution in Node.js)
- Nested property traversal depth analysis

### R4. Mutation & Evasion Strategies
Include at least 5 distinct bypass/evasion strategies:
- JSON Key Encoding Variations (__proto__ vs \u005f\u005fproto\u005f\u005f vs constructor["prototype"])
- Content-Type Manipulation (application/json vs application/x-www-form-urlencoded vs multipart for pollution payloads)
- URL Encoding Layers for Redirect Bypass (double encoding, unicode normalization, scheme-relative URLs //evil.com)
- DOM Clobbering Payload Variants (form elements, embed/object, a[name] vs a[id], nested form clobbering)
- Frame-Busting Bypass Techniques (sandbox attribute, double framing, data: URI framing)

### R5. Pipeline Connectivity
Wire the collector into the TaskGenerator DAG after endpoint discovery. Register as an internal plugin in the tool registry. Confirmed findings must create HAS_VULNERABILITY edges on the attack surface graph. Map findings to CWE-1321 (Prototype Pollution), CWE-79 (DOM XSS via Clobbering), CWE-601 (Open Redirect), CWE-1021 (Clickjacking).

### R6. Zero Regression & E2E Validation
All 1,929+ currently passing tests must continue to pass. Write at least 25 new tests covering client-side detection modes, prototype pollution gadget analysis, false positive rejection, mutation strategies, and pipeline connectivity.
Write handoff to .agents/sprint29_prototype_pollution/handoff.md.

## Acceptance Criteria

### Prototype Pollution Detection
- [ ] Server-side prototype pollution via __proto__ JSON injection is detected when it causes observable response changes.
- [ ] Client-side prototype pollution gadgets via URL parameters are detected.
- [ ] Known framework gadgets (Express, Lodash) are identified with appropriate severity.
- [ ] False positive rejection: endpoints that sanitize/reject __proto__ keys do NOT generate evidence.

### DOM Clobbering
- [ ] HTML injection points where named elements shadow DOM APIs are detected.
- [ ] Severity calibration: DOM clobbering leading to XSS = High, logic corruption = Medium.

### Open Redirects
- [ ] Unvalidated redirect parameters allowing external domain redirection are detected with Medium severity.
- [ ] Multi-hop redirect chains are traced and reported.
- [ ] False positive rejection: redirects restricted to same-origin or allowlisted domains do NOT generate evidence.

### Clickjacking
- [ ] Pages missing X-Frame-Options AND CSP frame-ancestors on sensitive endpoints are detected.
- [ ] Pages with proper frame-busting (DENY/SAMEORIGIN or CSP frame-ancestors 'self') do NOT generate evidence.

### Mutations
- [ ] At least 5 distinct evasion strategies implemented and tested.

### Pipeline
- [ ] Collector registered in registry.py and scheduled in TaskGenerator DAG.
- [ ] Confirmed findings create HAS_VULNERABILITY edges in the attack surface graph.
- [ ] CWE-1321/CWE-79/CWE-601/CWE-1021 mapped in cvss.py.

### Regression
- [ ] python -m pytest tests/ --ignore=tests/workspace -x -q exits 0 (1,929+ passing, 0 regressions).
- [ ] At least 25 new tests added.
- [ ] Handoff written to .agents/sprint29_prototype_pollution/handoff.md.
