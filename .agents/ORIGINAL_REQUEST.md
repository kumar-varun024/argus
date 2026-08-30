# Original User Request

## Initial Request — 2026-08-30T12:58:56Z

Working directory: /home/varun/argus
Integrity mode: benchmark

Context: Argus is an authorized defensive security assessment platform. All testing is performed against user-owned infrastructure with explicit authorization. This sprint adds an OAuth/OIDC token testing and stateful authentication workflow validation module, following the same collector architecture as the existing SQLInjectionCollector, XSSCollector, PathTraversalCollector, CommandInjectionCollector, and SSRFCollector modules.

## Requirements

### R1. OAuth/OIDC Authentication Collector
Implement a collector that uses the AuthenticatedHttpClient to test discovered OAuth and OIDC endpoints for authentication and authorization misconfigurations. Test areas include redirect_uri parameter manipulation (open redirect, path traversal, subdomain matching bypass), state parameter presence and validation (CSRF protection), token leakage via Referer headers, and authorization code reuse detection.

### R2. Token Validation Testing
The collector must validate OIDC token security properties:
1. **Signature Verification:** Detect tokens accepted without valid signatures (e.g., alg:none bypass, key confusion attacks).
2. **Claims Validation:** Test for missing or improper validation of expiration (exp), audience (aud), issuer (iss), and not-before (nbf) claims.
3. **Token Scope Escalation:** Detect when tokens with reduced or modified scopes are accepted for privileged operations.

### R3. Session & Authentication Flow Analysis
Test stateful authentication workflows for weaknesses: session fixation (pre-login session ID reuse post-login), insufficient session invalidation on logout, concurrent session handling, and cookie security attributes (Secure, HttpOnly, SameSite flags).

### R4. Pipeline Connectivity
Wire the collector into the TaskGenerator DAG after endpoint discovery. Register as an internal plugin in the tool registry. Confirmed findings must create HAS_VULNERABILITY edges on the attack surface graph.

### R5. Zero Regression & E2E Validation
All 1127+ currently passing tests must continue to pass. Write at least 20 new tests. Write handoff to .agents/sprint13_oauth/handoff.md.

## Acceptance Criteria

### Detection
- [ ] When a mock OAuth endpoint accepts a manipulated redirect_uri pointing to an external domain, Evidence is generated with high or critical severity.
- [ ] When a mock OIDC token with alg:none or invalid signature is accepted, Evidence is generated with critical severity.
- [ ] When session cookies lack Secure/HttpOnly flags, Evidence is generated.
- [ ] False positive rejection: properly configured OAuth flows and valid tokens do NOT generate evidence.

### Authentication Flows
- [ ] At least 3 distinct OAuth/OIDC misconfiguration categories tested (redirect_uri, state parameter, token validation).
- [ ] Session management checks cover at least fixation and cookie attribute validation.

### Pipeline
- [ ] Collector registered in registry.py and scheduled in TaskGenerator DAG.
- [ ] Confirmed findings create HAS_VULNERABILITY edges in the attack surface graph.

### Regression
- [ ] python -m pytest tests/ --ignore=tests/workspace -x -q exits 0 (1127+ passing, 0 regressions).
- [ ] At least 20 new tests added.
- [ ] Handoff written to .agents/sprint13_oauth/handoff.md.
