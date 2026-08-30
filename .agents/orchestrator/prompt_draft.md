# Prompt Draft: Worker 1 (Sprint 13 Implementation Lead)

## Working Directory
`/home/varun/argus/.agents/worker_1`

## Role
Implementation Lead for Sprint 13 (OAuth/OIDC Token Testing & Stateful Auth Validation)

## Mandatory Files to Read Before Starting
- `/home/varun/argus/.agents/ORIGINAL_REQUEST.md`
- `/home/varun/argus/PROJECT.md`
- `/home/varun/argus/.agents/explorer_survey_1/handoff.md`
- `/home/varun/argus/.agents/explorer_survey_2/handoff.md`
- `/home/varun/argus/.agents/explorer_survey_3/handoff.md`

## Task Instructions & Code Ownership
You own and must implement/modify the following files:
1. `argus/collectors/oauth.py`: Full implementation of `OAuthCollector(BaseCollector)`, `OAuthPayloadGenerator`, `OAuthAnalyzer`, `TokenValidationAnalyzer`, `SessionSecurityAnalyzer` addressing:
   - R1: redirect_uri manipulation (open redirect, subdomain bypass, path traversal bypass), state parameter validation (missing/static/unvalidated), token leakage via Referer, authorization code reuse.
   - R2: JWT signature verification (alg:none bypass, invalid signature acceptance, RS256/HS256 key confusion), claims validation (exp, aud, iss, nbf), token scope escalation.
   - R3: Session fixation (pre-login session ID retention), logout invalidation, cookie flags (Secure, HttpOnly, SameSite), concurrent session handling.
   - False positive suppression: genuine OAuth flows, valid JWTs, and secure cookies must NOT produce evidence.
   - Graph and Evidence updates: emits `Evidence` with `CONFIRMED` status, proper severity, confidence >=0.90, updates `mission.vulnerabilities`, adds `live_host`, `endpoint`, `vulnerability` nodes and connects `HAS_ENDPOINT` and `HAS_VULNERABILITY` edges.
2. `argus/collectors/__init__.py`: Export `OAuthCollector`, `OAuthPayloadGenerator`, `OAuthAnalyzer`, `TokenValidationAnalyzer`, `SessionSecurityAnalyzer` and add to `__all__`.
3. `argus/planning/task_generator.py`: Add `"oauth"` template to `_RECON_TEMPLATES` with `dependencies: ["Discover API Endpoints"]`, `required_inputs: ["endpoints"]`, priority 0.81. Update `_resolve_template_for_gap` and `from_gaps`.
4. `argus/runtime/registry.py`: Register `Tool(id="oauth", ...)` in `ToolRegistry` with aliases (`oauth_collector`, `oidc`, `oidc_collector`, `oauth_oidc`).
5. `argus/runtime/plugins.py`: Update `PluginExecutorAdapter._instantiate_specialist_fallback` to instantiate `OAuthCollector` on `"oauth"` / `"oidc"`.
6. `argus/graph/attack_surface.py`: Update `AttackSurfaceGraphBuilder.build_from_evidence` to build `live_host -> vulnerability` and `endpoint -> vulnerability` `HAS_VULNERABILITY` edges for oauth and session evidence categories.
7. `tests/collectors/test_oauth.py`: Implement at least 20 comprehensive unit and component tests covering R1, R2, R3, R4.
8. `tests/collectors/test_oauth_adversarial.py`: Implement adversarial, boundary, and false positive rejection tests.
9. `tests/runtime/test_e2e_oauth.py`: Implement E2E mission pipeline and graph reconstruction tests.

## Mandatory Integrity Warning
DO NOT CHEAT. All implementations must be genuine. DO NOT hardcode test results, create dummy/facade implementations, or circumvent the intended task. A forensic auditor will independently verify your work. Integrity violations WILL be detected and your work WILL be rejected.

## Verification & Victory Audit
- Run `python3 -m pytest tests/ --ignore=tests/workspace -x -q` to verify:
  1. All 1,127 baseline tests pass with 0 regressions.
  2. At least 20 new tests pass.
  3. Total test suite passes 100%.
- Document all modified files, test execution outputs, and verification details in `/home/varun/argus/.agents/worker_1/handoff.md`.
- Operate silently and notify parent only when 100% complete.
