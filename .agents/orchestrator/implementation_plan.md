# Implementation Plan: Sprint 13 OAuth/OIDC & Stateful Auth Module

## Overview
Implement OAuth/OIDC token testing and stateful authentication workflow validation module following Argus's existing collector architecture (`SQLInjectionCollector`, `SSRFCollector`, `XSSCollector`, `PathTraversalCollector`, `CommandInjectionCollector`, `AccessControlCollector`).

## Architecture & Design
1. **Collector Architecture (`argus/collectors/oauth.py`)**:
   - `OAuthCollector(BaseCollector)` with `collect(mission)` and `execute(mission)`.
   - `OAuthPayloadGenerator`: Generates redirect_uri manipulation variants (open redirect, subdomain bypass, path traversal bypass), state parameters, test JWT tokens (alg:none, invalid signature, HMAC-RSA key confusion, expired timestamps, bad audience/issuer, future nbf, modified scopes), and session probe cookies.
   - `OAuthAnalyzer`: Analyzes OAuth authorization and token exchange responses.
   - `TokenValidationAnalyzer`: Analyzes JWT and OIDC token validation endpoints.
   - `SessionSecurityAnalyzer`: Analyzes session fixation, logout invalidation, cookie flags (`Secure`, `HttpOnly`, `SameSite`), and concurrent sessions.
   - Supports constructor injection of `http_client` (defaults to `AuthenticatedHttpClient`).
   - Generates `Evidence` with `CONFIRMED` status, proper severity, confidence >=0.90, and rich metadata.
   - Updates `mission.vulnerabilities` and attaches `live_host`, `endpoint`, `vulnerability` nodes with `HAS_ENDPOINT` and `HAS_VULNERABILITY` edges.

2. **Pipeline Connectivity & Graph Integration**:
   - `argus/planning/task_generator.py`: Add `"oauth"` template to `_RECON_TEMPLATES` with `dependencies: ["Discover API Endpoints"]`, `required_inputs: ["endpoints"]`, priority 0.81. Update gap resolver and endpoint extractor.
   - `argus/runtime/registry.py`: Register `Tool(id="oauth", ...)` in `ToolRegistry` with aliases (`oauth_collector`, `oidc`, `oidc_collector`, `oauth_oidc`).
   - `argus/runtime/plugins.py`: Update `PluginExecutorAdapter._instantiate_specialist_fallback` to map `"oauth"` / `"oidc"` to `OAuthCollector`.
   - `argus/graph/attack_surface.py`: Update `AttackSurfaceGraphBuilder.build_from_evidence` to build `live_host -> vulnerability` and `endpoint -> vulnerability` `HAS_VULNERABILITY` edges for oauth and session evidence categories.
   - `argus/collectors/__init__.py`: Export all public classes and include in `__all__`.

3. **Testing Suite & Verification**:
   - `tests/collectors/test_oauth.py`: >=20 unit tests covering R1, R2, R3, R4 with `MockOAuthHttpClient`.
   - `tests/collectors/test_oauth_adversarial.py`: Adversarial tests, malformed inputs, false positive suppression.
   - `tests/runtime/test_e2e_oauth.py`: End-to-end DAG execution, graph reconstruction, and mission loop.
   - Zero regressions on all 1127+ baseline tests.
   - Handoff report in `.agents/sprint13_oauth/handoff.md`.

## Milestones & Execution Flow
- **Phase 1**: Implementation of `argus/collectors/oauth.py` and `argus/collectors/__init__.py` (R1, R2, R3).
- **Phase 2**: Implementation of Pipeline & Graph Integration (`task_generator.py`, `registry.py`, `plugins.py`, `attack_surface.py`) (R4).
- **Phase 3**: Comprehensive Test Suite Creation (`tests/collectors/test_oauth.py`, `test_oauth_adversarial.py`, `tests/runtime/test_e2e_oauth.py`) (R5).
- **Phase 4**: Multi-Agent Review, Adversarial Challenge, and Forensic Integrity Audit.
- **Phase 5**: Final Verification & Handoff (.agents/sprint13_oauth/handoff.md).
