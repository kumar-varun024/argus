# Project: Sprint 13 — OAuth/OIDC Token Testing & Stateful Auth Validation

## Architecture
Argus security assessment engine with modular vulnerability collectors (`BaseCollector`), HTTP execution layer (`AuthenticatedHttpClient`, `MultiIdentitySessionCoordinator`), graph representation (`KnowledgeGraph`, `AttackSurfaceGraphBuilder`), and automated mission planning DAG (`TaskGenerator`, `ToolRegistry`, `PluginExecutorAdapter`).

```
[Target Mission]
       │
       ▼
[TaskGenerator DAG] ──> Dependencies: "Discover API Endpoints"
       │
       ▼
[ToolRegistry / PluginExecutorAdapter] ──> Dispatches "oauth" / "oauth_oidc"
       │
       ▼
[OAuthCollector (BaseCollector)]
       ├── OAuthPayloadGenerator (Redirect URIs, Tampered JWTs, Insecure Cookies, State Vectors)
       ├── OAuthAnalyzer (Open Redirect, Subdomain Bypass, Path Traversal, State Missing, Code Reuse)
       ├── TokenValidationAnalyzer (alg:none, Bad Signatures, Key Confusion, Expired/Aud/Iss/Nbf, Scope Escalation)
       └── SessionSecurityAnalyzer (Session Fixation, Logout Invalidation, Cookie Flags: Secure/HttpOnly/SameSite)
       │
       ▼
[EvidenceStore & KnowledgeGraph]
       ├── Node: live_host:<url>, endpoint:<url>, vulnerability:<id>
       └── Edges: HAS_ENDPOINT, HAS_VULNERABILITY (live_host -> vuln, endpoint -> vuln)
```

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| 1 | OAuth Redirect URI Manipulation | Test open redirect, path traversal bypass, subdomain matching bypass on redirect_uri | M1 | ORIGINAL_REQUEST §R1 |
| 2 | OAuth State Parameter Validation | Detect missing, static, or unvalidated state parameter (CSRF risk) | M1 | ORIGINAL_REQUEST §R1 |
| 3 | Token Leakage via Referer | Detect token or authorization code leakage in Referer headers | M1 | ORIGINAL_REQUEST §R1 |
| 4 | Authorization Code Reuse | Detect authorization codes that can be exchanged multiple times | M1 | ORIGINAL_REQUEST §R1 |
| 5 | JWT Signature Verification & alg:none | Detect acceptance of tokens with alg:none or invalid/tampered signatures | M2 | ORIGINAL_REQUEST §R2 |
| 6 | JWT Key Confusion (RS256 vs HS256) | Detect acceptance of HMAC signed tokens using public RSA key | M2 | ORIGINAL_REQUEST §R2 |
| 7 | JWT Claims Validation | Detect missing/improper validation of exp, aud, iss, nbf claims | M2 | ORIGINAL_REQUEST §R2 |
| 8 | Token Scope Escalation | Detect acceptance of tokens with modified/stripped scopes for privileged actions | M2 | ORIGINAL_REQUEST §R2 |
| 9 | Session Fixation Detection | Detect pre-login session IDs retained after successful authentication | M3 | ORIGINAL_REQUEST §R3 |
| 10 | Logout Invalidation Detection | Detect session cookies/tokens remaining active after logout request | M3 | ORIGINAL_REQUEST §R3 |
| 11 | Cookie Security Flags Validation | Validate Secure, HttpOnly, and SameSite attributes on session cookies | M3 | ORIGINAL_REQUEST §R3 |
| 12 | Concurrent Session Handling | Analyze concurrent login state and session collisions | M3 | ORIGINAL_REQUEST §R3 |
| 13 | False Positive Rejection | Ensure properly configured flows, valid JWTs, and secure cookies emit no findings | M1-M3 | ORIGINAL_REQUEST §Acceptance Criteria |
| 14 | TaskGenerator DAG Integration | Register "oauth" recon template scheduled after "Discover API Endpoints" | M4 | ORIGINAL_REQUEST §R4 |
| 15 | Tool Registry & Plugin Adapter | Register "oauth" in ToolRegistry with aliases and fallback in PluginExecutorAdapter | M4 | ORIGINAL_REQUEST §R4 |
| 16 | Attack Surface Graph Connectivity | Generate HAS_ENDPOINT and HAS_VULNERABILITY edges in KnowledgeGraph and AttackSurfaceGraphBuilder | M4 | ORIGINAL_REQUEST §R4 |
| 17 | Test Suite & Zero Regression | >=20 new tests, 0 regressions on 1127+ existing tests | M5 | ORIGINAL_REQUEST §R5 |
| 18 | Sprint Handoff Documentation | Detailed handoff written to .agents/sprint13_oauth/handoff.md | M5 | ORIGINAL_REQUEST §R5 |

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M1 | OAuth/OIDC Flow Collector | Implement `OAuthCollector`, `OAuthPayloadGenerator`, `OAuthAnalyzer` (redirect_uri, state, referer leakage, code reuse) in `argus/collectors/oauth.py` | none | DONE |
| M2 | Token Validation Testing | Implement JWT and token validation (alg:none, invalid signature, key confusion, claims exp/aud/iss/nbf, scope escalation) in `argus/collectors/oauth.py` | M1 | DONE |
| M3 | Stateful Auth & Session Analysis | Implement session fixation, logout invalidation, cookie flags (Secure/HttpOnly/SameSite) in `argus/collectors/oauth.py` | M2 | DONE |
| M4 | Pipeline & Graph Connectivity | Integrate with `task_generator.py`, `registry.py`, `plugins.py`, `attack_surface.py`, `argus/collectors/__init__.py` | M3 | DONE |
| M5 | Comprehensive Tests & Victory Audit | Implement unit, adversarial, and E2E tests (>=20 tests), verify 1127+ baseline tests pass, write handoff to `.agents/sprint13_oauth/handoff.md`, run Forensic Audit | M4 | DONE |

## Interface Contracts
### Collector Interface
```python
class OAuthCollector(BaseCollector):
    def __init__(
        self,
        http_client: Optional[Any] = None,
        timeout: float = 10.0,
        payload_generator: Optional[Any] = None,
        analyzer: Optional[Any] = None,
    ):
        ...
    def collect(self, mission: Any) -> List[Evidence]:
        ...
    def execute(self, mission: Any) -> List[Evidence]:
        return self.collect(mission)
```

### Graph & Evidence Contract
```python
Evidence(
    category="oauth_misconfiguration", # or "session_management", "token_validation", "oauth"
    severity="critical" | "high" | "medium" | "low",
    status="CONFIRMED",
    confidence=0.95,
    metadata={
        "url": target_url,
        "host": base_url,
        "misconfiguration_type": str,
        "parameter": Optional[str],
        "evidence_snippet": str,
        "template_id": str,
    }
)
```

## Code Layout
- `argus/collectors/oauth.py`: Main collector and analyzer subcomponents.
- `argus/collectors/__init__.py`: Module exports for `OAuthCollector`, `OAuthPayloadGenerator`, `OAuthAnalyzer`, `TokenValidationAnalyzer`, `SessionSecurityAnalyzer`.
- `argus/planning/task_generator.py`: `_RECON_TEMPLATES["oauth"]`, `_resolve_template_for_gap`, `from_gaps`.
- `argus/runtime/registry.py`: `ToolRegistry` registration and aliases for `oauth`.
- `argus/runtime/plugins.py`: `PluginExecutorAdapter._instantiate_specialist_fallback` mapping.
- `argus/graph/attack_surface.py`: `AttackSurfaceGraphBuilder.build_from_evidence` section for oauth/session evidence.
- `tests/collectors/test_oauth.py`: Unit and component test cases (22 tests).
- `tests/collectors/test_oauth_adversarial.py`: Adversarial and false positive suppression test cases (8 tests).
- `tests/runtime/test_e2e_oauth.py`: End-to-end mission loop and graph integration test cases (6 tests).
- `.agents/sprint13_oauth/handoff.md`: Final Sprint 13 handoff report.
