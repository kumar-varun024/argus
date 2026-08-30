# Project: ARGUS Sprint 4

## Architecture
ARGUS Sprint 4 delivers autonomous DNS resolution, CNAME subdomain takeover detection, a comprehensive 26-service fingerprint database, attack surface graph vulnerability integration, TestIdentity security model, and a persistent AuthenticatedHttpClient.

```
+---------------------------------------------------------------------------------------------------+
|                                      ARGUS SPRINT 4 ARCHITECTURE                                  |
+---------------------------------------------------------------------------------------------------+
|                                                                                                   |
|  1. DNSX Tool Wrapper (`argus/tools/dnsx.py`) & Registry (`argus/runtime/registry.py`)            |
|     - Wraps CLI binary (`dnsx` with `-cname -resp -json -omit-raw -silent -rl -t`)                |
|     - Registered in `ToolRegistry` with capability="dns_resolver"                                 |
|     - Parser: `ReconParser.parse_dnsx` in `argus/runtime/parser.py`                               |
|                                                                                                   |
|  2. Subdomain Takeover Detection & Fingerprint DB                                                 |
|     - Fingerprint DB: 26 signatures in `argus/recon/takeover_fingerprints.py`                      |
|     - Collector: `SubdomainTakeoverCollector` in `argus/collectors/takeover.py`                   |
|     - Generates: `Evidence(category="subdomain_takeover", severity="critical", ...)`              |
|     - Graph Integration: `AttackSurfaceGraphBuilder` generates `HAS_VULNERABILITY` edges:          |
|       `subdomain:<host>` -> `HAS_VULNERABILITY` -> `vulnerability:subdomain_takeover:...`         |
|                                                                                                   |
|  3. `TestIdentity` Model (`argus/models/test_identity.py`) & `Mission.test_identities`            |
|     - Dataclass `TestIdentity` with `AuthType` enum, token, credentials, headers, cookies,        |
|       login configuration (`login_url`, `login_payload`, `login_type`), serialization            |
|     - Attached to `Mission.test_identities: list[TestIdentity]` in `argus/runtime/mission.py`     |
|     - Mission helper methods: `add_test_identity()`, `get_active_identity()`, etc.               |
|                                                                                                   |
|  4. Persistent `AuthenticatedHttpClient` (`argus/http/client.py`)                                 |
|     - Extends `AuthorizedHttpClient` for 100% backward compatibility                              |
|     - Persistent `httpx.Client` session with automatic cookie jar management                      |
|     - Strict scope gating before credential transmission (zero token leakage)                     |
|     - Identity injection from active `TestIdentity` (headers, cookies, tokens)                    |
|     - Automated `login()` method supporting JSON and Form authentication flows                    |
|     - Proxy support (`proxy`) and retry policies with backoff                                     |
|                                                                                                   |
|  5. Test Suite & Verification                                                                     |
|     - Zero regression on existing 578 tests                                                       |
|     - 68 new tests covering DNSX, Takeover DB, TestIdentity, and AuthenticatedHttpClient          |
|     - Total 646 tests passing                                                                     |
+---------------------------------------------------------------------------------------------------+
```

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| 1 | `DNSXTool` wrapper & parser | CLI wrapper for `dnsx` + `ReconParser.parse_dnsx` + tool registry | M1 | survey |
| 2 | Subdomain Takeover DB (26 signatures) | Structured signatures with CNAME regex, body fingerprints, status codes, NXDOMAIN flags | M1 | survey |
| 3 | Subdomain Takeover Collector & Evidence | `SubdomainTakeoverCollector` producing `Evidence(category="subdomain_takeover", severity="critical")` | M1 | survey |
| 4 | Graph Vulnerability Edges | `AttackSurfaceGraphBuilder` creates vulnerability nodes and `HAS_VULNERABILITY` edges | M1 | survey |
| 5 | `TestIdentity` Model | Dataclass model with `AuthType`, credentials, tokens, cookies, serialization, clone | M2 | survey |
| 6 | `Mission.test_identities` Integration | `Mission` fields + helper methods (`add_test_identity`, `get_active_identity`, etc.) + pickle safety | M2 | survey |
| 7 | Persistent `AuthenticatedHttpClient` | Session cookie jar, scope gating, identity injection, automated `login()` for JSON/Form, proxy & retries | M2 | survey |
| 8 | Comprehensive Unit & Integration Tests | 68 new tests verifying DNSX, Takeover DB, Graph edges, TestIdentity, and AuthenticatedHttpClient | M3 | survey |
| 9 | Full Regression Victory Audit | 100% pass on all 646 tests with zero regressions | M3 | survey |

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| 1 | Subdomain Takeover & DNSX Engine | `argus/tools/dnsx.py`, `argus/recon/takeover_fingerprints.py`, `argus/collectors/takeover.py`, `argus/runtime/parser.py`, `argus/runtime/registry.py`, `argus/graph/attack_surface.py` | none | DONE |
| 2 | TestIdentity Model & Authenticated HTTP Client | `argus/models/test_identity.py`, `argus/models/__init__.py`, `argus/models/identity.py`, `argus/runtime/mission.py`, `argus/http/client.py`, `argus/http/__init__.py` | none | DONE |
| 3 | Test Suite Expansion & Victory Audit | `tests/test_dnsx.py`, `tests/test_subdomain_takeover.py`, `tests/test_test_identity.py`, `tests/http/test_authenticated_http_client.py`, `tests/graph/test_takeover_graph.py`, `tests/http/test_sprint4_empirical_stress.py` | M1, M2 | DONE |

## Code Layout
- `argus/tools/__init__.py`: Exports `DNSXTool`, `DNSResult`
- `argus/tools/dnsx.py`: DNSX CLI wrapper
- `argus/recon/takeover_fingerprints.py` & `argus/collectors/takeover_signatures.py`: 26 service signatures
- `argus/collectors/takeover.py`: Subdomain takeover collector
- `argus/collectors/__init__.py`: Exports `SubdomainTakeoverCollector`
- `argus/runtime/parser.py`: `ReconParser.parse_dnsx`
- `argus/runtime/registry.py`: `dnsx` tool registration
- `argus/graph/attack_surface.py`: `subdomain_takeover` node and edge generation
- `argus/models/test_identity.py`: `TestIdentity` dataclass & `AuthType` enum
- `argus/models/__init__.py` & `argus/models/identity.py`: Exports `TestIdentity`, `AuthType`
- `argus/runtime/mission.py`: `Mission.test_identities` and helpers
- `argus/http/client.py`: `AuthenticatedHttpClient`
- `argus/http/__init__.py`: Exports `AuthenticatedHttpClient`
- `tests/test_dnsx.py`: Tests for `DNSXTool` and parser
- `tests/test_subdomain_takeover.py`: Tests for Subdomain Takeover Collector & Signatures
- `tests/test_test_identity.py`: Tests for `TestIdentity` and `Mission` integration
- `tests/http/test_authenticated_http_client.py`: Tests for `AuthenticatedHttpClient`
- `tests/graph/test_takeover_graph.py`: Tests for takeover graph nodes and edges
- `tests/http/test_sprint4_empirical_stress.py`: Comprehensive stress test suite
