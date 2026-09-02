# ARGUS Sprint Handoff — Sprint 29 Complete (All Planned Sprints Done)

> **This file is self-contained.** A new agent with zero prior context can execute the next sprint from this file alone.
> **Instructions for user:** Open a new conversation and say:
> `Read /home/varun/argus/.agents/sprint_handoff.md and launch the sprint`

---

## Current State of ARGUS

**Test baseline:** 1,992 passing tests (`python -m pytest tests/ --ignore=tests/workspace -x -q`)
**Working directory:** `/home/varun/argus`
**Integrity mode:** benchmark (all sprints use this)

---

## Completed Sprints Summary

| Sprint | Engine | Tests After | Key Files Created |
|--------|--------|:-----------:|-------------------|
| 0–3 | Mission Loop, DAG, Attack Surface Graph, Graph-Aware Reasoning | 578 | `argus/runtime/mission.py`, `argus/graph/attack_surface.py`, `argus/planning/task_generator.py` |
| 4 | CNAME Takeover + Auth Foundation (TestIdentity, AuthenticatedHttpClient) | 646 | `argus/models/test_identity.py`, `argus/http/client.py`, `argus/collectors/takeover.py` |
| 5 | Information Disclosure (`.env`, `.git`, actuator fuzzing, secret extraction) | 701 | `argus/collectors/information_disclosure.py` |
| 6 | Access Control / IDOR (Multi-Identity Sessions, Response Discrepancy Analyzer) | 749 | `argus/collectors/access_control.py`, `argus/http/coordinator.py` |
| 8 | Path Traversal (payload mutations, OS file signatures) | 861 | `argus/collectors/path_traversal.py` |
| 9 | SQL Injection (error-based, boolean-blind, time-blind, WAF bypass) | 896 | `argus/collectors/sql_injection.py` |
| 10 | XSS (reflected, stored, context-aware) + Environment Detector | 996 | `argus/collectors/xss.py`, `argus/utils/environment.py` |
| 11 | Command Injection (result-based, time-blind, separator mutations) | 1,071 | `argus/collectors/command_injection.py` |
| 12 | SSRF (cloud metadata AWS/GCP/Azure, internal service banners, 9 bypass strategies) | 1,127 | `argus/collectors/ssrf.py` |
| 13 | OAuth/OIDC (JWT alg:none, key confusion, redirect_uri, CSRF state, session security) | 1,196 | `argus/collectors/oauth.py` |
| 14 | Reporting Engine (HackerOne Markdown, JSON, CVSS v3.1, mission lifecycle hooks) | 1,258 | `argus/reporting/generator.py`, `argus/reporting/cvss.py`, `argus/reporting/markdown.py` |
| 15 | XML Parser Security / XXE (entity resolution, parameter entities, recursive expansion, 6 bypass strategies) | 1,307 | `argus/collectors/xml_parser.py` |
| 16 | Insecure Deserialization (Java aced0005, Python pickle, PHP serialize, Ruby Marshal, .NET ViewState, 6 bypass strategies) | 1,352 | `argus/collectors/deserialization.py` |
| 17 | GraphQL Security (Introspection, Depth DoS, Array/Alias Batching, BOPLA, 6 bypass strategies) | 1,425 | `argus/collectors/graphql.py`, `tests/collectors/test_graphql.py`, `tests/collectors/test_graphql_adversarial.py` |
| 18 | WebSocket Security (CSWSH, Handshake Auth, Query Token Leakage, Frame SQLi/CMDi/XSS/Proto-Pollution, DoS/Unmasked Frames, 6 bypass strategies) | 1,476 | `argus/collectors/websocket.py`, `tests/collectors/test_websocket.py`, `tests/collectors/test_websocket_adversarial.py` |
| 19 | HTTP Request Smuggling (CL.TE, TE.CL, TE.TE Obfuscations, HTTP/2 Downgrading H2.CL/H2.TE/CRLF, Timing/Pipeline Probing, 6 bypass strategies) | 1,515 | `argus/collectors/request_smuggling.py`, `tests/collectors/test_request_smuggling.py`, `tests/collectors/test_request_smuggling_adversarial.py` |
| 20 | Race Conditions & Concurrency Vulnerabilities (Limit Overrun, TOCTOU, Session Concurrency, Multi-Endpoint, Differential State Verification, HTTP/2 Single-Packet, Microsecond Barrier) | 1,572 | `argus/collectors/race_conditions.py`, `tests/collectors/test_race_conditions.py`, `tests/collectors/test_race_conditions_adversarial.py` |
| 21 | Business Logic Flaws & State Machine Security (Price/Quantity Tampering, State Skips, Mass Assignment, Coupon Stacking, Differential Invariants, 5 Mutation Strategies) | 1,614 | `argus/collectors/business_logic.py`, `tests/collectors/test_business_logic.py`, `tests/collectors/test_business_logic_adversarial.py` |
| 22 | Server-Side Template Injection / SSTI (18 Engine Families, Polyglot Arithmetic, Differential Tree Routing, Sandbox Escapes, Error Fingerprinting, 5 Mutation Strategies) | 1,648 | `argus/collectors/ssti.py`, `tests/collectors/test_ssti.py`, `tests/collectors/test_ssti_adversarial.py` |
| 23 | Web Cache Poisoning & Cache Deception (8 Vuln Types, 7 CDN/Cache Engine Families, 4-Step Differential Confirmation, 5 Mutation Strategies, CVSS CWE-444/CWE-524) | 1,678 | `argus/collectors/cache_security.py`, `tests/collectors/test_cache_security.py`, `tests/collectors/test_cache_security_adversarial.py` |
| 24 | Scan Orchestration Engine (ScanEngine, DAG topological sort, collector dispatch, lifecycle state machine, report consolidation) | 1,740 | `argus/scanning/engine.py`, `argus/scanning/dag.py`, `argus/scanning/models.py`, `argus/runtime/state_machine.py`, `tests/scanning/test_scan_engine.py`, `tests/scanning/test_scan_engine_adversarial.py` |
| 25 | CORS Misconfiguration & HTTP Security Header Audit (6 CORS Detection Modes, 8 Header Audits, Origin Parser Differentials, 5 Mutation Strategies, CWE-942/CWE-693/CWE-1021) | 1,784 | `argus/collectors/cors_security.py`, `argus/collectors/cors_headers.py`, `tests/collectors/test_cors_security.py`, `tests/collectors/test_cors_security_adversarial.py`, `tests/graph/test_cors_graph_pipeline_adversarial.py` |
| 26 | File Upload Vulnerability Detection (6 Upload Detection Modes, Upload Response Analysis, 5 Mutation/Evasion Strategies, CWE-434/CWE-436) | 1,828 | `argus/collectors/file_upload.py`, `tests/collectors/test_file_upload.py`, `tests/collectors/test_file_upload_adversarial.py` |
| 27 | API Security Testing REST/gRPC (Parameter Tampering, Mass Assignment, BOLA/IDOR, Rate Limiting Bypass, Excessive Data Exposure, Method Tampering, 5 Mutation Strategies, CWE-639/CWE-915/CWE-770) | 1,862 | `argus/collectors/api_security.py`, `tests/collectors/test_api_security.py`, `tests/collectors/test_api_security_adversarial.py` |
| 28 | Authentication Bypass & Credential Attacks (Brute Force, Password Reset Abuse, MFA Bypass, Session Fixation, JWT Manipulation, Default Credentials, Shannon Entropy Analysis, 5 Mutation Strategies, CWE-287/CWE-307/CWE-384/CWE-640) | 1,929 | `argus/collectors/auth_bypass.py`, `tests/collectors/test_auth_bypass.py`, `tests/collectors/test_auth_bypass_pipeline.py`, `tests/collectors/test_auth_bypass_adversarial.py` |
| **29** | **Prototype Pollution & Client-Side Attacks (Server/Client Prototype Pollution, DOM Clobbering, Open Redirect Chains, Clickjacking, Gadget Analysis, 5 Mutation Strategies, CWE-1321/CWE-79/CWE-601/CWE-1021)** | **1,992** | **`argus/collectors/prototype_pollution.py`, `tests/collectors/test_prototype_pollution.py`, `tests/collectors/test_prototype_pollution_adversarial.py`, `tests/collectors/test_prototype_pollution_pipeline.py`** |

---

## Remaining Roadmap

All planned sprints (0–29) have been completed. The ARGUS platform now covers 26 vulnerability detection modules with 1,992 passing tests.

---

## Key Architecture Patterns (for the new agent)

- **Collectors** follow the tripartite pattern in `argus/collectors/ssti.py`, `argus/collectors/business_logic.py`, `argus/collectors/race_conditions.py`, `argus/collectors/request_smuggling.py`, `argus/collectors/websocket.py`, `argus/collectors/graphql.py`, `argus/collectors/auth_bypass.py`:
  - `NewCollector(BaseCollector)` inheriting from `argus/collectors/base.py`
  - `NewPayloadGenerator` generating attack payloads
  - `NewAnalyzer` identifying vulnerabilities and suppressing false positives
- **Registration:** add tool and aliases to `argus/runtime/registry.py` AND fallback in `argus/runtime/plugins.py`
- **DAG scheduling:** add template to `_RECON_TEMPLATES` in `argus/planning/task_generator.py` with dependency `["Discover API Endpoints"]`
- **Graph edges:** create `HAS_VULNERABILITY` and `HAS_ENDPOINT` edges in `argus/graph/attack_surface.py` connecting `live_host` and `endpoint` to `vulnerability` node
- **Evidence:** use `EvidenceStore` (at `argus/evidence/store.py`) to record findings with status `CONFIRMED`
- **CVSS & CWE:** map vulnerability types in `argus/reporting/cvss.py`
- **AuthenticatedHttpClient** in `argus/http/client.py` enforces scope boundaries
- **ScanEngine** in `argus/scanning/engine.py` orchestrates the full DAG -> collector dispatch -> report generation pipeline

## Orchestration Rules

Read `/home/varun/argus/.agents/rules/user_global.md` before starting. Key rules:
- **ZERO intermediate messages** — subagents ONLY message on task completion or unrecoverable blocker
- **Post-sprint verification** — run test suite + functional mock test + DAG/registry connectivity check
- **Update this file** after sprint completes

---

## Sprint 29 — Completed (2026-09-02)

Sprint 29 was executed via teamwork_preview and completed with orchestrator-level post-sprint fixes.

**Results:**
- 1,992 tests passing (63 new, 0 regressions)
- All 5 detection modes implemented (server/client prototype pollution, DOM clobbering, open redirects, clickjacking)
- Gadget analysis for Express, Lodash, jQuery, Handlebars frameworks
- 5+ mutation/evasion strategies
- Full pipeline connectivity verified (registry, DAG, graph edges, CWE mappings)
- Handoff at `.agents/sprint29_prototype_pollution/handoff.md`

---

## All Planned Sprints Complete

All 30 sprints (0–29) have been completed. The ARGUS platform includes 26 vulnerability detection modules with 1,992 passing tests.
