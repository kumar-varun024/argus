# ARGUS Sprint Handoff — Sprint 31c Complete

> **This file is self-contained.** A new agent with zero prior context can execute the next sprint from this file alone.
> **Instructions for user:** Open a new conversation and say:
> `Read /home/varun/argus/.agents/sprint_handoff.md and launch the sprint`

---

## Current State of ARGUS

**Test baseline:** 2,356 passing tests (`python -m pytest tests/ --ignore=tests/workspace -x -q`)
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
| 29 | Prototype Pollution & Client-Side Attacks (Server/Client Prototype Pollution, DOM Clobbering, Open Redirect Chains, Clickjacking, Gadget Analysis, 5 Mutation Strategies, CWE-1321/CWE-79/CWE-601/CWE-1021) | 1,992 | `argus/collectors/prototype_pollution.py`, `tests/collectors/test_prototype_pollution.py`, `tests/collectors/test_prototype_pollution_adversarial.py`, `tests/collectors/test_prototype_pollution_pipeline.py` |
| 30 | Scanner Glue & Burp MCP (CLI Entry Point, Scan Command, Scope Defaulting, Recon Fallback, Burp Suite MCP Server, Dependency & AI Stub Cleanup) | 2,089 | `argus/__main__.py`, `argus/cli/app.py`, `argus/bridges/burp/server.py`, `argus/bridges/burp/proxy.py`, `argus/bridges/burp/importer.py`, `argus/bridges/burp/scanner.py`, `argus/bridges/burp/collaborator.py` |
| 31a | Conversational Memory System & Vector Recall (MemoryEntry, MemoryStore, MemoryManager, ResearchContextEngine Integration) | 2,261 | `argus/memory/models.py`, `argus/memory/store.py`, `argus/memory/manager.py`, `argus/memory/__init__.py`, `tests/memory/test_memory.py`, `tests/memory/test_memory_adversarial.py`, `tests/memory/test_memory_integration.py` |
| **31b** | **CLI Search & End-to-End Vector RAG Integration Tests (`argus search`, `argus/cli/search_cli.py`, `tests/vector/test_rag_integration.py`, `tests/cli/test_search_cli.py`)** | **2,311** | **`argus/cli/search_cli.py`, `argus/cli/app.py`, `tests/vector/test_rag_integration.py`, `tests/cli/test_search_cli.py`** |
| **31c** | **Adversarial RAG Pipeline Tests (Poisoned Findings, Deceptive CVEs, Prompt Injection Resilience, Embedding Robustness, Cross-Source Contamination, Ranking Manipulation)** | **2,356** | **`tests/vector/test_rag_adversarial.py`, `tests/vector/test_rag_prompt_injection.py`, `tests/vector/test_embedding_robustness.py`** |

---

## Remaining Roadmap

All planned sprints are complete. The ARGUS Vector RAG subsystem is fully implemented and hardened.

---

## Key Architecture Patterns (for the new agent)

- **Vector Store:** `argus/vector/store.py` (`VectorStore`, `get_vector_store()`) backed by SQLite with native sqlite-vec or NumPy vector fallback.
- **Embeddings:** `argus/vector/embeddings.py` (`EmbeddingEngine`) providing deterministic 384-d feature hashing & concept clustering offline.
- **Search CLI:** `argus/cli/search_cli.py` registered as `search` subcommand in `argus/cli/app.py`.
- **Finding Indexer & Search:** `argus/reporting/vector_indexer.py` (`ScanEvidenceIndexer`, `FindingSemanticSearchEngine`).
- **CVE KB & Correlator:** `argus/knowledge/cve_kb.py`, `argus/knowledge/cve_correlator.py`.
- **Conversational Memory:** `argus/memory/` (`MemoryManager`, `MemoryStore`, `MemoryEntry`).
- **Research Context Engine:** `argus/workspace/context/engine.py` (`ResearchContextEngine`).

## Orchestration Rules

Read `/home/varun/argus/.agents/rules/user_global.md` before starting. Key rules:
- **ZERO intermediate messages** — subagents ONLY message on task completion or unrecoverable blocker
- **Post-sprint verification** — run test suite + functional mock test + DAG/registry connectivity check
- **Update this file** after sprint completes

---

## Sprint 31c — Completed (2026-09-04)

Sprint 31c was executed to implement adversarial RAG pipeline evaluations, prompt injection resilience tests, and embedding retrieval robustness test suites.

**Results:**
- **2,356 tests passing across the codebase** (45 new tests, 0 regressions).
- `tests/vector/test_rag_adversarial.py` (17 tests): Poisoned finding injection (SQL payloads, XSS, null bytes, RTL overrides, verbatim storage), deceptive CVE records (misleading descriptions, empty/None fields, 10K char descriptions, correlator resistance), embedding collision attacks (lexical overlap, ranking differentiation, stability), cross-source contamination (source-type filtering between findings/CVEs/memory), ranking manipulation (keyword stuffing, query repetition, long queries), large-scale stress (500+ documents, concurrent indexing & searching).
- `tests/vector/test_rag_prompt_injection.py` (12 tests): Stored prompt injection in findings (title, description, impact with exact preservation), prompt injection in CVE descriptions & references (CVEKnowledgeBase and CVECorrelator handling), prompt injection in memory (MemoryManager recall, lifecycle, archive, supersede), ResearchContextEngine injection (injection queries, injection data isolation, template preservation), nested/chained injection (JSON + Base64, control codes, null bytes, Unicode).
- `tests/vector/test_embedding_robustness.py` (16 tests): Unicode normalization forms (NFC/NFD/NFKC/NFKD, CJK, Arabic, emoji, zero-width), null/control characters, extreme length inputs (empty to 100K+), homoglyph attacks (Latin vs Cyrillic, lookalike domains), security taxonomy coverage (synonym pairs, multi-word concepts, abbreviations), determinism & idempotency (100 repeated calls, batch vs single), distance metric consistency (self-similarity, range bounds, semantic ordering).
- Handoff report written to `.agents/swe_sprint31c/handoff.md`.

---

## Sprint 31b — Completed (2026-09-03)

Sprint 31b was executed to implement the `argus search` CLI command group and comprehensive end-to-end Vector RAG integration tests.

**Results:**
- **2,311 tests passing across the codebase** (50 new tests: 28 vector RAG integration, 22 CLI search, 0 regressions).
- `argus/cli/search_cli.py`: Complete CLI command group built with Typer and Rich:
  - `argus search <query>`: Cross-source semantic search across findings, evidence, CVEs, and memory with Rich table output (Score, Type, Severity, Title/Content, Category) and raw JSON array output (`--json`). Supports filtering by `--type`, `--severity`, `--category`, `--mission`, `--top-k`, `--min-score`, and `--verbose` (`-v`).
  - `argus search cves <query>`: Specialized CVE semantic search shortcut with `--cwe` and `--product` post-filtering.
  - `argus search memory <query>`: Specialized memory recall shortcut with `--memory-type` filtering.
  - `argus search stats`: Index statistics displaying document counts by source type, total document count, vector database path, dimension, metric, and embedding provider name.
- `argus/cli/app.py`: Registered `search_app` under name `"search"`.
- `tests/vector/test_rag_integration.py`: 28 end-to-end integration tests verifying finding indexing & search, CVE ingestion & CVECorrelator matching, memory recall & lifecycle, cross-source unified queries, ResearchContextEngine multi-source resolution, round-trip persistence across store reopening, and multi-field filter composition.
- `tests/cli/test_search_cli.py`: 22 CLI integration tests verifying table formatting, `--json` serialization, error handling, empty results, subcommands (`cves`, `memory`, `stats`), and CLI registration.
- Handoff reports written to `.agents/implementer_r1/handoff.md` and `.agents/swe_sprint31b/handoff.md`.

