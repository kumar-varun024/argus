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

## 2026-09-02T17:42:49Z

Make ARGUS a fully functional, end-to-end security scanner by fixing the critical integration gaps preventing real-world scanning, adding Burp Suite integration via an MCP server, and cleaning up legacy AI stubs. ARGUS already has 33+ vulnerability collectors, a DAG-based scan engine, real HTTP client, and report generation — this sprint wires them into a usable product.

Working directory: /home/varun/argus
Integrity mode: development

## Requirements

### R1. CLI Entry Point & Scan Command
ARGUS currently has no way to launch a scan from the command line. A user must be able to run a command like `python -m argus scan <target>` that initializes a mission, executes the full ScanEngine DAG pipeline, and outputs a summary with report file paths. The existing CLI framework (Typer + Rich in `argus/cli/app.py`) should be extended, and a root `argus/__main__.py` entry point must be created.

### R2. Scope Defaulting & Recon Fallback
Two bugs block real-world scanning: (1) `Mission.scope` initializes as an empty list, causing `ScopeResolver` to block all HTTP requests — scope must auto-populate from the target on mission creation. (2) When external Go recon binaries (`subfinder`, `httpx-toolkit`, `katana`, `nuclei`) are not installed, the recon collectors exit immediately and the entire DAG skips all vulnerability collectors. A Python-native fallback must seed the target directly into live_hosts/endpoints so vulnerability collectors still execute.

### R3. Burp Suite MCP Server Integration
Build an MCP (Model Context Protocol) server that bridges ARGUS with Burp Suite Professional. The MCP server should expose tools for: (a) Proxy traffic routing — configure ARGUS's `AuthenticatedHttpClient` to route requests through Burp's proxy for logging and interception, (b) Import Burp scan results into ARGUS's evidence store, (c) Launch Burp active scans from ARGUS and poll for results, (d) Burp Collaborator / OAST callback registration and polling for out-of-band vulnerability detection. The MCP server should be launchable as a standalone process that ARGUS can connect to.

### R4. Dependency & Stub Cleanup
Fix undeclared dependencies in `pyproject.toml` — `httpx` and `python-dotenv` are imported throughout the codebase but not listed. Clean up legacy AI stubs: `argus/ai/openai_client.py` (empty 0-byte file), `argus/ai/gemini_client.py` (missing file with silenced import error), and `argus/memory/` (empty directory with no code). Either implement minimal functional versions or consolidate into the existing `argus/workspace/provider.py` architecture.

### R5. Zero Regression & Validation
All 1,992 currently passing tests must continue to pass. Write tests for the new CLI scan command, scope defaulting fix, recon fallback behavior, and Burp MCP server tools. Write handoff to `.agents/sprint30_scanner_glue/handoff.md`.

## Acceptance Criteria

### CLI & Entry Point
- [ ] `python -m argus` launches the CLI without errors.
- [ ] `python -m argus scan --help` displays scan command usage.
- [ ] The scan command accepts a target URL/domain and initiates ScanEngine execution.
- [ ] Scan output includes a summary table with finding counts by severity and report file paths.

### Scope & Recon
- [ ] Creating a Mission with `target="example.com"` auto-populates scope so that requests to `example.com` are not blocked by ScopeResolver.
- [ ] When `subfinder` binary is not in PATH, the scan still proceeds by seeding the target directly as a live host.
- [ ] Vulnerability collectors execute even when no external recon tools are installed.

### Burp MCP Server
- [ ] An MCP server process can be started that exposes Burp integration tools.
- [ ] A proxy configuration tool exists that can set the upstream proxy on AuthenticatedHttpClient.
- [ ] A tool exists to import Burp scan results (XML/JSON) into ARGUS evidence store.
- [ ] A tool exists to trigger Burp active scans and retrieve results.
- [ ] A tool exists for Burp Collaborator OAST callback registration and polling.
- [ ] MCP server has tests verifying tool schemas and basic request/response handling.

### Dependencies & Stubs
- [ ] `httpx` and `python-dotenv` are listed in pyproject.toml dependencies.
- [ ] No empty/broken stub files remain in `argus/ai/` — all files either contain functional code or are removed.
- [ ] `argus/memory/` is either implemented with minimal functionality or removed.

### Regression
- [ ] `python -m pytest tests/ --ignore=tests/workspace -x -q` exits 0 with 1,992+ tests passing and 0 regressions.
- [ ] At least 15 new tests added covering CLI, scope, recon fallback, and MCP tools.
- [ ] Handoff written to `.agents/sprint30_scanner_glue/handoff.md`.

## 2026-09-03T01:51:06+05:30

Add a Vector RAG (Retrieval-Augmented Generation) and Semantic Search system to the ARGUS security assessment platform. ARGUS currently has a keyword/graph-based context engine in `argus/workspace/context/` that powers its interactive copilot. This sprint upgrades it with vector embeddings and semantic retrieval using SQLite-vec (file-based, zero external services), enabling the platform to learn and grow from every scan and conversation.

Working directory: /home/varun/argus
Integrity mode: development

## Requirements

### R1. Embedding & Vector Store Engine
Build a vector store backed by SQLite-vec that can generate embeddings, store them, and perform semantic similarity search. The system must be file-based with no external services required — embeddings should be generated locally (e.g., sentence-transformers or similar lightweight model). The store must support inserting documents with metadata, querying by semantic similarity with configurable top-k, and filtering by metadata fields (source type, mission ID, severity, etc.).

### R2. Semantic Search Over Scan Evidence & Findings
Index all collected evidence and confirmed findings from ARGUS scans into the vector store. Users and the copilot should be able to search findings semantically — e.g., "authentication bypass via parameter tampering" should retrieve relevant SQLi, IDOR, and auth bypass findings even if those exact words weren't used. Historical scan reports should also be indexed so the system can recognize patterns across engagements.

### R3. CVE & Vulnerability Knowledge Base
Build an indexable knowledge base for CVE data and vulnerability intelligence. The system should be able to ingest CVE records (from JSON feeds or local files), embed their descriptions, and allow semantic search — e.g., "remote code execution in Java deserialization" should surface relevant CVEs. This enriches the copilot's responses and supports automated finding-to-CVE correlation.

### R4. Enhanced Workspace Copilot Integration
Upgrade the existing `ResearchContextEngine` in `argus/workspace/context/` to use semantic retrieval alongside the existing keyword/graph retrieval. The context ranker should blend vector similarity scores with the existing lexical scoring. The copilot should return more relevant, contextually rich responses by retrieving semantically similar evidence, findings, and knowledge base entries.

### R5. Conversational Learning & Growth
Implement a memory system that learns from every conversation and scan. Key interactions, decisions, successful attack patterns, and user corrections should be embedded and stored. Over time, the system should surface relevant past experiences — e.g., if the user previously found an SSRF on a similar target architecture, the copilot should recall and suggest similar approaches. This replaces the empty `argus/memory/` stub that was removed in Sprint 30.

### R6. Zero Regression & Validation
All 2,089 currently passing tests must continue to pass. Write tests for the vector store engine, semantic search accuracy, CVE indexing, copilot integration, and conversational memory. Add `sqlite-vec` and any embedding dependencies to `pyproject.toml`. Write handoff to `.agents/sprint31_vector_rag/handoff.md`.

## Acceptance Criteria

### Vector Store
- [ ] SQLite-vec backed vector store can insert documents with embeddings and metadata.
- [ ] Semantic similarity search returns top-k results ranked by cosine similarity.
- [ ] Metadata filtering works (e.g., filter by mission_id, severity, source_type).
- [ ] Store persists to disk and survives process restarts.

### Evidence & Finding Search
- [ ] Scan evidence and confirmed findings are indexed into the vector store after scan completion.
- [ ] Semantic query for a vulnerability concept retrieves relevant findings even without exact keyword match.
- [ ] Historical scan reports are indexable and searchable.

### CVE Knowledge Base
- [ ] CVE records can be ingested from JSON and indexed with embeddings.
- [ ] Semantic search over CVEs returns relevant entries by description similarity.
- [ ] Finding-to-CVE correlation suggestions are available.

### Copilot Integration
- [ ] `ResearchContextEngine` retrieves context via semantic similarity in addition to keyword matching.
- [ ] Context ranker blends vector scores with existing lexical scores.
- [ ] Copilot responses include semantically relevant evidence that keyword search would miss.

### Conversational Learning
- [ ] Key interactions and user corrections are embedded and stored.
- [ ] Past relevant experiences are surfaced when similar contexts arise.
- [ ] Memory persists across sessions.

### Regression
- [ ] `python -m pytest tests/ --ignore=tests/workspace -x -q` exits 0 with 2,089+ tests passing and 0 regressions.
- [ ] At least 20 new tests added covering vector store, semantic search, CVE indexing, copilot integration, and memory.
- [ ] `sqlite-vec` and embedding dependencies declared in `pyproject.toml`.
- [ ] Handoff written to `.agents/sprint31_vector_rag/handoff.md`.

## Follow-up — 2026-09-03T11:17:33Z

Sprint 31b for the ARGUS security scanner: Add the `argus search` CLI command for semantic search across all vector-indexed sources (findings, evidence, CVEs, memory) and write comprehensive end-to-end integration tests connecting all Vector RAG components. This is a single self-contained change within a well-defined architecture; keep it small and focused.

Working directory: /home/varun/argus
Integrity mode: development

## Requirements

### R1. CLI `argus search` Command

Add a new `search` CLI command group to ARGUS (`argus/cli/search_cli.py`) registered in `argus/cli/app.py`. The CLI must use Typer (already a dependency) and Rich (already a dependency) for output formatting. Commands:

- **`argus search <query>`**: Semantic search across all indexed sources (findings, evidence, CVEs, memory). Displays results in a Rich table with columns: Score, Type, Severity, Title/Content (truncated), Category. Supports these options:
  - `--type` / `-t`: Filter by source type (`finding`, `evidence`, `cve`, `memory`, or `all` default)
  - `--severity` / `-s`: Filter by severity (`critical`, `high`, `medium`, `low`, `info`)
  - `--category` / `-c`: Filter by category
  - `--mission` / `-m`: Filter by mission ID
  - `--top-k` / `-k`: Number of results (default 10)
  - `--min-score`: Minimum similarity threshold (default 0.0)
  - `--json`: Output raw JSON instead of Rich table
  - `--verbose` / `-v`: Show additional fields (full content, metadata, embeddings info)

- **`argus search cves <query>`**: Shortcut for CVE-specific semantic search. Same options as above but defaults to `--type cve`. Adds `--cwe` filter and `--product` filter.

- **`argus search memory <query>`**: Shortcut for memory-specific search. Same base options. Adds `--memory-type` filter (attack_pattern, user_correction, strategic_decision, session_context, note).

- **`argus search stats`**: Display index statistics — counts by source_type, total documents, vector store path, embedding provider name.

### R2. End-to-End Integration Tests

Write integration tests that verify the complete Vector RAG pipeline works end-to-end across all components:

- **`tests/vector/test_rag_integration.py`**: Tests covering:
  - Index findings via `ScanEvidenceIndexer` → search via `FindingSemanticSearchEngine` → verify results
  - Ingest CVEs via `CVEKnowledgeBase` → search via `search_cves()` → verify correlation
  - Store memories via `MemoryManager` → recall via `recall()` → verify semantic relevance
  - Cross-source search via `VectorStore.search()` spanning findings + CVEs + memory in single query
  - `ResearchContextEngine.resolve()` returning blended results from all sources
  - Round-trip persistence: add → close store → reopen → search → verify results survive
  - Filter composition: combining source_type + severity + mission_id + category filters
  - Minimum 25 test cases

- **`tests/cli/test_search_cli.py`**: CLI integration tests using Typer's `CliRunner`:
  - Basic search returns formatted output
  - `--json` flag produces valid JSON
  - `--type`, `--severity`, `--category` filters work
  - `search cves` and `search memory` subcommands work
  - `search stats` returns counts
  - Empty results handled gracefully
  - Minimum 15 test cases

### R3. CLI Registration

Register the search CLI in `argus/cli/app.py` by adding the search_app typer as a subcommand named "search".

## Existing Architecture (Reference)

These modules are **already fully implemented** and should be used as-is:

- `argus/vector/store.py` — `VectorStore`, `get_vector_store()`
- `argus/vector/embeddings.py` — `EmbeddingEngine`, `get_embedding_engine()`
- `argus/vector/models.py` — `VectorDocument`, `SearchResult`, `VectorFilter`
- `argus/reporting/vector_indexer.py` — `ScanEvidenceIndexer`, `FindingSemanticSearchEngine`
- `argus/knowledge/cve_kb.py` — `CVEKnowledgeBase`
- `argus/knowledge/cve_correlator.py` — `CVECorrelator`
- `argus/memory/store.py` — `MemoryStore`
- `argus/memory/manager.py` — `MemoryManager`, `get_memory_manager()`
- `argus/memory/models.py` — `MemoryEntry`, `MemoryType`, `MemorySearchResult`
- `argus/workspace/context/engine.py` — `ResearchContextEngine`
- `argus/cli/app.py` — Main Typer app with existing subcommand pattern

Follow the existing CLI patterns in `argus/cli/` — use Typer for commands, Rich for formatting.

## Post-Sprint Handoff

After all tests pass, update `/home/varun/argus/.agents/sprint_handoff.md`:
- Add Sprint 31b row to the completed sprints table
- Update the test baseline count
- Update the "Remaining Roadmap" section (Sprint 31c: Adversarial RAG pipeline tests)
- Add a Sprint 31b section with results summary

## Acceptance Criteria

### Test Suite
- [ ] All new tests pass: `python -m pytest tests/vector/test_rag_integration.py tests/cli/test_search_cli.py -x -q`
- [ ] Zero regressions: `python -m pytest tests/ --ignore=tests/workspace -x -q` passes with >= 2,261 tests
- [ ] Minimum 40 new test cases across the 2 test files

### Functional Correctness
- [ ] `python -m argus search "SQL injection"` returns formatted results when findings are indexed
- [ ] `python -m argus search --json "XSS"` returns valid JSON array
- [ ] `python -m argus search cves "buffer overflow" --severity critical` filters correctly
- [ ] `python -m argus search memory "attack pattern" --memory-type attack_pattern` filters correctly
- [ ] `python -m argus search stats` displays document counts by source type
- [ ] Cross-source search returns results from findings, CVEs, and memory in a single query
- [ ] `ResearchContextEngine.resolve()` integration test returns blended multi-source results

### Architecture Compliance
- [ ] CLI uses Typer + Rich (existing dependencies only)
- [ ] No modifications to existing vector store, embedding engine, CVE KB, or memory internals
- [ ] Search CLI registered in `argus/cli/app.py` following existing subcommand pattern



## 2026-09-04T08:14:09Z

Comprehensive deep audit of the Argus codebase against its 78-section feature inventory specification. Argus is an AI-assisted penetration testing and bug-bounty security research platform (~78K lines of Python source, ~59K lines of tests). The audit must verify whether each specified feature is correctly implemented, functional, and tested — or identify it as partial/missing/broken.

Working directory: /home/varun/argus
Integrity mode: development

## Reference Material

The complete 78-section feature inventory specification is provided below in the "Feature Inventory Specification" section. Every section (1–78) must be individually audited.

## Requirements

### R1. Deep Code Audit Against Feature Specification

For every one of the 78 sections in the feature inventory specification, perform a deep audit that:
- Locates the corresponding source files in the `argus/` directory tree
- Inspects the actual code logic (not just file existence) to determine if the described capabilities are implemented
- Checks whether the implementation matches the specification's described behavior, data models, and interfaces
- Identifies stub implementations, placeholder code, or incomplete logic
- Notes any discrepancies between the spec and the actual implementation
- For CLI commands mentioned in the spec, verify the CLI entry points exist and are wired up

### R2. Full Test Suite Execution and Analysis

- Run the complete test suite using `cd /home/varun/argus && python -m pytest tests/ -v --tb=short 2>&1 | head -3000`
- Record the total pass/fail/skip/error counts
- Map test failures to the relevant feature sections
- For each section, note whether dedicated tests exist and whether they pass
- Identify sections with zero test coverage

### R3. Detailed Per-Section Status Report

Produce a single comprehensive markdown report file at `/home/varun/argus/FEATURE_AUDIT_REPORT.md` with:
- A summary dashboard table at the top listing all 78 sections with their status (✅ Implemented / ⚠️ Partial / ❌ Missing / 🔴 Broken)
- Aggregate statistics: total implemented, partial, missing, broken
- For each section, a detailed subsection containing:
  - **Status**: one of ✅ Implemented, ⚠️ Partial, ❌ Missing, 🔴 Broken
  - **Source Files**: links to the relevant source files
  - **Implementation Evidence**: what specifically is implemented and how
  - **Gaps**: what is specified but not implemented or incomplete
  - **Test Coverage**: relevant test files and pass/fail status
  - **Notes**: any architectural concerns, technical debt, or observations

### R4. Executive Summary

Include an executive summary section covering:
- Overall project maturity assessment
- Count of fully implemented vs partial vs missing vs broken features
- Top 10 most critical gaps
- Test suite health (pass rate, coverage areas)
- Key architectural concerns (e.g., the legacy collectors vs Mission Runtime duplication noted in Section 57)
- Recommended prioritization for closing gaps

## Acceptance Criteria

### Report Completeness
- [ ] All 78 sections from the feature inventory are individually addressed in the report
- [ ] No section is skipped or summarized as a group — each gets its own status and evidence
- [ ] The summary dashboard table contains exactly 78 rows

### Audit Depth
- [ ] For each "Implemented" or "Partial" section, the report cites specific source files and describes what the code actually does
- [ ] For each "Missing" section, the report confirms no relevant source code exists
- [ ] For each "Broken" section, the report identifies the specific failure (test failure, import error, etc.)

### Test Execution
- [ ] The full test suite has been executed and results are recorded in the report
- [ ] The total pass/fail/error/skip counts are stated
- [ ] Test failures are mapped to relevant feature sections

### Report Quality
- [ ] The report is written to `/home/varun/argus/FEATURE_AUDIT_REPORT.md`
- [ ] The report uses clear markdown formatting with a navigable table of contents
- [ ] The executive summary provides actionable prioritization guidance

## Verification

An independent verification agent should:
1. Confirm the report file exists at `/home/varun/argus/FEATURE_AUDIT_REPORT.md`
2. Count the number of sections in the report and verify all 78 are present
3. Spot-check 5 random "Implemented" sections by verifying the cited source files exist and contain relevant code
4. Spot-check 3 random "Missing" sections by searching the codebase for related code
5. Verify the test suite results match what the report claims

---

## Feature Inventory Specification

Below is the complete 78-section feature inventory that must be audited. Each section number maps to a required section in the audit report.

### Section 1: Project Identity

**Argus** is an open-source, AI-assisted platform for authorized penetration testing and bug-bounty security research.

Core principles:
- Scope-first execution
- Evidence-backed reasoning
- Deterministic and auditable execution
- AI assists investigation rather than blindly declaring vulnerabilities
- Every finding should be traceable to evidence
- Automated actions must respect mission authorization and policy
- External tools are integrated through controlled execution
- Specialists produce structured investigation opportunities
- Every feature should increase useful vulnerability-hunting capability

### Section 2: Core Architecture

Argus is organized around these major layers:

**Mission → Scope Manager → Policy Engine → Mission Runtime → Scheduler → Agents/Tools → Evidence → Correlation → Investigation → Human Validation → Report**

Major systems:
- Mission Runtime, Scope Manager, Policy Engine, Event Bus, State Store, Configuration, Plugin SDK, Evidence Store, Provenance Engine, Reporting, Knowledge Graph, Workflow Intelligence, Authorization Graph, AI Research, Knowledge Base, Security Research RAG / Intelligence Fabric, Research Cards, Investigation Planner, Multi-Agent Framework, HTTP Engine, Rules Engine, Credential Vault, Session Manager, Asset Inventory, Workspace, Observability, Performance

### Section 3: Mission

A mission is the central unit of security research. It can contain/connect: target scope, execution policy, assets, live hosts, endpoints, technologies, observations, evidence, workflows, business objects, authentication information, authorization information, GraphQL state, JavaScript state, API intelligence, investigations, correlations, tool execution history, artifacts, execution results, execution logs, configuration, notes.

### Section 4: Scope Manager

Scope Manager is a core safety invariant. Capabilities: include/exclude scope, imported bug-bounty scope, program rules, execution policy, passive-only mode, policy validation, agent permission checks, scope validation before execution. No research execution should bypass authorization and policy.

### Section 5: Policy Engine

Responsible for: allowed-operation checks, execution restrictions, passive-only enforcement, tool permission validation, agent permission validation, controlled boundary between planning and execution.

### Section 6: Mission Runtime

Coordinates actual execution: Receive ResearchTask → Resolve compatible tool → Prepare ToolExecutionContext → Enforce mission scope/policy → Execute tool → Monitor execution → Collect results/artifacts → Publish events → Store results → Persist history.

Main components: Tool Registry, Tool Dispatcher, Tool Executors, Execution Monitor, Event Bus, Result Collector, Mission storage.

### Section 7: Tool Registry

Registered tools: subfinder, httpx, katana_crawler, nuclei, graphql_specialist, javascript_specialist, authorization_specialist, authentication_specialist, file_upload_specialist, api_specialist, business_logic_specialist.

Tool metadata includes: ID, name, version, description, supported tasks, required inputs, produced outputs, capabilities, safety requirements, timeout, priority, command, capability.

### Section 8: Tool Dispatcher

Maps ResearchTask categories to compatible tools. Supports: task-category matching, specialist matching, deterministic resolution, priority-aware selection, compatibility lookup, failure logging.

### Section 9: Tool Orchestrator

Handles the execution lifecycle: ResearchTask → resolve_tool() → ToolExecutionContext → monitoring → dispatch → result collection → events → mission storage → persistent history.

Events: TOOL_SELECTED, TOOL_STARTED, TOOL_COMPLETED, TOOL_FAILED, TOOL_TIMED_OUT, TOOL_CANCELLED, ARTIFACTS_PRODUCED.

### Section 10: Event Bus

Provides event-driven communication for: execution lifecycle, logging, observability, decoupling, future automation/learning.

### Section 11: Scheduler

Handles: task ordering, dependencies, task lifecycle, readiness, execution coordination. Task states: PENDING, READY, RUNNING, COMPLETED, FAILED. Tasks can declare dependencies.

### Section 12: Research Task Model

ResearchTask contains: ID, title, description, goal, category, required inputs, expected outputs, priority, confidence, dependencies, required specialists, estimated duration, status, reason, supporting evidence, metadata, creation timestamp.

Task categories: Technology Discovery, API Discovery, GraphQL Analysis, Authentication Analysis, Authorization Analysis, Business Logic Analysis, JavaScript Analysis, Workflow Analysis, Evidence Correlation, Investigation Review, Coverage Improvement.

### Section 13: Research Planning

The planner determines useful next actions from mission state. Core question: "What is the most valuable next research action?"

### Section 14: Gap Analysis Engine

GapAnalyzer checks for missing/incomplete analysis. Current detectors: Technology gaps, API gaps, GraphQL gaps, Authentication gaps, Authorization gaps, Business Logic gaps, JavaScript gaps, Correlation gaps.

### Section 15: Coverage Tracker

Produces CoverageReport tracking: endpoints total/covered, business objects total/covered, workflows total/covered, authentication coverage, authorization coverage, technologies total/covered, overall coverage, gaps, calculation time.

### Section 16: Reconnaissance

Integrated external tools: Subfinder (subdomain discovery), httpx (HTTP probing), Katana (crawler), Nuclei (vulnerability scanning).

### Section 17: Recon Parser

Parsers convert tool output into Argus structures. Subfinder (line-based), httpx (JSONL), Katana (line-based), Nuclei (JSONL with template_id, severity, etc.).

### Section 18: Nuclei Integration

Collector executes `nuclei -u <authorized-host> -silent -jsonl`. Results feed into Argus processing. Scanner output is evidence/observation, not automatically a confirmed vulnerability.

### Section 19: Evidence Store

Evidence is first-class. Sources: HTTP responses, recon, tool output, API analysis, GraphQL, JavaScript, authorization, authentication, business logic, Nuclei, observations, correlations.

### Section 20: Provenance Engine

Tracks lineage from conclusions/artifacts back to sources. Supports: artifact lineage, evidence traceability, investigation traceability, reproducibility, auditability. CLI: `argus trace <artifact_id>`.

### Section 21: Observations & Correlations

Separates observations from conclusions. Observations: API facts, technologies, recon, security behavior, application behavior. Correlations connect observations. CLI: `argus observations`, `argus correlations`, `argus evidence`.

### Section 22: Knowledge Graph

Models interconnected target entities: assets, hosts, endpoints, APIs, business objects, users/roles, workflows, technologies, observations, evidence, investigations.

### Section 23: Workflow Intelligence

Models workflows and state transitions. Supports reasoning about: states, transitions, dependencies, business rules, trust boundaries, object relationships, suspicious/interesting workflow behavior.

### Section 24: Authorization Graph

Models: users, roles, permissions, resources, ownership, relationships, privilege boundaries. Supports: object/function authorization, ownership analysis, permission analysis, role transitions, privilege-boundary investigations.

### Section 25: Business Objects

Models application objects: users, accounts, orders, invoices, projects, files, payments, resources. For business-logic and authorization reasoning.

### Section 26: AI Research

AI as research assistant. Should: understand context, inspect evidence, generate hypotheses, explain reasoning, prioritize investigations, suggest manual validation, connect related observations, avoid unsupported claims. Must remain evidence-backed.

### Section 27: Security Research RAG / Intelligence Fabric

RAG as first-class subsystem. Subsections 27.1-27.16 covering: Research Sources, Ingestion Pipeline, Knowledge Representations, Retrieval Modes, Hybrid Retrieval, Graph RAG, Evidence RAG, Research Context Builder, Reranking, Grounding/Citations, RAG Confidence, Knowledge Freshness, Privacy/Scope-Aware Retrieval, Pluggable RAG Providers, RAG Evaluation, RAG Failure Handling.

### Section 28: Research Cards

Structured security research ideas: hypothesis, evidence, affected assets, confidence, reasoning, methodology, suggested validation, vulnerability classification.

### Section 29: Vulnerability Intelligence Engine

Transforms Knowledge Graph + Workflow Intelligence + Authorization Graph + Evidence into Investigation Hypotheses. Outputs: investigation, confidence, priority, reasoning, evidence, manual validation guidance, CWE, OWASP mapping. Must NOT automatically confirm vulnerabilities.

### Section 30: Methodology Engine

Encodes expert methodology through playbooks: Authorization Review, Business Logic Review, Authentication Review, Session Review, API Review, Workflow Review, File Upload Review, Information Disclosure Review. Playbooks contain: steps, required evidence, actions, expected outputs, plugin/tool support.

### Section 31: Authorization Specialist

Analyzes: object authorization, function authorization, ownership, roles, permissions, privilege boundaries, role transitions. Produces investigation objects.

### Section 32: Business Logic Specialist

Analyzes: workflow states, transitions, business rules, object dependencies, trust boundaries. Components: workflow, states, objects, transitions, heuristics, planner.

### Section 33: API Intelligence Specialist

Supports: REST, OpenAPI, Swagger, GraphQL integration, gRPC parsers. Analyzes: resources, CRUD, nested resources, ownership, relationships, schemas, versions, operations, authentication, pagination, filtering, bulk operations. CLI: `argus api inventory/graph/resources/explain`.

### Section 34: GraphQL Specialist

Models: endpoints, schemas, queries, mutations, types, fields, relationships, security-relevant structure. CLI: `argus graphql`. Gap analysis for GraphQL without analyzed schemas.

### Section 35: JavaScript Intelligence

Intended: endpoint extraction, route discovery, configuration discovery, application object discovery, technology clues, security-relevant relationships. CLI: `argus javascript`.

### Section 36: Authentication Specialist

Focus: authentication workflows, login behavior, authentication state, session relationships, authentication investigation opportunities.

### Section 37: File Upload Specialist

Analyzes: upload workflows, file/object relationships, validation logic, storage behavior, content-processing workflows, upload-related investigation opportunities.

### Section 38: Plugin SDK

Plugins support: registration, capabilities, task categories, inputs, outputs, execution, safety requirements, CLI integration.

### Section 39: Controlled Plugin Execution

Plugin execution uses controlled mission context (ControlledMission). Keeps specialist execution connected to mission constraints.

### Section 40: Credential Vault

Controlled credential storage/access. Prevent credentials from scattering through logs/configuration/state.

### Section 41: Session Manager

Supports: authenticated research, session state, session reuse, authentication workflows, controlled session handling.

### Section 42: HTTP Engine

Structured HTTP interaction for: requests, responses, evidence, provenance, controlled interaction with authorized targets.

### Section 43: Rules Engine

Deterministic: heuristics, policy checks, investigation rules, pattern matching, security logic. Complements AI reasoning.

### Section 44: Configuration

Centralized configuration for: tools, runtime, policies, execution, plugins, missions. Deterministic and auditable.

### Section 45: Observability

Tracks: logs, execution events, tool runs, timings, failures, artifacts, history. Execution history persisted under `.argus/tool_history.json`.

### Section 46: Performance

Performance tooling/CLI measures: execution duration, monitoring overhead, scheduler behavior, runtime performance, research throughput.

### Section 47: Workspace

Unified researcher interface. CLI: `argus workspace`. Exposes missions, evidence, investigations, and research state.

### Section 48: CLI Surface

Namespaces: knowledge, queue, workflow, auth, agent, execution, plugin, provenance, mission, intelligence, playbooks, business, api, authn, upload, tools, graphql, javascript, observations, correlations, benchmark, workspace, evidence, investigations, explain, performance, plan, research, scheduler, learning, hypothesis. Also: `argus execute`, `argus trace`, `argus version`.

### Section 49: Planning → Investigation → Hypothesis → Evidence → Validation → Report

These concepts remain deliberately separate stages.

### Section 50: Investigation Philosophy

An investigation is NOT automatically a vulnerability. It should explain: what to inspect, why it matters, affected assets, supporting evidence, confidence, priority, validation approach, methodology, classification.

### Section 51: Reporting

Reporting converts validated research into evidence-backed, traceable, understandable, reproducible reports based on validated findings.

### Section 52: Explainability

CLI: `argus explain`. Purpose: explain why an investigation was generated, show supporting evidence/correlations/methodology, explain confidence, show validation guidance.

### Section 53: Learning

Learning subsystem for future improvement of: prioritization, methodology, historical research outcomes. Must never silently change safety policy.

### Section 54: Benchmarking

Benchmark CLI for evaluating: task selection, tool resolution, execution latency, coverage, investigation quality, false positives, evidence quality.

### Section 55: Testing

Tests cover: planner, task categories, scheduler, dispatcher, runtime orchestrator, end-to-end missions, Nuclei, tool registration, compatibility resolution.

### Section 56: Current External Tool Environment

Environment-specific tool paths (subfinder, httpx, katana, nuclei). Must be rechecked when needed.

### Section 57: Important Architectural Cleanup

Dual execution paths: older collector/agent-style AND newer Mission Runtime/Registry/Dispatcher/Orchestrator. Long-term goal: unify to single pipeline.

### Section 58: Future Roadmap — Phase 9: Security Research Specialists

9.1 Vulnerability Intelligence Engine, 9.2 Methodology Engine, 9.3 Authorization Specialist, 9.4 Business Logic Specialist, 9.5 API Intelligence Specialist.

### Section 59: Phase 9.6–9.10

9.6 Authentication & Session Specialist, 9.7 File Upload Specialist, 9.8 GraphQL Specialist, 9.9 JavaScript Intelligence, 9.10 Technology Packs.

### Section 60: Phase 10 — Continuous Investigation Loop

Recon → Understand → Model → Find Gaps → Generate Investigations → Prioritize → Collect Evidence → Correlate → Re-evaluate → Next Investigation.

### Section 61: Phase 11 — Adaptive Research Prioritization

Prioritize using: asset importance, vulnerability potential, evidence strength, confidence, historical outcomes, architecture, relationships, business impact, coverage gaps.

### Section 62: Phase 12 — Cross-Specialist Correlation

Connect intelligence across specialists (API + Business Logic + Authorization + Authentication → Evidence Correlation → High-value Investigation).

### Section 63: Phase 13 — Stateful Application Research

Reasoning across: multiple user contexts, roles, authenticated/unauthenticated state, object ownership, workflow states, session state.

### Section 64: Phase 14 — Differential Analysis

Compare: responses, users, roles, sessions, object ownership, application states, API versions, workflow states.

### Section 65: Phase 15 — Finding Validation Framework

Hypothesis → Required Evidence → Safe Validation Steps → Observed Result → Confidence Update → Validated/Rejected.

### Section 66: Phase 16 — False Positive Reduction

Evidence requirements, confidence calibration, repeated observations, contradictory evidence handling, validation outcomes, researcher feedback, dismissal, finding deduplication.

### Section 67: Phase 17 — Finding Deduplication

Correlate duplicate descriptions from different tools/specialists into one correlated investigation.

### Section 68: Phase 18 — Security Research RAG & Intelligence Fabric

Full RAG subsystem build with all deliverables from Section 27.

### Section 69: Phase 19 — Security Research Knowledge Base

Expand with: vulnerability patterns, CWEs, OWASP categories, API/auth/authz/business logic patterns, technology behavior, framework security characteristics, validation methodologies.

### Section 70: Phase 19 — Technology-Aware Investigation

Technology packs influence planning: Technology → Relevant behavior → Security questions → Specialist investigations.

### Section 71: Phase 21 — Researcher Feedback Loop

Researchers mark investigations: useful, irrelevant, duplicate, confirmed, rejected, needs more evidence. Feedback improves prioritization and methodology.

### Section 72: Phase 22 — Evidence-First Reporting

Pipeline: Evidence → Observation → Correlation → Investigation → Validation → Finding → Report. Reports preserve provenance.

### Section 73: Phase 23 — Reproducibility

Researcher can see: mission, scope, policy, task, tool, tool version, inputs, outputs, evidence, reasoning, validation, timestamps.

### Section 74: Phase 24 — Mission Replay

Replay previous missions, reproduce investigations, debug, regression test, benchmark, compare versions.

### Section 75: Phase 25 — Research Benchmarks

Benchmark representative applications. Measure: coverage, useful investigation rate, false positives, time to hypothesis, evidence quality, validation success.

### Section 76: Phase 26 — Production Hardening

Stabilize APIs, improve tests, remove duplicate execution paths, improve error handling/configuration/logging, secure credentials, improve plugin isolation/performance/documentation/installation/upgrades.

### Section 77: Recommended Development Order

21-step prioritized development order from "finish current specialists" through "validate against realistic scenarios."

### Section 78: Core Success Criteria & Final Vision

Argus should answer: What does this app do? What security boundaries exist? What objects/workflows exist? What information is missing? What to investigate next? Why? What evidence supports it? How to validate safely? Can I reproduce? Can I produce a high-quality report?

Final vision: Authorized Mission → Recon → Knowledge Graph → Intelligence → Correlation → AI Research → Investigation → Evidence & Validation → Human-verified Finding → Report.
