# Original User Request

## Initial Request — 2026-09-03T15:05:41+05:30

You are the SWE Orchestrator for Sprint 31a: Conversational Memory System for the ARGUS security scanner.

Working directory: /home/varun/argus/.agents/swe_sprint31a
Workspace root: /home/varun/argus
Original request: /home/varun/argus/.agents/ORIGINAL_REQUEST.md
Handoff destination: /home/varun/argus/.agents/swe_sprint31a/handoff.md

Your mission is to implement the conversational memory system (`argus/memory/`) with vector-backed persistence, integrate it into `ResearchContextEngine`, write comprehensive unit, adversarial, and integration tests, verify zero regressions across the codebase, update sprint_handoff.md, and deliver a clean handoff.

## Detailed Requirements

### R1. Memory Data Models & Store (`argus/memory/`)
Implement the memory system module with these components:
1. `argus/memory/models.py`:
   - Data models for memory entries covering: attack patterns learned from previous scans, user corrections/overrides, strategic decisions (e.g. "skip host X", "prioritize SQLi over XSS"), session context (current scan state, active hypotheses), and free-form notes.
   - Each entry must have: `id`, `content` text, `memory_type` enum/str (`attack_pattern`, `user_correction`, `strategic_decision`, `session_context`, `note`), `mission_id` (optional, for mission-scoped memories), `created_at`/`updated_at` timestamps, `metadata` dict, `tags` list, `confidence` float, and `status` (`active`, `archived`, `superseded`).
   - Follow ARGUS dataclass patterns (slots, type hints, factory defaults).
2. `argus/memory/store.py`:
   - Vector-backed memory store persisting entries into the existing `VectorStore` (`argus/vector/store.py`) under `source_type='memory'`.
   - Must support: `add(entry)`, `get(id)`, `search(query, top_k, filters)` for semantic recall, `list(memory_type, mission_id)`, `update(id, ...)`, `archive(id)`, `clear(mission_id)`, and `count(filters)`.
   - Score values from memory search must always be bounded in [0.0, 1.0].
   - Entries must persist across `MemoryStore` re-instantiation (disk persistence via VectorStore).
3. `argus/memory/manager.py`:
   - High-level `MemoryManager` facade wrapping the store.
   - Provides semantic recall (`recall(query, top_k)` returning ranked memory entries), memory lifecycle management, and cross-mission knowledge transfer.
   - Expose `get_memory_manager()` singleton factory.
4. `argus/memory/__init__.py`:
   - Clean public exports.

### R2. ResearchContextEngine Integration
- Wire `MemoryManager` into the existing `ResearchContextEngine` at `argus/workspace/context/engine.py`.
- The `_get_memory_manager()` method (around line 78) currently has a placeholder — make it resolve to the real `MemoryManager`.
- Semantic retrieval in `resolve()` should include memory results alongside findings, evidence, CVE, and graph results when `enable_semantic_retrieval=True`.
- Touch only `_get_memory_manager()` and semantic retrieval integration in `argus/workspace/context/engine.py`. Do NOT break existing tests or behavior.

### R3. Tests
- `tests/memory/test_memory.py`: Unit tests for models, store CRUD, vector search integration, filtering by memory_type and mission_id, lifecycle operations (archive, supersede). Minimum 30 test cases.
- `tests/memory/test_memory_adversarial.py`: Adversarial tests including: empty/null inputs, extremely long content, special characters, concurrent access patterns, score bound invariants ([0.0, 1.0]), state isolation between missions. Minimum 15 test cases.
- `tests/memory/test_memory_integration.py`: Integration test verifying memory recall flows through `ResearchContextEngine.resolve()`.
- Total new test cases across the 3 files must be at least 45.

### Existing Architecture Reference
Do NOT modify existing vector store, embedding engine, or CVE KB internal logic:
- `argus/vector/store.py` (`VectorStore` dual-engine sqlite-vec / NumPy)
- `argus/vector/embeddings.py` (`EmbeddingEngine`)
- `argus/vector/models.py` (`VectorDocument`, `SearchResult`, `VectorFilter`, `VectorStoreConfig`)
- `argus/evidence/model.py`, `argus/evidence/store.py`
- `argus/knowledge/cve_kb.py`
- `argus/workspace/context/engine.py` (touch only `_get_memory_manager()` and semantic retrieval integration)
- `argus/workspace/context/models.py`
All vector documents for memory must use `source_type='memory'`.

### Post-Sprint Handoff
Update `/home/varun/argus/.agents/sprint_handoff.md`:
- Add Sprint 31a row to completed sprints table
- Update test baseline count
- Update "Remaining Roadmap" section (Sprint 31b: CLI search + integration tests, Sprint 31c: Adversarial RAG pipeline tests)
- Add Sprint 31a section with results summary

### Verification & Acceptance
- `python -m pytest tests/memory/ -x -q` must pass completely.
- `python -m pytest tests/ --ignore=tests/workspace -x -q` must pass with >= 2,089 tests.
- Minimum 45 new test cases.
- In your working directory `/home/varun/argus/.agents/swe_sprint31a`, maintain `progress.md` and write `handoff.md` upon completion.
- When 100% complete with all tests passing and handoff written, send your completion report with a victory claim.

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
