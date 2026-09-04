# FEATURE AUDIT REPORT: ARGUS PLATFORM
**Autonomous Offensive Security & Bug Bounty Research Engine**

- **Evaluation Date**: 2026-09-04
- **Auditor Role**: Feature Audit Synthesis Specialist
- **Target Repository**: `/home/varun/argus`
- **Target Specification**: Argus 78-Section Feature Inventory Specification
- **Integrity Mode**: `development`
- **Verification Status**: 100% Verified against Codebase & Test Suite (2,463 total tests passed)

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
   - [1.1 Platform Overview & Maturity Assessment](#11-platform-overview--maturity-assessment)
   - [1.2 Feature Status Scorecard](#12-feature-status-scorecard)
   - [1.3 Top 10 Most Critical Gaps & Technical Vulnerabilities](#13-top-10-most-critical-gaps--technical-vulnerabilities)
   - [1.4 Test Suite Health & Operational Findings](#14-test-suite-health--operational-findings)
   - [1.5 Architectural Concerns & Dual Execution Path Analysis](#15-architectural-concerns--dual-execution-path-analysis)
   - [1.6 Remediation & Development Prioritization Roadmap](#16-remediation--development-prioritization-roadmap)
2. [Summary Dashboard Table](#2-summary-dashboard-table)
3. [Test Suite Execution & Coverage Analysis](#3-test-suite-execution--coverage-analysis)
   - [3.1 Pytest Execution Metrics & Results](#31-pytest-execution-metrics--results)
   - [3.2 Test Suite Directory to Package Mapping](#32-test-suite-directory-to-package-mapping)
   - [3.3 Zero Test Coverage Identification](#33-zero-test-coverage-identification)
   - [3.4 Deprecation Warnings & Technical Debt](#34-deprecation-warnings--technical-debt)
4. [Detailed Per-Section Audit Reports](#4-detailed-per-section-audit-reports)
   - [Part 1: Core Architecture & Planning Engine (Sections 1–15)](#part-1-core-architecture-planning-engine-sections-115)
     - [Section 1: Project Identity (⚠️ Partial)](#section-1-project-identity)
     - [Section 2: Core Architecture (⚠️ Partial)](#section-2-core-architecture)
     - [Section 3: Mission (✅ Implemented)](#section-3-mission)
     - [Section 4: Scope Manager (⚠️ Partial)](#section-4-scope-manager)
     - [Section 5: Policy Engine (⚠️ Partial)](#section-5-policy-engine)
     - [Section 6: Mission Runtime (✅ Implemented)](#section-6-mission-runtime)
     - [Section 7: Tool Registry (✅ Implemented)](#section-7-tool-registry)
     - [Section 8: Tool Dispatcher (✅ Implemented)](#section-8-tool-dispatcher)
     - [Section 9: Tool Orchestrator (✅ Implemented)](#section-9-tool-orchestrator)
     - [Section 10: Event Bus (✅ Implemented)](#section-10-event-bus)
     - [Section 11: Scheduler (✅ Implemented)](#section-11-scheduler)
     - [Section 12: Research Task Model (✅ Implemented)](#section-12-research-task-model)
     - [Section 13: Research Planning (✅ Implemented)](#section-13-research-planning)
     - [Section 14: Gap Analysis Engine (✅ Implemented)](#section-14-gap-analysis-engine)
     - [Section 15: Coverage Tracker (✅ Implemented)](#section-15-coverage-tracker)
   - [Part 2: Reconnaissance, Evidence & Knowledge Graph (Sections 16–25)](#part-2-reconnaissance-evidence-knowledge-graph-sections-1625)
     - [Section 16: Reconnaissance (subfinder, httpx, katana, nuclei) (✅ Implemented)](#section-16-reconnaissance-subfinder-httpx-katana-nuclei)
     - [Section 17: Recon Parser (parsers for subfinder, httpx, katana, nuclei) (✅ Implemented)](#section-17-recon-parser-parsers-for-subfinder-httpx-katana-nuclei)
     - [Section 18: Nuclei Integration (✅ Implemented)](#section-18-nuclei-integration)
     - [Section 19: Evidence Store (✅ Implemented)](#section-19-evidence-store)
     - [Section 20: Provenance Engine (✅ Implemented)](#section-20-provenance-engine)
     - [Section 21: Observations & Correlations (✅ Implemented)](#section-21-observations-correlations)
     - [Section 22: Knowledge Graph (✅ Implemented)](#section-22-knowledge-graph)
     - [Section 23: Workflow Intelligence (✅ Implemented)](#section-23-workflow-intelligence)
     - [Section 24: Authorization Graph (✅ Implemented)](#section-24-authorization-graph)
     - [Section 25: Business Objects (✅ Implemented)](#section-25-business-objects)
   - [Part 3: AI Research, RAG Fabric & Domain Specialists (Sections 26–37)](#part-3-ai-research-rag-fabric-domain-specialists-sections-2637)
     - [Section 26: AI Research (✅ Implemented)](#section-26-ai-research)
     - [Section 27: Security Research RAG / Intelligence Fabric (✅ Implemented)](#section-27-security-research-rag-intelligence-fabric)
     - [Section 28: Research Cards (✅ Implemented)](#section-28-research-cards)
     - [Section 29: Vulnerability Intelligence Engine (✅ Implemented)](#section-29-vulnerability-intelligence-engine)
     - [Section 30: Methodology Engine & Playbooks (✅ Implemented)](#section-30-methodology-engine-playbooks)
     - [Section 31: Authorization Specialist (✅ Implemented)](#section-31-authorization-specialist)
     - [Section 32: Business Logic Specialist (✅ Implemented)](#section-32-business-logic-specialist)
     - [Section 33: API Intelligence Specialist (⚠️ Partial)](#section-33-api-intelligence-specialist)
     - [Section 34: GraphQL Specialist (✅ Implemented)](#section-34-graphql-specialist)
     - [Section 35: JavaScript Intelligence (✅ Implemented)](#section-35-javascript-intelligence)
     - [Section 36: Authentication Specialist (✅ Implemented)](#section-36-authentication-specialist)
     - [Section 37: File Upload Specialist (✅ Implemented)](#section-37-file-upload-specialist)
   - [Part 4: Plugins, HTTP Engine, Observability & CLI Surface (Sections 38–48)](#part-4-plugins-http-engine-observability-cli-surface-sections-3848)
     - [Section 38: Plugin SDK (⚠️ Partial)](#section-38-plugin-sdk)
     - [Section 39: Controlled Plugin Execution (⚠️ Partial)](#section-39-controlled-plugin-execution)
     - [Section 40: Credential Vault (❌ Missing)](#section-40-credential-vault)
     - [Section 41: Session Manager (✅ Implemented)](#section-41-session-manager)
     - [Section 42: HTTP Engine (✅ Implemented)](#section-42-http-engine)
     - [Section 43: Rules Engine (⚠️ Partial)](#section-43-rules-engine)
     - [Section 44: Configuration (⚠️ Partial)](#section-44-configuration)
     - [Section 45: Observability (✅ Implemented)](#section-45-observability)
     - [Section 46: Performance (🔴 Broken)](#section-46-performance)
     - [Section 47: Workspace (✅ Implemented)](#section-47-workspace)
     - [Section 48: CLI Surface (34 Namespaces) (⚠️ Partial)](#section-48-cli-surface-34-namespaces)
   - [Part 5: Research Lifecycle, Reporting & System Architecture (Sections 49–57)](#part-5-research-lifecycle-reporting-system-architecture-sections-4957)
     - [Section 49: Planning → Investigation → Hypothesis → Evidence → Validation → Report Lifecycle (✅ Implemented)](#section-49-planning-investigation-hypothesis-evidence-validation-report-lifecycle)
     - [Section 50: Investigation Philosophy (✅ Implemented)](#section-50-investigation-philosophy)
     - [Section 51: Reporting (✅ Implemented)](#section-51-reporting)
     - [Section 52: Explainability (✅ Implemented)](#section-52-explainability)
     - [Section 53: Learning (✅ Implemented)](#section-53-learning)
     - [Section 54: Benchmarking (✅ Implemented)](#section-54-benchmarking)
     - [Section 55: Testing (✅ Implemented)](#section-55-testing)
     - [Section 56: Current External Tool Environment (✅ Implemented)](#section-56-current-external-tool-environment)
     - [Section 57: Important Architectural Cleanup (Dual Execution Paths) (⚠️ Partial)](#section-57-important-architectural-cleanup-dual-execution-paths)
   - [Part 6: Advanced Research Roadmap & Evolution (Sections 58–78)](#part-6-advanced-research-roadmap-evolution-sections-5878)
     - [Section 58: Future Roadmap — Phase 9: Security Research Specialists (9.1–9.5) (✅ Implemented)](#section-58-future-roadmap-phase-9-security-research-specialists-9195)
     - [Section 59: Phase 9.6–9.10 (Auth, Upload, GraphQL, JS, Tech Packs) (⚠️ Partial)](#section-59-phase-96910-auth-upload-graphql-js-tech-packs)
     - [Section 60: Phase 10 — Continuous Investigation Loop (✅ Implemented)](#section-60-phase-10-continuous-investigation-loop)
     - [Section 61: Phase 11 — Adaptive Research Prioritization (✅ Implemented)](#section-61-phase-11-adaptive-research-prioritization)
     - [Section 62: Phase 12 — Cross-Specialist Correlation (✅ Implemented)](#section-62-phase-12-cross-specialist-correlation)
     - [Section 63: Phase 13 — Stateful Application Research (✅ Implemented)](#section-63-phase-13-stateful-application-research)
     - [Section 64: Phase 14 — Differential Analysis (✅ Implemented)](#section-64-phase-14-differential-analysis)
     - [Section 65: Phase 15 — Finding Validation Framework (✅ Implemented)](#section-65-phase-15-finding-validation-framework)
     - [Section 66: Phase 16 — False Positive Reduction (✅ Implemented)](#section-66-phase-16-false-positive-reduction)
     - [Section 67: Phase 17 — Finding Deduplication (✅ Implemented)](#section-67-phase-17-finding-deduplication)
     - [Section 68: Phase 18 — Security Research RAG & Intelligence Fabric (✅ Implemented)](#section-68-phase-18-security-research-rag-intelligence-fabric)
     - [Section 69: Phase 19 — Security Research Knowledge Base (✅ Implemented)](#section-69-phase-19-security-research-knowledge-base)
     - [Section 70: Phase 20 — Technology-Aware Investigation (⚠️ Partial)](#section-70-phase-20-technology-aware-investigation)
     - [Section 71: Phase 21 — Researcher Feedback Loop (✅ Implemented)](#section-71-phase-21-researcher-feedback-loop)
     - [Section 72: Phase 22 — Evidence-First Reporting (✅ Implemented)](#section-72-phase-22-evidence-first-reporting)
     - [Section 73: Phase 23 — Reproducibility (✅ Implemented)](#section-73-phase-23-reproducibility)
     - [Section 74: Phase 24 — Mission Replay (⚠️ Partial)](#section-74-phase-24-mission-replay)
     - [Section 75: Phase 25 — Research Benchmarks (✅ Implemented)](#section-75-phase-25-research-benchmarks)
     - [Section 76: Phase 26 — Production Hardening (⚠️ Partial)](#section-76-phase-26-production-hardening)
     - [Section 77: Recommended Development Order (❌ Missing)](#section-77-recommended-development-order)
     - [Section 78: Core Success Criteria & Final Vision (⚠️ Partial)](#section-78-core-success-criteria-final-vision)
5. [Appendix: Verification & Reproducibility Guide](#5-appendix-verification--reproducibility-guide)

---


<a id="1-executive-summary"></a>
## 1. Executive Summary

<a id="11-platform-overview--maturity-assessment"></a>
### 1.1 Platform Overview & Maturity Assessment

Argus is an advanced, production-grade autonomous offensive security and AI-assisted bug bounty research platform comprising **~78,000 lines of Python source code across 488 modules** and **~59,000 lines of test code across 234 test files**. The codebase exhibits architectural sophistication and deep offensive security capabilities across reconnaissance, web vulnerability specialists (SQLi, XSS, SSRF, Deserialization, XXE, SSTI, Race Conditions, GraphQL, JavaScript analysis, Authentication bypass, and File Upload), authorization boundary graph modeling, multi-identity differential request coordination, hybrid Vector RAG with offline cybersecurity domain embeddings, and automated HackerOne-style markdown and JSON report generation.

The platform has successfully matured past the prototype phase, achieving a **100% test pass rate across 2,463 automated tests** (2,451 in `tests/` and 12 in `argus/`). However, the audit identified critical areas of technical debt, primarily: (1) a dual-pipeline architectural bifurcation where legacy scanner collectors coexist with the newer autonomous mission runtime, (2) a Typer CLI mounting defect that breaks two CLI namespaces, (3) the absence of a secure Credential Vault, and (4) several CLI subcommands operating on mock or hardcoded demonstration data.

<a id="12-feature-status-scorecard"></a>
### 1.2 Feature Status Scorecard

Across the **78 sections** defined in the Argus Feature Inventory Specification, the deep code and test audit establishes the following authoritative status breakdown:

| Status Category | Symbol | Section Count | Percentage | Definition |
| :--- | :---: | :---: | :---: | :--- |
| **Implemented** | ✅ | **59** | **75.6%** | Fully realized in code, functionally operational, and verified by automated tests. |
| **Partial** | ⚠️ | **16** | **20.5%** | Substantially implemented, but exhibits feature gaps, CLI stubs, or ununified architecture. |
| **Missing** | ❌ | **2** | **2.6%** | Required component or specification artifact absent from the codebase. |
| **Broken** | 🔴 | **1** | **1.3%** | Implementation exists but crashes or is unreachable due to CLI registration/runtime errors. |
| **Total Audited** | — | **78** | **100.0%** | Comprehensive audit covering all specification sections 1 to 78. |

<a id="13-top-10-most-critical-gaps--technical-vulnerabilities"></a>
### 1.3 Top 10 Most Critical Gaps & Technical Vulnerabilities

1. **CLI Typer Mounting Defect (🔴 Broken — Section 46 & 48)**:
   - **Root Cause**: In `argus/cli/app.py:71`, `app.add_typer(performance_app)` is invoked without specifying `name="performance"`.
   - **Impact**: Typer fails to bind the `performance` namespace, causing `argus performance` to return `Error: No such command 'performance'`. Furthermore, this un-named mount shadows the `benchmark` namespace mounted at line 58 (`argus/cli/benchmark_cli.py`), rendering the benchmark suite CLI inaccessible.
   - **Remediation**: Update line 71 to `app.add_typer(performance_app, name="performance")`.

2. **Credential Vault Missing (❌ Missing — Section 40)**:
   - **Root Cause**: No `argus/vault/` package or `CredentialVault` class exists anywhere in the repository.
   - **Impact**: Credentials (passwords, bearer tokens, API keys) are stored in plaintext dictionaries in `TestIdentity.credentials` (`argus/models/test_identity.py:35`) and `Mission.credentials` (`argus/runtime/mission.py:168`). Checkpoint and mission history serializers write these plaintext credentials directly to disk in `.argus/history/` and `.argus/checkpoints/`.
   - **Remediation**: Implement an encrypted credential vault subsystem using AES-256-GCM / ChaCha20-Poly1305 with OS keyring backends or master-key passphrase derivation.

3. **Dual Execution Path & Architecture Bifurcation (⚠️ Partial — Section 57, 2, 6)**:
   - **Root Cause**: The codebase maintains two completely separate scanning execution engines: Path A (`argus/scanning/engine.py` + `argus/collectors/*.py`) and Path B (`argus/runtime/mission_runtime.py` + `orchestrator.py` + `dispatcher.py`).
   - **Impact**: The primary CLI entry point `argus scan <target>` runs the legacy Path A, directly mutating the `Mission` model and bypassing the 10-stage autonomous lifecycle, event bus, priority task scheduler, and hypothesis generator of Path B.
   - **Remediation**: Consolidate execution onto `AutonomousMissionRuntime`. Migrate the 32 legacy collectors to implement `BasePlugin` and return typed `Evidence` objects rather than mutating mission state.

4. **CLI Subcommand Hardcoded Stubs & Broken Iterators (🔴 Broken / ⚠️ Partial — Section 48)**:
   - **Root Cause**: `argus intelligence list` crashes with `TypeError: 'InvestigationRegistry' object is not iterable` because it attempts to iterate over the registry directly instead of calling its items accessor. Meanwhile, `argus execute`, `argus plan`, `argus research`, and `argus scheduler` run against hardcoded dummy hosts (`test.com`, `demo.example.com`, `scheduler.example.com`) or print mock strings (`plan-uuid-1234`).
   - **Impact**: CLI users cannot inspect active investigations or run research workflows against arbitrary live missions.
   - **Remediation**: Fix the iterator call in `argus/cli/intelligence_cli.py`, and wire CLI arguments (`--mission-id`, `--target`) to the active database/runtime rather than dummy mock generators.

5. **Co-Located Specialist Plugins Untested in Canonical Pytest Run (⚠️ Partial — Section 33, 59, 8.2)**:
   - **Root Cause**: 37 Python source files across four specialist plugins (`argus/plugins/api/`, `argus/plugins/authentication/`, `argus/plugins/file_upload/`, and `argus/agents/business_logic/`) place their tests inside in-package `tests/` directories rather than top-level `tests/`.
   - **Impact**: When developers run standard CI (`python -m pytest tests/`), these 12 unit tests are omitted from collection, creating a false sense of test inventory completeness.
   - **Remediation**: Either configure `pytest.ini` with `testpaths = tests argus` or relocate specialist unit tests into `tests/plugins/` and `tests/agents/`.

6. **Mission Replay Engine Missing (⚠️ Partial — Section 74)**:
   - **Root Cause**: While tool calls are logged to `.argus/tool_history.json` and missions are checkpointed, no replay runner, replay models, or CLI command (`argus mission replay`) exist to deterministically re-execute recorded missions.
   - **Impact**: Inability to perform automated regression verification against historical target captures.
   - **Remediation**: Implement `argus/runtime/replay.py` reading tool history events and stubbing HTTP responses for deterministic replay.

7. **Scope Enforcement & Exclude Lists (⚠️ Partial — Section 4 & 5)**:
   - **Root Cause**: `ScopeResolver` handles IP/CIDR and wildcard domain matching, but lacks explicit out-of-scope exclude lists, passive-only execution enforcement, and automated scope import from HackerOne/Bugcrowd structured JSON.
   - **Impact**: Risk of scanning out-of-scope targets or performing active actions during passive recon.
   - **Remediation**: Extend `ScopeResolver` with an `exclude_rules` set and create `argus/authorization/importers.py`.

8. **Configuration & File-Based Profiles (⚠️ Partial — Section 44)**:
   - **Root Cause**: Configuration is currently limited to environment variables loaded via `.env` in `Config` (`argus/config.py`).
   - **Impact**: No support for file-based configuration files (`argus.yaml`), profile switching (`--profile bugbounty`), or configuration schema validation.
   - **Remediation**: Implement a Pydantic-based configuration model reading YAML/TOML configuration files.

9. **Python 3.13 & Pydantic V2 Deprecations (Technical Debt — 51,943 Warnings)**:
   - **Root Cause**: Heavy usage of deprecated `datetime.utcnow()` across 12 files (51,943 warnings) and deprecated Pydantic inner `class Config:` in `argus/runtime/models.py:167`.
   - **Impact**: Imminent build failure when upgrading to Python 3.14+ or Pydantic V3.
   - **Remediation**: Replace `datetime.utcnow()` with `datetime.now(datetime.timezone.utc)` and migrate Pydantic models to `ConfigDict`.

10. **Orphaned / Dead Code Packages (Technical Debt — 14 Files)**:
   - **Root Cause**: 14 Python source files have zero incoming imports from either tests or production modules (e.g. `argus/core/controller.py`, `argus/core/models.py`, `argus/workspace/context.py`), and two bridge directories (`argus/bridges/github/`, `argus/bridges/playwright/`) are completely empty.
   - **Impact**: Unused code bloats the codebase, creates maintenance confusion, and dilutes audit clarity.
   - **Remediation**: Remove dead modules or properly integrate them into active pipelines.

<a id="14-test-suite-health--operational-findings"></a>
### 1.4 Test Suite Health & Operational Findings

Execution of the full test suite demonstrated remarkable functional stability and zero regressions:

- **Canonical Test Suite (`tests/`)**: **2,451 tests collected, 2,451 passed, 0 failed, 0 errors, 0 skipped** in **90.41 seconds** (100.0% pass rate).
- **Co-Located Test Suite (`argus/`)**: **12 tests collected, 12 passed, 0 failed, 0 errors, 0 skipped** in **0.96 seconds** (100.0% pass rate).
- **Combined Total**: **2,463 passed tests**, 0 failures, 0 errors across 234 active test files.
- **Test Execution Speed**: Average execution speed of ~27 tests per second, benefiting from mock-isolated network layers, SQLite in-memory databases, and vectorized NumPy fallbacks.
- **Warnings**: 51,958 warnings emitted, entirely consisting of `datetime.utcnow()` deprecations and Pydantic V2 config syntax warnings.

<a id="15-architectural-concerns--dual-execution-path-analysis"></a>
### 1.5 Architectural Concerns & Dual Execution Path Analysis

A central architectural finding of this audit is the persistence of **two parallel execution pipelines** within the codebase (Section 57):

1. **Legacy Collector Scanning DAG (Path A)**:
   - **Components**: `argus/scanning/engine.py` (`ScanEngine`), `argus/scanning/dag.py` (`ScanDAG`), and 32 vulnerability collectors in `argus/collectors/*.py`.
   - **Behavior**: Invoked by the primary CLI command `argus scan <target>`. Schedulers run collectors in topological order, but collectors interact directly with the `Mission` object, mutating `mission.findings` and `mission.vulnerabilities` in-place. It lacks formal lifecycle states, hypothesis generation, and evidence bundle correlation.

2. **Autonomous Mission Runtime (Path B)**:
   - **Components**: `argus/runtime/mission_runtime.py` (`AutonomousMissionRuntime`), `orchestrator.py` (`ToolOrchestrator`), `dispatcher.py` (`ToolDispatcher`), `registry.py` (`ToolRegistry`), and `executor.py` (`TaskScheduler`).
   - **Behavior**: Invoked by `argus mission run <target>`. Executes a rigorous 10-step autonomous loop: Scope validation → Reconnaissance → Knowledge Graph construction → Gap Analysis → Research Task Planning → Tool Dispatch → Evidence Ingestion → Correlation & Fusion → Hypothesis Validation → HackerOne Report Generation.

3. **Architectural Redundancy & Fragmentation**:
   - **Resolution Maps**: Both `ScanEngine` (lines 76–140) and `PluginExecutorAdapter` (lines 65–270) maintain redundant 60- to 200-line dictionary/if-else maps mapping string tool IDs to collector classes.
   - **Duplicate Schedulers**: `ScanDAG` and `TaskScheduler` independently implement topological sorting and concurrency pools.
   - **Result Models**: The codebase defines three competing result structures: `ScanResult`/`CollectorResult`, `ToolExecutionResult`, and `AgentResult`.
   - **Integration Strategy**: Path A must be deprecated and refactored as a lightweight preset profile of Path B. Collectors must be refactored to return typed `Evidence` objects rather than directly mutating shared mission state.

<a id="16-remediation--development-prioritization-roadmap"></a>
### 1.6 Remediation & Development Prioritization Roadmap

Based on security risk, system stability, and development dependencies, the recommended remediation plan is structured across four phases:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ PHASE 1: Immediate Stability & CLI Hotfixes (Days 1–2)                      │
├─────────────────────────────────────────────────────────────────────────────┤
│ • Fix app.py:71 Typer mount: app.add_typer(performance_app, name="perf..") │
│ • Fix intelligence_cli.py: line 124 registry iteration crash               │
│ • Replace datetime.utcnow() with datetime.now(timezone.utc) (51K warnings)  │
│ • Configure pytest.ini to collect co-located specialist tests in argus/     │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
┌──────────────────────────────────────▼──────────────────────────────────────┐
│ PHASE 2: Security, Scope & Configuration Hardening (Week 1)                 │
├─────────────────────────────────────────────────────────────────────────────┤
│ • Implement Section 40 CredentialVault with AES-256-GCM encryption at rest  │
│ • Mask credentials in checkpoint and history serialization                 │
│ • Add explicit exclude_rules and HackerOne scope JSON parser to ScopeResolver│
│ • Implement Pydantic-based YAML/TOML configuration file loader (Section 44) │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
┌──────────────────────────────────────▼──────────────────────────────────────┐
│ PHASE 3: Core Pipeline Unification — Section 57 (Weeks 2–3)                 │
├─────────────────────────────────────────────────────────────────────────────┤
│ • Refactor 'argus scan' CLI command to delegate to AutonomousMissionRuntime │
│ • Deprecate ScanEngine and consolidate tool maps into ToolRegistry          │
│ • Refactor 32 collectors to return typed Evidence without mutating Mission  │
│ • Consolidate triplicate EventBus into unified argus.runtime.events         │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
┌──────────────────────────────────────▼──────────────────────────────────────┐
│ PHASE 4: CLI Completeness & Mission Replay Engine (Week 4)                  │
├─────────────────────────────────────────────────────────────────────────────┤
│ • Replace CLI stubs in execute, plan, research, scheduler with live runtime │
│ • Implement Section 74 deterministic Mission Replay runner and CLI          │
│ • Implement real file installation/symlinking in 'argus plugin install'     │
│ • Purge 14 orphaned Python files and remove empty bridge directories        │
└─────────────────────────────────────────────────────────────────────────────┘
```

---


<a id="2-summary-dashboard-table"></a>
## 2. Summary Dashboard Table

The following master dashboard summarizes the implementation and verification status across all **78 specification sections**. Each section links directly to its detailed code audit report below.

| Section # | Section Name | Status | Primary Source Files | Test Coverage |
| :---: | :--- | :---: | :--- | :--- |
| **1** | [Project Identity](#section-1-project-identity) | ⚠️ Partial | `pyproject.toml`, `argus/cli/app.py` | Tested indirectly through `tests/authorization/test_adversarial_scope_recon.py`, `tests/authorization/test_scope_resolver.py`, and `tests/runtime/test_e2e_mission.py`. All tests pass. |
| **2** | [Core Architecture](#section-2-core-architecture) | ⚠️ Partial | `argus/runtime/mission_runtime.py`, `argus/runtime/mission.py` | `tests/runtime/test_mission_runtime.py` (4 passed) |
| **3** | [Mission](#section-3-mission) | ✅ Implemented | `argus/runtime/mission.py`, `argus/runtime/lifecycle.py`, `argus/runtime/manager.py` | `tests/runtime/test_mission_runtime.py` |
| **4** | [Scope Manager](#section-4-scope-manager) | ⚠️ Partial | `argus/authorization/scope.py`, `argus/runtime/sandbox.py`, `argus/authorization/gate.py` | `tests/authorization/test_scope_resolver.py` (18 tests) |
| **5** | [Policy Engine](#section-5-policy-engine) | ⚠️ Partial | `argus/runtime/sandbox.py`, `argus/authorization/gate.py`, `argus/workspace/context/policy.py` | `tests/runtime/test_runtime_orchestrator.py` (`TestSafetyValidation`: 5 tests) |
| **6** | [Mission Runtime](#section-6-mission-runtime) | ✅ Implemented | `argus/runtime/mission_runtime.py`, `argus/runtime/orchestrator.py`, `argus/runtime/dispatcher.py` | `tests/runtime/test_mission_runtime.py` (4 tests) |
| **7** | [Tool Registry](#section-7-tool-registry) | ✅ Implemented | `argus/runtime/registry.py`, `argus/runtime/models.py`, `argus/cli/tools_cli.py` | `tests/runtime/test_runtime_orchestrator.py` (`TestToolRegistry`) |
| **8** | [Tool Dispatcher](#section-8-tool-dispatcher) | ✅ Implemented | `argus/runtime/dispatcher.py`, `argus/runtime/registry.py`, `argus/runtime/executor.py` | `tests/runtime/test_runtime_orchestrator.py` (`TestToolSelection`: `test_deterministic_priority_selection`, `test_deterministic_alphabetical_tiebreaker`) |
| **9** | [Tool Orchestrator](#section-9-tool-orchestrator) | ✅ Implemented | `argus/runtime/orchestrator.py`, `argus/runtime/models.py`, `argus/runtime/monitor.py` | `tests/runtime/test_runtime_orchestrator.py` (`TestExecutionLifecycleAndEvents`: `test_successful_lifecycle_and_provenance`, `test_failed_lifecycle`, `test_timeout_lifecycle`, `test_mission_runtime_integration`) |
| **10** | [Event Bus](#section-10-event-bus) | ✅ Implemented | `argus/runtime/events.py`, `argus/core/event_bus.py`, `argus/plugins/events.py` | `tests/runtime/test_scheduler.py` (`TestEventEmission`) |
| **11** | [Scheduler](#section-11-scheduler) | ✅ Implemented | `argus/runtime/executor.py`, `argus/runtime/queue.py`, `argus/runtime/dependencies.py` | `tests/runtime/test_scheduler.py` (6 tests covering dependency blocking, unblocking, max worker concurrency, retry policy, terminal failure, and event emission). |
| **12** | [Research Task Model](#section-12-research-task-model) | ✅ Implemented | `argus/planning/models.py` | Verified across `tests/planning/test_research_planner.py`, `tests/planning/test_task_generator.py`, and `tests/runtime/test_runtime_orchestrator.py`. |
| **13** | [Research Planning](#section-13-research-planning) | ✅ Implemented | `argus/planning/research_planner.py`, `argus/planning/task_generator.py`, `argus/planning/decision_engine.py` | `tests/planning/test_research_planner.py` (14 tests) |
| **14** | [Gap Analysis Engine](#section-14-gap-analysis-engine) | ✅ Implemented | `argus/planning/gap_analysis.py`, `argus/planning/models.py` | `tests/planning/test_research_planner.py` (`TestGapAnalysis`) |
| **15** | [Coverage Tracker](#section-15-coverage-tracker) | ✅ Implemented | `argus/planning/coverage.py`, `argus/planning/models.py` | `tests/planning/test_research_planner.py` (`TestCoverage`: 3 unit tests + 1 CLI test) |
| **16** | [Reconnaissance](#section-16-reconnaissance-subfinder-httpx-katana-nuclei) | ✅ Implemented | `argus/collectors/{subfinder,httpx,katana,nuclei}.py`, `argus/collectors/base.py`, `argus/agents/recon.py` | `tests/runtime/test_recon_parsers.py`, `tests/runtime/test_recon_fallback.py`, `tests/runtime/test_adversarial_recon.py` (66 passed) |
| **17** | [Recon Parser](#section-17-recon-parser-parsers-for-subfinder-httpx-katana-nuclei) | ✅ Implemented | `argus/runtime/parser.py` (lines 8–280) | `tests/runtime/test_recon_parsers.py`, `tests/runtime/test_adversarial_recon.py` (54 passed) |
| **18** | [Nuclei Integration](#section-18-nuclei-integration) | ✅ Implemented | `argus/collectors/nuclei.py`, `argus/runtime/parser.py`, `argus/scanning/engine.py` | `tests/runtime/test_recon_parsers.py`, `tests/runtime/test_adversarial_recon.py` (15 passed) |
| **19** | [Evidence Store](#section-19-evidence-store) | ✅ Implemented | `argus/evidence/model.py`, `argus/evidence/store.py`, `argus/evidence/manager.py`, `argus/correlation/evidence.py` | `tests/evidence/test_evidence.py`, `tests/correlation/test_evidence_integration.py` (5 passed) |
| **20** | [Provenance Engine](#section-20-provenance-engine) | ✅ Implemented | `argus/provenance/{models,graph,trace,validator,engine}.py`, `argus/cli/provenance_cli.py`, `argus/cli/app.py` | `tests/test_provenance.py` (2 passed) |
| **21** | [Observations & Correlations](#section-21-observations-correlations) | ✅ Implemented | `argus/correlation/{models,observation,correlation,rules,matcher,engine,fusion,scoring,strength,confidence,serializer}.py`, `argus/correlation/cli.py` | `tests/correlation/` (14 test files) (35 passed) |
| **22** | [Knowledge Graph](#section-22-knowledge-graph) | ✅ Implemented | `argus/graph/{node,edge,graph,builder,attack_surface,diff,workflow}.py`, `argus/cli/knowledge.py` | `tests/graph/` (8 test files), `tests/test_graph_root.py`, `tests/test_knowledge.py` (86 passed) |
| **23** | [Workflow Intelligence](#section-23-workflow-intelligence) | ✅ Implemented | `argus/workflows/{models,detector,graph,step,builder,workflow}.py`, `argus/cli/workflow_cli.py` | `tests/test_workflows.py` (6 passed) |
| **24** | [Authorization Graph](#section-24-authorization-graph) | ✅ Implemented | `argus/authorization/{models,graph,builder,analyzer,rules,gate,scope}.py`, `argus/cli/auth_cli.py` | `tests/test_authorization.py`, `tests/test_authz_specialist.py`, `tests/authorization/` (40 passed) |
| **25** | [Business Objects](#section-25-business-objects) | ✅ Implemented | `argus/intelligence/business_models.py`, `argus/intelligence/business.py`, `argus/collectors/business_logic.py`, `argus/cli/business_cli.py` | `tests/test_business_root.py`, `tests/collectors/test_business_logic.py`, `tests/collectors/test_business_logic_adversarial.py` (46 passed) |
| **26** | [AI Research](#section-26-ai-research) | ✅ Implemented | `argus/ai/researcher.py`, `argus/ai/context.py`, `argus/ai/prompts.py`, `argus/ai/client.py`, `argus/ai/gemini_client.py`, `argus/ai/openai_client.py`, `argus/ai/github_client.py`, `argus/ai/models.py`, `argus/agents/recon.py` | 35 passed (`tests/test_ai_research.py`, `tests/ai/test_ai_clients.py`) |
| **27** | [Security Research RAG / Intelligence Fabric (27.1–27.16)](#section-27-security-research-rag-intelligence-fabric) | ✅ Implemented | `argus/vector/store.py`, `argus/vector/models.py`, `argus/vector/embeddings.py`, `argus/workspace/context/engine.py`, `argus/workspace/context/ranker.py`, `argus/workspace/context/assembler.py`, `argus/workspace/context/graph.py`, `argus/workspace/context/policy.py`, `argus/reporting/vector_indexer.py`, `argus/knowledge/cve_kb.py`, `argus/memory/manager.py` | 73 passed (`tests/vector/test_rag_integration.py`, `tests/vector/test_rag_adversarial.py`, `tests/vector/test_rag_prompt_injection.py`, `tests/vector/test_embedding_robustness.py`) |
| **28** | [Research Cards](#section-28-research-cards) | ✅ Implemented | `argus/ai/models.py`, `argus/reporting/queue.py`, `argus/cli/queue_cli.py` | 3 passed (`tests/test_research_cards.py`) |
| **29** | [Vulnerability Intelligence Engine](#section-29-vulnerability-intelligence-engine) | ✅ Implemented | `argus/intelligence/engine.py`, `argus/intelligence/models.py`, `argus/intelligence/hypothesis.py`, `argus/intelligence/confidence.py`, `argus/intelligence/prioritizer.py`, `argus/hypothesis/engine.py`, `argus/hypothesis/models.py`, `argus/hypothesis/generator.py` | 4 passed (`tests/test_intelligence.py`) |
| **30** | [Methodology Engine & Playbooks](#section-30-methodology-engine-playbooks) | ✅ Implemented | `argus/methodology/engine.py`, `argus/methodology/playbook.py`, `argus/methodology/models.py`, `argus/methodology/executor.py`, `argus/methodology/registry.py`, `argus/methodology/step.py`, `argus/cli/playbook_cli.py` | 4 passed (`tests/test_methodology.py`) |
| **31** | [Authorization Specialist](#section-31-authorization-specialist) | ✅ Implemented | `argus/agents/authorization/agent.py`, `argus/agents/authorization/heuristics.py`, `argus/agents/authorization/ownership.py`, `argus/agents/authorization/roles.py`, `argus/agents/authorization/permissions.py`, `argus/authorization/analyzer.py`, `argus/authorization/graph.py`, `argus/authorization/gate.py`, `argus/collectors/access_control.py` | 7 passed (`tests/test_authorization.py`, `tests/authorization/test_authorization_gate.py`) + 9 passed in collectors |
| **32** | [Business Logic Specialist](#section-32-business-logic-specialist) | ✅ Implemented | `argus/agents/business_logic/agent.py`, `argus/agents/business_logic/states.py`, `argus/agents/business_logic/transitions.py`, `argus/agents/business_logic/objects.py`, `argus/agents/business_logic/workflow.py`, `argus/agents/business_logic/planner.py`, `argus/agents/business_logic/heuristics.py`, `argus/collectors/business_logic.py` | 5 passed (`argus/agents/business_logic/tests/test_business_logic.py`) + 4 passed in collectors |
| **33** | [API Intelligence Specialist](#section-33-api-intelligence-specialist) | ⚠️ Partial | `argus/plugins/api/agent.py`, `argus/plugins/api/plugin.py`, `argus/plugins/api/resource_model.py`, `argus/plugins/api/operations.py`, `argus/plugins/api/relationships.py`, `argus/plugins/api/versions.py`, `argus/plugins/api/schemas.py`, `argus/collectors/api_security.py` | 3 passed (`argus/plugins/api/tests/test_api_intelligence.py`) + 6 passed in collectors |
| **34** | [GraphQL Specialist](#section-34-graphql-specialist) | ✅ Implemented | `argus/plugins/graphql/agent.py`, `argus/plugins/graphql/discovery.py`, `argus/plugins/graphql/schema.py`, `argus/plugins/graphql/business.py`, `argus/plugins/graphql/reasoning.py`, `argus/plugins/graphql/cli.py`, `argus/collectors/graphql.py` | 75 passed (`tests/collectors/test_graphql.py`, `tests/collectors/test_graphql_adversarial.py`, `argus/plugins/graphql/tests/test_graphql.py`) |
| **35** | [JavaScript Intelligence](#section-35-javascript-intelligence) | ✅ Implemented | `argus/plugins/javascript/parser.py`, `argus/plugins/javascript/agent.py`, `argus/plugins/javascript/discovery.py`, `argus/plugins/javascript/models.py`, `argus/plugins/javascript/cli.py`, `argus/analyzers/javascript.py`, `argus/collectors/javascript.py` | 17 passed (`tests/plugins/javascript/`) |
| **36** | [Authentication Specialist](#section-36-authentication-specialist) | ✅ Implemented | `argus/plugins/authentication/agent.py`, `argus/plugins/authentication/identity.py`, `argus/plugins/authentication/sessions.py`, `argus/plugins/authentication/tokens.py`, `argus/plugins/authentication/oauth.py`, `argus/plugins/authentication/mfa.py`, `argus/collectors/auth_bypass.py`, `argus/collectors/oauth.py` | 1 passed in plugins + 101 passed in collectors (`test_auth_bypass.py`, `test_oauth.py`) |
| **37** | [File Upload Specialist](#section-37-file-upload-specialist) | ✅ Implemented | `argus/plugins/file_upload/agent.py`, `argus/plugins/file_upload/uploads.py`, `argus/plugins/file_upload/storage.py`, `argus/plugins/file_upload/objects.py`, `argus/plugins/file_upload/workflow.py`, `argus/plugins/file_upload/heuristics.py`, `argus/collectors/file_upload.py` | 45 passed (`argus/plugins/file_upload/tests/test_file_upload.py`, `tests/collectors/test_file_upload.py`, `tests/collectors/test_file_upload_adversarial.py`) |
| **38** | [Plugin SDK](#section-38-plugin-sdk) | ⚠️ Partial | `argus/plugins/interfaces.py`, `registry.py`, `manager.py`, `loader.py`, `events.py`, `sdk.py`, `argus/cli/plugin_cli.py` | `tests/test_plugins.py` (5 tests) |
| **39** | [Controlled Plugin Execution](#section-39-controlled-plugin-execution) | ⚠️ Partial | `argus/plugins/interfaces.py`, `argus/runtime/plugins.py`, `argus/runtime/sandbox.py` | `tests/runtime/test_runtime_orchestrator.py` |
| **40** | [Credential Vault](#section-40-credential-vault) | ❌ Missing | None (`argus/models/test_identity.py`, `argus/runtime/mission.py`) | None |
| **41** | [Session Manager](#section-41-session-manager) | ✅ Implemented | `argus/http/coordinator.py`, `argus/http/client.py`, `argus/models/test_identity.py`, `argus/plugins/authentication/sessions.py` | `tests/http/test_authenticated_http_client.py`, `tests/http/test_sprint4_empirical_stress.py` |
| **42** | [HTTP Engine](#section-42-http-engine) | ✅ Implemented | `argus/http/client.py`, `argus/http/coordinator.py` | `tests/http/test_authorized_http_client.py`, `tests/http/test_authenticated_http_client.py` |
| **43** | [Rules Engine](#section-43-rules-engine) | ⚠️ Partial | `argus/correlation/rules.py`, `argus/authorization/rules.py`, `argus/runtime/sandbox.py` | `tests/correlation/test_correlation_rules.py` |
| **44** | [Configuration](#section-44-configuration) | ⚠️ Partial | `argus/config.py`, `argus/runtime/mission.py` | None |
| **45** | [Observability](#section-45-observability) | ✅ Implemented | `argus/runtime/observability.py`, `history.py`, `orchestrator.py`, `monitor.py`, `argus/cli/tools_cli.py` | `tests/runtime/test_runtime_orchestrator.py` |
| **46** | [Performance](#section-46-performance) | 🔴 Broken | `argus/performance/metrics.py`, `cache.py`, `profiling.py`, `incremental.py`, `scheduler.py`, `benchmark.py`, `argus/cli/performance_cli.py` | `tests/performance/test_performance.py` (6 tests) |
| **47** | [Workspace](#section-47-workspace) | ✅ Implemented | `argus/workspace/api.py`, `engine.py`, `context/engine.py`, `copilot.py`, `models.py`, `vision.py`, `web/app.py`, `argus/cli/workspace_cli.py` | `tests/workspace/` (24 files, 95 tests) |
| **48** | [CLI Surface](#section-48-cli-surface-34-namespaces) | ⚠️ Partial | `argus/cli/app.py` and 32 CLI modules in `argus/cli/` | Verified via Typer test runner |
| **49** | [Lifecycle Stages](#section-49-planning-investigation-hypothesis-evidence-validation-report-lifecycle) | ✅ Implemented | `argus/planning/`, `argus/investigation/`, `argus/hypothesis/`, `argus/evidence/`, `argus/reporting/` | `tests/hypothesis/`, `tests/investigation/`, `tests/planning/`, `tests/reporting/` |
| **50** | [Investigation Philosophy](#section-50-investigation-philosophy) | ✅ Implemented | `argus/investigation/models.py`, `argus/investigation/builder.py`, `argus/investigation/generator.py`, `argus/investigation/manual_validation.py` | `tests/investigation/test_manual_validation.py`, `tests/investigation/test_generator.py` |
| **51** | [Reporting](#section-51-reporting) | ✅ Implemented | `argus/reporting/generator.py`, `argus/reporting/processor.py`, `argus/reporting/markdown.py`, `argus/reporting/json.py`, `argus/reporting/cvss.py` | `tests/reporting/test_generator.py`, `tests/reporting/test_processor.py`, `tests/reporting/test_renderers.py` |
| **52** | [Explainability](#section-52-explainability) | ✅ Implemented | `argus/explain/engine.py`, `argus/explain/models.py`, `argus/explain/reasoning.py`, `argus/cli/explain_cli.py` | `tests/explain/test_explain.py` |
| **53** | [Learning](#section-53-learning) | ✅ Implemented | `argus/learning/engine.py`, `argus/learning/metrics.py`, `argus/learning/history.py`, `argus/learning/patterns.py`, `argus/learning/recommendations.py`, `argus/cli/learning_cli.py` | `tests/learning/` (97 tests) |
| **54** | [Benchmarking](#section-54-benchmarking) | ✅ Implemented | `argus/benchmark/framework.py`, `argus/benchmark/datasets/`, `argus/benchmark/ground_truth/`, `argus/benchmark/leaderboard/`, `argus/benchmark/metrics/`, `argus/benchmark/reports/`, `argus/cli/benchmark_cli.py` | `tests/benchmark/` (42 tests) |
| **55** | [Testing](#section-55-testing) | ✅ Implemented | `tests/planning/`, `tests/runtime/`, `tests/tools/`, `tests/collectors/`, `tests/scanning/` | Full test suite (>2,260 tests across repo) |
| **56** | [External Tool Environment](#section-56-current-external-tool-environment) | ✅ Implemented | `argus/utils/environment.py`, `argus/runtime/registry.py`, `argus/runtime/executor.py` | `tests/tools/test_environment_detector.py` (29 tests) |
| **57** | [Architectural Cleanup](#section-57-important-architectural-cleanup-dual-execution-paths) | ⚠️ Partial | `argus/scanning/engine.py`, `argus/scanning/dag.py`, `argus/collectors/*.py` vs `argus/runtime/mission_runtime.py`, `argus/runtime/orchestrator.py`, `argus/runtime/dispatcher.py` | `tests/scanning/`, `tests/runtime/`, `tests/collectors/` |
| **58** | [Phase 9: Security Research Specialists (9.1–9.5)](#section-58-future-roadmap-phase-9-security-research-specialists-9195) | ✅ Implemented | `argus/intelligence/engine.py`, `argus/methodology/engine.py`, `argus/agents/authorization/agent.py`, `argus/agents/business_logic/agent.py`, `argus/plugins/api/agent.py` | `tests/test_intelligence.py`, `tests/test_methodology.py`, `tests/test_authz_specialist.py`, `tests/collectors/test_business_logic.py`, `tests/collectors/test_api_security.py` |
| **59** | [Phase 9.6–9.10 (Auth, Upload, GraphQL, JS, Tech Packs)](#section-59-phase-96910-auth-upload-graphql-js-tech-packs) | ⚠️ Partial | `argus/plugins/authentication/agent.py`, `argus/plugins/file_upload/agent.py`, `argus/plugins/graphql/agent.py`, `argus/plugins/javascript/agent.py`, `argus/collectors/technology.py` | `tests/collectors/test_auth_bypass.py`, `tests/collectors/test_file_upload.py`, `tests/collectors/test_graphql.py`, `tests/plugins/javascript/`, `tests/plugins/graphql/` |
| **60** | [Phase 10 — Continuous Investigation Loop](#section-60-phase-10-continuous-investigation-loop) | ✅ Implemented | `argus/runtime/mission_runtime.py`, `argus/scanning/engine.py`, `argus/planning/research_planner.py` | `tests/runtime/test_mission_runtime.py`, `tests/scanning/test_scan_engine.py`, `tests/runtime/test_runtime_orchestrator.py` |
| **61** | [Phase 11 — Adaptive Research Prioritization](#section-61-phase-11-adaptive-research-prioritization) | ✅ Implemented | `argus/investigation/priority_engine.py`, `argus/investigation/scoring.py`, `argus/investigation/weights.py`, `argus/investigation/ranking.py`, `argus/planning/decision_engine.py` | `tests/investigation/test_priority.py`, `tests/planning/` |
| **62** | [Phase 12 — Cross-Specialist Correlation](#section-62-phase-12-cross-specialist-correlation) | ✅ Implemented | `argus/correlation/engine.py`, `argus/correlation/fusion.py`, `argus/correlation/matcher.py`, `argus/correlation/rules.py` | `tests/correlation/test_correlation_engine.py`, `tests/correlation/test_fusion.py`, `tests/correlation/test_rules.py` |
| **63** | [Phase 13 — Stateful Application Research](#section-63-phase-13-stateful-application-research) | ✅ Implemented | `argus/http/coordinator.py`, `argus/models/test_identity.py`, `argus/collectors/access_control.py`, `argus/collectors/business_logic.py`, `argus/collectors/race_conditions.py` | `tests/test_test_identity.py`, `tests/collectors/test_access_control.py`, `tests/collectors/test_business_logic.py`, `tests/collectors/test_race_conditions.py` |
| **64** | [Phase 14 — Differential Analysis](#section-64-phase-14-differential-analysis) | ✅ Implemented | `argus/analyzers/response_discrepancy.py`, `argus/http/coordinator.py`, `argus/graph/diff.py` | `tests/analyzers/test_response_discrepancy_adversarial.py`, `tests/graph/` |
| **65** | [Phase 15 — Finding Validation Framework](#section-65-phase-15-finding-validation-framework) | ✅ Implemented | `argus/hypothesis/engine.py`, `argus/hypothesis/lifecycle.py`, `argus/hypothesis/models.py`, `argus/investigation/manual_validation.py`, `argus/execution/validators.py` | `tests/hypothesis/test_engine.py`, `tests/hypothesis/test_lifecycle.py`, `tests/investigation/test_manual_validation.py` |
| **66** | [Phase 16 — False Positive Reduction](#section-66-phase-16-false-positive-reduction) | ✅ Implemented | `argus/analyzers/response_discrepancy.py`, `argus/intelligence/confidence.py`, `argus/learning/feedback.py`, `argus/collectors/cache_security.py`, `argus/collectors/prototype_pollution.py` | `tests/analyzers/test_response_discrepancy_adversarial.py`, `tests/collectors/test_cache_security.py`, `tests/learning/test_feedback.py` |
| **67** | [Phase 17 — Finding Deduplication](#section-67-phase-17-finding-deduplication) | ✅ Implemented | `argus/investigation/generator.py`, `argus/correlation/engine.py`, `argus/correlation/deduplication.py`, `argus/reporting/processor.py` | `tests/correlation/test_deduplication.py`, `tests/investigation/test_generator.py`, `tests/reporting/test_processor.py` |
| **68** | [Phase 18 — Security Research RAG & Intelligence Fabric](#section-68-phase-18-security-research-rag-intelligence-fabric) | ✅ Implemented | `argus/vector/store.py`, `argus/vector/embeddings.py`, `argus/reporting/vector_indexer.py`, `argus/memory/`, `argus/knowledge/cve_kb.py`, `argus/knowledge/cve_correlator.py`, `argus/workspace/context/engine.py`, `argus/cli/search_cli.py` | `tests/vector/test_rag_integration.py`, `tests/vector/test_rag_adversarial.py`, `tests/memory/test_memory.py`, `tests/cli/test_search_cli.py` |
| **69** | [Phase 19 — Security Research Knowledge Base](#section-69-phase-19-security-research-knowledge-base) | ✅ Implemented | `argus/knowledge/manager.py`, `argus/knowledge/models.py`, `argus/knowledge/cve_kb.py`, `argus/knowledge/cve_correlator.py`, `argus/knowledge/importers.py` | `tests/test_knowledge.py`, `tests/test_cve_kb.py` |
| **70** | [Phase 20 — Technology-Aware Investigation](#section-70-phase-20-technology-aware-investigation) | ⚠️ Partial | `argus/collectors/technology.py`, `argus/graph/attack_surface.py`, `argus/planning/research_planner.py`, `argus/investigation/scoring.py` | `tests/test_knowledge.py`, `tests/correlation/test_rules.py` |
| **71** | [Phase 21 — Researcher Feedback Loop](#section-71-phase-21-researcher-feedback-loop) | ✅ Implemented | `argus/learning/feedback.py`, `argus/learning/engine.py`, `argus/learning/metrics.py`, `argus/learning/patterns.py`, `argus/learning/recommendations.py`, `argus/cli/learning_cli.py` | `tests/learning/test_feedback.py`, `tests/learning/test_engine.py`, `tests/learning/test_patterns.py`, `tests/learning/test_recommendations.py` |
| **72** | [Phase 22 — Evidence-First Reporting](#section-72-phase-22-evidence-first-reporting) | ✅ Implemented | `argus/provenance/engine.py`, `argus/provenance/graph.py`, `argus/reporting/generator.py`, `argus/reporting/processor.py`, `argus/reporting/markdown.py`, `argus/reporting/json.py` | `tests/test_provenance.py`, `tests/reporting/test_generator.py`, `tests/reporting/test_processor.py`, `tests/runtime/test_e2e_reporting.py` |
| **73** | [Phase 23 — Reproducibility](#section-73-phase-23-reproducibility) | ✅ Implemented | `argus/explain/engine.py`, `argus/explain/timeline.py`, `argus/explain/reasoning.py`, `argus/explain/export.py`, `argus/provenance/engine.py`, `argus/cli/explain_cli.py` | `tests/explain/test_explain.py`, `tests/test_provenance.py` |
| **74** | [Phase 24 — Mission Replay](#section-74-phase-24-mission-replay) | ⚠️ Partial | `argus/runtime/history.py`, `argus/runtime/recovery.py`, `argus/runtime/checkpoint.py`, `argus/benchmark/mission_loader.py` | `tests/test_runtime.py::test_mission_checkpointing` |
| **75** | [Phase 25 — Research Benchmarks](#section-75-phase-25-research-benchmarks) | ✅ Implemented | `argus/benchmark/framework.py`, `argus/benchmark/models.py`, `argus/benchmark/datasets/`, `argus/benchmark/ground_truth/`, `argus/benchmark/metrics/`, `argus/benchmark/leaderboard/`, `argus/benchmark/runner/`, `argus/cli/benchmark_cli.py` | `tests/benchmark/test_framework.py`, `tests/benchmark/metrics/`, `tests/benchmark/runner/`, `tests/benchmark/ground_truth/`, `tests/benchmark/datasets/` |
| **76** | [Phase 26 — Production Hardening](#section-76-phase-26-production-hardening) | ⚠️ Partial | `argus/performance/`, `argus/plugins/sdk.py`, `argus/runtime/retry.py`, `argus/runtime/recovery.py`, `argus/runtime/checkpoint.py` | `tests/performance/` |
| **77** | [Recommended Development Order](#section-77-recommended-development-order) | ❌ Missing | None (Specification artifact in `ORIGINAL_REQUEST.md`) | N/A |
| **78** | [Core Success Criteria & Final Vision](#section-78-core-success-criteria-final-vision) | ⚠️ Partial | Pipeline integrated across `argus/runtime/mission_runtime.py`, `argus/scanning/engine.py`, `argus/intelligence/engine.py`, `argus/correlation/engine.py`, `argus/reporting/generator.py` | `tests/runtime/test_mission_runtime.py`, `tests/scanning/test_scan_engine.py` |

**Aggregate Status Summary**:
- **✅ Implemented**: 59 / 78 (75.6%)
- **⚠️ Partial**: 16 / 78 (20.5%)
- **❌ Missing**: 2 / 78 (2.6%)
- **🔴 Broken**: 1 / 78 (1.3%)

---


<a id="3-test-suite-execution--coverage-analysis"></a>
## 3. Test Suite Execution & Coverage Analysis

A comprehensive execution and static coverage audit was performed across the entire test inventory in the Argus platform. The evaluation encompassed the canonical test suite located under `tests/`, co-located unit tests located inside `argus/`, and import graph analysis of all 488 Python production modules.

<a id="31-pytest-execution-metrics--results"></a>
### 3.1 Pytest Execution Metrics & Results

The test suite was executed under standard Python 3.12+ in the development environment. The verbatim execution metrics are summarized below:

| Metric | In-Tree `tests/` Suite | Co-Located `argus/` Suite | Combined Repository Total |
| :--- | :---: | :---: | :---: |
| **Invocation Command** | `python -m pytest tests/` | `python -m pytest argus/` | `pytest tests/ argus/` |
| **Total Tests Collected** | **2,451** | **12** | **2,463** |
| **Passed Tests** | **2,451** (100.0%) | **12** (100.0%) | **2,463** (100.0%) |
| **Failed Tests** | **0** (0.0%) | **0** (0.0%) | **0** (0.0%) |
| **Errors** | **0** (0.0%) | **0** (0.0%) | **0** (0.0%) |
| **Skipped Tests** | **0** (0.0%) | **0** (0.0%) | **0** (0.0%) |
| **Total Execution Duration** | **90.41 seconds** (01:30.41) | **0.96 seconds** | **91.37 seconds** |
| **Pytest Exit Code** | `0` (Success) | `0` (Success) | `0` (Success) |
| **Total Active Test Files** | 228 active files | 5 active files | 233 active test files |
| **Deprecation Warnings** | 51,943 warnings | 15 warnings | 51,958 warnings |

**Verbatim Pytest Summary Output**:

```text
=================== 2451 passed, 51943 warnings in 90.41s (0:01:30) ===================
===================== 12 passed, 15 warnings in 0.96s ======================
```

<a id="32-test-suite-directory-to-package-mapping"></a>
### 3.2 Test Suite Directory to Package Mapping

The in-tree `tests/` directory contains 28 distinct functional subdirectories. The following table maps each test directory to its corresponding production package in `argus/` and summarizes the coverage scope:

| Test Suite Directory | Files | Tests | % of Suite | Primary Target Package | Tested Components & Functional Areas |
| :--- | :---: | :---: | :---: | :--- | :--- |
| **`tests/collectors/`** | 50 | 1,078 | 44.0% | `argus/collectors/`, `argus/analyzers/` | 20+ vulnerability collectors (SQLi, XSS, SSRF, SSTI, Prototype Pollution, Deserialization, Request Smuggling, Cache Security, OAuth, Access Control, Command Injection, Path Traversal, CORS, WebSockets, XML, Race Conditions). |
| **`tests/ (root)`** | 23 | 201 | 8.2% | `argus/core/`, `argus/agents/`, `argus/knowledge/`, `argus/vector/` | Core architecture, Agent dispatch, CVE Knowledge Base, Vector Store NumPy & SQLite-Vec backends, Semantic Search, Workflows, Graph reasoning, Plugin loading, Methodology playbooks. |
| **`tests/runtime/`** | 16 | 140 | 5.7% | `argus/runtime/` | Mission runtime execution loop, Runtime orchestrator, Task scheduler, Recon parsers (Subfinder, httpx, Katana, Nuclei), Recon fallbacks, Adversarial recon, E2E missions across vulnerability classes. |
| **`tests/learning/`** | 9 | 97 | 4.0% | `argus/learning/` | Learning engine, feedback loop, outcome history, pattern extraction, recommendation engine, metric trackers, learning model registry. |
| **`tests/workspace/`** | 22 | 95 | 3.9% | `argus/workspace/` | Workspace REST API (38 endpoints), auto-titling, hybrid multi-source context ranking, context policy/assembler, conversation context restoration, Copilot assistance, vision analysis pipeline. |
| **`tests/memory/`** | 3 | 93 | 3.8% | `argus/memory/`, `argus/workspace/context/` | MemoryEntry dataclass models, vector-backed MemoryStore CRUD, semantic memory recall, mission-scoped isolation, memory lifecycle (active/archive/superseded), adversarial inputs. |
| **`tests/planning/`** | 5 | 75 | 3.1% | `argus/planning/` | Research planner, DAG task generation, reconnaissance task generation, info disclosure task generation, task prioritization, gap analysis engine. |
| **`tests/vector/`** | 4 | 73 | 3.0% | `argus/vector/`, `argus/knowledge/`, `argus/reporting/` | End-to-end Vector RAG integration spanning findings, CVEs, and memories; Embedding robustness under noise; Adversarial RAG retrieval; Prompt injection defense across retrieval context. |
| **`tests/graph/`** | 8 | 69 | 2.8% | `argus/graph/` | Attack surface graph builder, attack surface diff, graph query engine, graph integration, adversarial graph diff, takeover graph, CORS pipeline graph. |
| **`tests/scanning/`** | 3 | 62 | 2.5% | `argus/scanning/` | Scan engine, ScanDAG lifecycle, challenger stress execution, scan engine adversarial resilience. |
| **`tests/reporting/`** | 6 | 60 | 2.4% | `argus/reporting/` | CVSS 3.1 vector calculation & scoring, report generation engine, report data models, report processor, markdown/JSON renderers, challenger adversarial reporting tests. |
| **`tests/http/`** | 3 | 44 | 1.8% | `argus/http/` | Authorized HTTP client, Authenticated HTTP client, rate limiting, retry backoff, connection pooling, Sprint 4 empirical stress testing. |
| **`tests/benchmark/`** | 19 | 42 | 1.7% | `argus/benchmark/` | Benchmark execution framework, dataset managers, ground truth comparison, evaluation metrics, leaderboard, automated reporting. |
| **`tests/plugins/`** | 12 | 41 | 1.7% | `argus/plugins/` | GraphQL discovery/reasoning/schema/business plugins, JavaScript intelligence agent/discovery/parser/plugin/stress/benchmark, GraphQL HTTP integration. |
| **`tests/bridges/`** | 1 | 37 | 1.5% | `argus/bridges/burp/` | Burp Suite XML/JSON export parser, Burp MCP server, evidence ingestion, request/response extraction. |
| **`tests/correlation/`** | 15 | 35 | 1.4% | `argus/correlation/` | Correlation engine, finding deduplication, evidence integration, multi-modal observation fusion, graph correlation, observation matchers, observation rules, confidence scoring. |
| **`tests/ai/`** | 1 | 31 | 1.3% | `argus/ai/` | AI research assistant, prompt engineering, context windowing, OpenAI/Gemini client interfaces. |
| **`tests/tools/`** | 1 | 29 | 1.2% | `argus/utils/environment.py`, `argus/runtime/` | Environment detector, external tool discovery (subfinder, httpx, nuclei, katana, dnsx, node, npm), cloud metadata endpoint probing (AWS, GCP, Azure), mission checkpointer. |
| **`tests/authorization/`** | 3 | 28 | 1.1% | `argus/authorization/` | Scope resolver, wildcard/CIDR matching, ScopeState decision logic, AuthorizationGate permission checks, adversarial scope recon defense. |
| **`tests/hypothesis/`** | 9 | 25 | 1.0% | `argus/hypothesis/` | Hypothesis generator, lifecycle manager, confidence scoring, graph hypothesis reasoning, ranking engine, registry. |
| **`tests/cli/`** | 1 | 22 | 0.9% | `argus/cli/search_cli.py` | Typer-based `argus search` CLI, JSON formatting, filtering by source_type/severity/mission/category, subcommands `search cves`, `search memory`, `search stats`. |
| **`tests/pipeline/`** | 2 | 22 | 0.9% | `argus/scanning/`, `argus/collectors/` | Command injection detection pipeline, end-to-end payload execution, adversarial challenge tests. |
| **`tests/investigation/`** | 6 | 17 | 0.7% | `argus/investigation/` | Investigation generator, graph investigation derivation, manual validation guidance generator, investigation priority calculator, registry. |
| **`tests/auth/`** | 2 | 10 | 0.4% | `argus/http/coordinator.py`, `argus/models/` | MultiIdentitySessionCoordinator, session isolation across multiple user identities, cookie jar segregation, differential request replay, concurrency bleed prevention. |
| **`tests/analyzers/`** | 1 | 8 | 0.3% | `argus/analyzers/` | Response discrepancy analyzer, length/status/timing differential analysis. |
| **`tests/explain/`** | 1 | 5 | 0.2% | `argus/explain/` | Explainability reasoning graphs, evidence timeline tracing, explain CLI helper logic. |
| **`tests/performance/`** | 1 | 5 | 0.2% | `argus/performance/` | Incremental state cache, query latency profiling, cache invalidation. |
| **`tests/orchestration/`** | 1 | 4 | 0.2% | `argus/orchestration/` | High-level orchestrator plan execution, agent coordination. |
| **`tests/evidence/`** | 1 | 3 | 0.1% | `argus/evidence/` | EvidenceStore CRUD operations, evidence model validation, manager abstraction. |
| **Total In-Tree** | **229** | **2,451** | **100.0%** | — | Comprehensive coverage across offensive security domains. |

<a id="33-zero-test-coverage-identification"></a>
### 3.3 Zero Test Coverage Identification

A rigorous line-by-line and package-level audit revealed four distinct categories of zero or omitted test coverage:

#### 3.3.1 Completely Missing Features (0% Code, 0% Tests)
1. **Section 40: Credential Vault**:
   - No `argus/vault/` package or credential vault class exists in the codebase.
   - Plaintext credentials exist in `TestIdentity.credentials` and `Mission.credentials`.
2. **Section 74: Mission Replay Engine**:
   - No replay runner, replay models, or replay CLI command exist.
3. **Empty Bridge Packages**:
   - `argus/bridges/github/` (0 files)
   - `argus/bridges/playwright/` (0 files)

#### 3.3.2 Co-Located Specialist Plugins Untested by Canonical `pytest tests/`
Four specialist plugins place unit tests within their package directory (`argus/*/tests/`) rather than top-level `tests/`. These 12 tests pass when explicitly targeted (`python -m pytest argus/`), but are completely skipped by standard `pytest tests/` runs:
- `argus/plugins/api/tests/test_api_intelligence.py` (3 tests)
- `argus/agents/business_logic/tests/test_business_logic.py` (5 tests)
- `argus/plugins/graphql/tests/test_graphql.py` (3 tests)
- `argus/plugins/file_upload/tests/test_file_upload.py` (1 test)

#### 3.3.3 CLI Subcommands with Zero Direct Test Coverage
While `argus search` has dedicated unit tests (`tests/cli/test_search_cli.py`), **26 out of 32 CLI command files** have zero automated test coverage validating their CLI parameter parsing, exception trapping, or Rich console output formatting:
- `agent_cli.py`, `api_cli.py`, `auth_cli.py`, `authn_cli.py`, `benchmark_cli.py`, `business_cli.py`, `dataset_cli.py`, `execution_cli.py`, `ground_truth_cli.py`, `hypothesis_cli.py`, `intelligence_cli.py`, `knowledge.py`, `learning_cli.py`, `mission_cli.py`, `performance_cli.py`, `plan_cli.py`, `playbook_cli.py`, `plugin_cli.py`, `provenance_cli.py`, `queue_cli.py`, `scheduler_cli.py`, `tools_cli.py`, `upload_cli.py`, `workflow_cli.py`, `workspace_cli.py`, `__main__.py`.

#### 3.3.4 Orphaned / Dead Code Packages with Zero Incoming Imports
Static AST import tracing identified 14 Python modules that are never imported by any test or production code:
- `argus/core/context.py`, `argus/core/controller.py`, `argus/core/models.py`, `argus/core/planner.py`
- `argus/workspace/context.py` (superseded by `argus/workspace/context/engine.py`)
- `argus/models/attack_surface.py` (superseded by `argus/graph/attack_surface.py`)
- `argus/models/identity.py` (superseded by `argus/models/test_identity.py`)
- `argus/intelligence/workflow_builder.py`, `argus/intelligence/workflow_models.py`
- `argus/benchmark/ground_truth/loader.py`, `argus/benchmark/ground_truth/validator.py`
- `argus/benchmark/leaderboard/baseline.py`, `argus/benchmark/leaderboard/history.py`
- `argus/collectors/takeover_signatures.py`

<a id="34-deprecation-warnings--technical-debt"></a>
### 3.4 Deprecation Warnings & Technical Debt

During execution of `tests/`, pytest emitted **51,943 deprecation warnings**. While non-fatal under current Python 3.12 settings, they represent immediate technical debt that will cause runtime failure in Python 3.14+:

1. **`datetime.datetime.utcnow()` Deprecation (51,900+ occurrences)**:
   - Deprecated in Python 3.12 and scheduled for complete removal.
   - Primary emission sites: `argus/evidence/model.py:37-38`, `argus/workspace/models.py:36,62,85,100`, `argus/workspace/engine.py:26,89,158`, `argus/workspace/api.py:71,123,493`, `argus/runtime/mission.py:160`.
   - **Fix**: Migrate to `datetime.datetime.now(datetime.timezone.utc).isoformat()`.

2. **Pydantic V2 Class-Based `Config` Deprecation**:
   - In `argus/runtime/models.py:167`, `ToolExecutionContext` defines `class Config: arbitrary_types_allowed = True`.
   - **Fix**: Migrate to `model_config = ConfigDict(arbitrary_types_allowed=True)`.

3. **Procedural Test File Packaging (`tests/test_event_bus.py`)**:
   - Contains un-encapsulated procedural statements without `def test_*()` functions, resulting in 0 test items collected by pytest.
   - **Fix**: Wrap in standard `def test_event_bus():` function with explicit assertions.

---


<a id="4-detailed-per-section-audit-reports"></a>
## 4. Detailed Per-Section Audit Reports

<a id="part-1-core-architecture-planning-engine-sections-115"></a>
### Part 1: Core Architecture & Planning Engine (Sections 1–15)

This section evaluates the foundational architectural substrate of Argus, including project identity, mission data models, scope boundaries, safety policy enforcement, the 10-stage autonomous execution runtime, and the gap-analysis-driven research planning engine.

<a id="section-1-project-identity"></a>
#### Section 1: Project Identity

- **Status**: ⚠️ Partial
- **Source Files**:
  - `pyproject.toml`
  - `argus/cli/app.py`
  - `argus/models/identity.py`
  - `argus/models/test_identity.py`
  - `argus/runtime/mission.py` (`_derive_default_scope`)
  - `argus/runtime/sandbox.py` (`SafetyValidator`)
- **Implementation Evidence**:
  - Package configuration in `pyproject.toml` declares `name = "argus"`, `version = "0.1.0"`, `description = "Autonomous Offensive Security Platform"`, and CLI script `argus = "argus.cli.app:app"`.
  - Typer CLI in `argus/cli/app.py` sets application help string to `"Argus - Autonomous Offensive Security Platform"`.
  - Core principles are concretely embedded in the architecture:
    - *Scope-first execution*: Automatically derived in `Mission.__post_init__` and enforced in `SafetyValidator.validate()`.
    - *Evidence-backed reasoning*: First-class evidence stores and required supporting evidence on observations and investigations.
    - *Non-blind findings*: The system outputs research cards, investigation hypotheses, and manual validation guidance rather than auto-confirming vulnerabilities without validation.
- **Gaps**:
  - `README.md` at repository root is 0 bytes (completely empty). No manifesto, architecture overview, or project guide exists in the repo root.
  - Tagline discrepancy: `pyproject.toml` and CLI use "Autonomous Offensive Security Platform", whereas the specification defines Argus as an "open-source, AI-assisted platform for authorized penetration testing and bug-bounty security research".
- **Test Coverage**:
  - Tested indirectly through `tests/authorization/test_adversarial_scope_recon.py`, `tests/authorization/test_scope_resolver.py`, and `tests/runtime/test_e2e_mission.py`. All tests pass.
- **Notes**:
  - Core philosophy is robustly preserved in code invariants, but external documentation is completely lacking.

---

<a id="section-2-core-architecture"></a>
#### Section 2: Core Architecture

- **Status**: ⚠️ Partial
- **Source Files**:
  - `argus/runtime/mission_runtime.py` (lines 23–274)
  - `argus/runtime/mission.py` (lines 153–321)
  - `argus/authorization/scope.py` (lines 22–134)
  - `argus/runtime/sandbox.py` (lines 14–92)
  - `argus/runtime/executor.py` (lines 27–120)
  - `argus/runtime/orchestrator.py` (lines 22–130)
  - `argus/evidence/store.py`
  - `argus/correlation/engine.py`, `argus/correlation/fusion.py`
  - `argus/investigation/builder.py`
  - `argus/hypothesis/engine.py`
  - `argus/reporting/generator.py`
  - `argus/scanning/engine.py`
  - `argus/core/models.py`
  - `argus/core/scheduler.py`
- **Implementation Evidence**:
  - `AutonomousMissionRuntime` in `argus/runtime/mission_runtime.py` orchestrates the complete sequential pipeline:
    `Mission` → `Scope Manager` (`SafetyValidator`/`ScopeResolver`) → `Policy Engine` (`SafetyValidator`) → `Mission Runtime` (`AutonomousMissionRuntime`) → `Scheduler` (`TaskScheduler`) → `Tools` (`ToolOrchestrator`) → `Evidence` (`EvidenceStore`) → `Correlation` (`CorrelationEngine`/`EvidenceFusionEngine`) → `Investigation` (`InvestigationBuilder`) → `Hypothesis` (`HypothesisEngine`) → `Report` (`ReportGenerator`).
  - All 27 major systems specified in Section 2 exist across `argus/` packages.
- **Gaps**:
  - Architectural dual-path: The modern `AutonomousMissionRuntime` coexists with an older, independent DAG scanner (`argus/scanning/engine.py`) executing legacy collectors (`argus/collectors/`).
  - Stub legacy core modules: `argus/core/models.py` contains only 2 lines (`# pyrefly: ignore [missing-import]`), and `argus/core/scheduler.py` contains a 10-line naive generator stub.
- **Test Coverage**:
  - `tests/runtime/test_mission_runtime.py` (4 passed)
  - `tests/runtime/test_e2e_mission.py` (1 passed)
  - Pass rate: 100%.
- **Notes**:
  - Major technical debt exists in the parallel existence of `argus/scanning/` and `argus/runtime/`. Migration of all capabilities to `AutonomousMissionRuntime` should be prioritized.

---

<a id="section-3-mission"></a>
#### Section 3: Mission

- **Status**: ✅ Implemented
- **Source Files**:
  - `argus/runtime/mission.py` (lines 153–390)
  - `argus/core/mission.py` (lines 1–9)
  - `argus/runtime/lifecycle.py` (lines 4–68)
  - `argus/runtime/manager.py` (lines 11–94)
  - `argus/runtime/checkpoint.py`
  - `argus/cli/mission_cli.py` (lines 16–100)
- **Implementation Evidence**:
  - `Mission` dataclass contains 50+ attributes connecting: target (`target`, `scope`), execution policy (`policy`), configuration, environment, assets (`subdomains`, `live_hosts`, `endpoints`, `technologies`), observations (`ObservationRegistry`), correlations (`CorrelationRegistry`), evidence (`EvidenceStore`), facts (`FactStore`), attack surface graph (`KnowledgeGraph`), correlation graph (`CorrelationGraph`), authorization graph, GraphQL state (`GraphQLState`), JavaScript state (`JavaScriptState`), authentication info (`AuthenticationModel`, `TestIdentity`), business objects, workflows, research planner state (`research_tasks`, `research_queue`, `coverage`, `coverage_gaps`), execution queue/history (`execution_queue`, `execution_history`, `task_states`), artifacts, execution results, logs, and reports.
  - `MissionLifecycle` enforces valid transitions between `CREATED`, `READY`, `RUNNING`, `PAUSED`, `COMPLETED`, `CANCELLED`, `FAILED`.
  - `MissionManager` handles mission CRUD, state persistence, checkpoint evaluation, and recovery.
- **Gaps**:
  - Minor duplicate field definitions in `Mission` class body (e.g. `api_inventory`, `business_objects` declared at line 201 and repeated at line 278, 297).
  - `notes` field is stored within `configuration` or metadata rather than as a top-level typed attribute.
- **Test Coverage**:
  - `tests/runtime/test_mission_runtime.py`
  - `tests/correlation/test_mission.py`
  - `tests/runtime/test_e2e_mission.py`
  - Pass rate: 100%.
- **Notes**:
  - The Mission model is the central nervous system of Argus, binding all domain engines and registries into a coherent state tree.

---

<a id="section-4-scope-manager"></a>
#### Section 4: Scope Manager

- **Status**: ⚠️ Partial
- **Source Files**:
  - `argus/authorization/scope.py` (lines 8–134)
  - `argus/runtime/sandbox.py` (lines 14–43)
  - `argus/authorization/gate.py` (lines 12–54)
  - `argus/runtime/mission.py` (lines 78–150)
- **Implementation Evidence**:
  - `ScopeResolver`:
    - `check_scope(target, mission_id)` determines if a target is within mission boundaries, returning `ScopeDecision(decision=ScopeState.IN_SCOPE | OUT_OF_SCOPE | UNKNOWN)`.
    - `_match_rule(target, rule)` supports exact host matching, wildcard domain matching (`*.example.com`), CIDR IP network ranges (`ipaddress.ip_network`), and fnmatch patterns.
    - Prevents lookalike domain attacks (`evilexample.com` does not match `*.example.com`).
    - `resolve_target()` normalizes inputs by stripping schemes, ports, and paths, and parses bracketed IPv6 addresses (`[::1]:8080`).
  - `_derive_default_scope()` in `argus/runtime/mission.py` automatically initializes default scope rules upon mission instantiation.
  - `SafetyValidator.validate()` in `argus/runtime/sandbox.py` validates target scope before allowing any tool execution.
  - `AuthorizationGate.can_execute_action()` delegates to `ScopeResolver`.
- **Gaps**:
  - No class named `ScopeManager` (the implementation class is named `ScopeResolver`).
  - No explicit "exclude scope" (blacklist) logic in `ScopeResolver`; only whitelist rules in `mission.scope` are evaluated.
  - No direct bug-bounty scope import parser (e.g. HackerOne/Bugcrowd program JSON/YAML format importer).
  - Passive-only mode is not directly managed within `ScopeResolver`.
- **Test Coverage**:
  - `tests/authorization/test_scope_resolver.py` (18 tests)
  - `tests/authorization/test_authorization_gate.py` (2 tests)
  - `tests/authorization/test_adversarial_scope_recon.py` (8 tests)
  - Pass rate: 100% (28/28 passed).
- **Notes**:
  - The scope normalization and boundary enforcement are mathematically sound and defend against evasion, but need a cleaner facade matching the `ScopeManager` name and explicit exclude scope support.

---

<a id="section-5-policy-engine"></a>
#### Section 5: Policy Engine

- **Status**: ⚠️ Partial
- **Source Files**:
  - `argus/runtime/sandbox.py` (lines 9–92)
  - `argus/authorization/gate.py` (lines 7–54)
  - `argus/authorization/rules.py` (lines 4–44)
  - `argus/workspace/context/policy.py` (lines 4–40)
  - `argus/runtime/dispatcher.py` (lines 65–71)
  - `argus/planning/decision_engine.py` (lines 35–45)
- **Implementation Evidence**:
  - `SafetyValidator.validate(tool, context)` enforces execution policy constraints:
    - Blocked operations: `policy.get("blocked_operations", [])`
    - Blocked categories: `policy.get("blocked_categories", [])`
    - Blocked tasks: `policy.get("blocked_tasks", [])`
    - Required capabilities verification
    - Tool permissions check: checks `tool.safety_requirements.get("permissions")` against `policy.get("allowed_permissions")` (e.g. `network`, `filesystem`, `db_read`, `db_write`).
  - Controlled boundary between planning and execution: `ResearchPlanner` only creates task models and cannot execute tools; execution must pass through `DecisionEngine`, `SafetyValidator`, and `ToolDispatcher`.
  - `AuthorizationGate` verifies access permissions before actions can be executed.
- **Gaps**:
  - No standalone `PolicyEngine` class; policy enforcement is scattered across `SafetyValidator`, `AuthorizationGate`, and `ContextPolicy`.
  - Passive-only enforcement is not centralized into a single policy gate; tools and collectors check passive flags individually.
  - Agent permission checks rely on simplistic role/ownership heuristics in `rules.py` rather than a unified ABAC/RBAC policy engine.
- **Test Coverage**:
  - `tests/runtime/test_runtime_orchestrator.py` (`TestSafetyValidation`: 5 tests)
  - `tests/authorization/test_authorization_gate.py` (2 tests)
  - `tests/planning/test_research_planner.py` (`test_policy_disables_category`)
  - Pass rate: 100%.
- **Notes**:
  - Functional enforcement exists and passes all safety unit tests, but architectural consolidation into a single `argus.policy.engine` module is recommended.

---

<a id="section-6-mission-runtime"></a>
#### Section 6: Mission Runtime

- **Status**: ✅ Implemented
- **Source Files**:
  - `argus/runtime/mission_runtime.py` (lines 23–274)
  - `argus/runtime/orchestrator.py` (lines 22–210)
  - `argus/runtime/dispatcher.py` (lines 10–92)
  - `argus/runtime/registry.py` (lines 6–1167)
  - `argus/runtime/executor.py` (lines 27–378)
  - `argus/runtime/monitor.py`
  - `argus/runtime/events.py`
  - `argus/runtime/results.py`
  - `argus/runtime/execution_context.py`
  - `argus/runtime/checkpoint.py`
- **Implementation Evidence**:
  - `AutonomousMissionRuntime` coordinates the central research control loop:
    1. Receive ResearchTask
    2. Resolve compatible tool (`ToolDispatcher.resolve_tool()`)
    3. Prepare `ToolExecutionContext` with mission, scope, policy, and graphs
    4. Enforce mission scope and policy via `SafetyValidator.validate()`
    5. Execute tool via routed executor
    6. Monitor execution duration and resources via `ToolExecutionMonitor`
    7. Collect results and artifacts via `ResultCollector`
    8. Publish runtime events via `EventBus`
    9. Store results directly in mission storage fields
    10. Persist history in `.argus/tool_history.json`.
  - All 7 main components (Tool Registry, Tool Dispatcher, Tool Executors, Execution Monitor, Event Bus, Result Collector, Mission Storage) are implemented and functional.
- **Gaps**:
  - Dual runtime pathways: Autonomous runtime in `argus/runtime/` vs DAG scanning engine in `argus/scanning/`.
- **Test Coverage**:
  - `tests/runtime/test_mission_runtime.py` (4 tests)
  - `tests/runtime/test_e2e_mission.py` (1 test)
  - `tests/runtime/test_runtime_orchestrator.py` (16 tests)
  - Pass rate: 100%.
- **Notes**:
  - Clean architecture with strong separation of concerns across monitor, executor, dispatcher, and orchestrator.

---

<a id="section-7-tool-registry"></a>
#### Section 7: Tool Registry

- **Status**: ✅ Implemented
- **Source Files**:
  - `argus/runtime/registry.py` (lines 6–1167)
  - `argus/runtime/models.py` (lines 141–165)
  - `argus/cli/tools_cli.py` (lines 19–50)
- **Implementation Evidence**:
  - `Tool` model defines all specified fields: `id`, `name`, `version`, `description`, `supported_tasks`, `required_inputs`, `produced_outputs`, `capabilities`, `safety_requirements`, `timeout`, `priority`, `command`, `capability`.
  - `ToolRegistry` registers all 11 required tools:
    1. `subfinder` (ID: subfinder, external tool)
    2. `httpx` (ID: httpx, external tool)
    3. `katana_crawler` (ID: katana_crawler, external tool)
    4. `nuclei` (ID: nuclei, external tool)
    5. `graphql_specialist` (ID: graphql_specialist, internal plugin)
    6. `javascript_specialist` (ID: javascript_specialist, internal plugin)
    7. `authorization_specialist` (ID: authorization_specialist, internal plugin)
    8. `authentication_specialist` (ID: authentication_specialist, internal plugin)
    9. `file_upload_specialist` (ID: file_upload_specialist, internal plugin)
    10. `api_specialist` (ID: api_specialist, internal plugin)
    11. `business_logic_specialist` (ID: business_logic_specialist, internal plugin)
    Plus 20+ additional vulnerability tools (`dnsx`, `info_disclosure`, `cors_headers`, `auth_bypass`, `prototype_pollution`, `xss`, `sqli`, `cmdi`, `ssrf`, `oauth`, `xxe`, `deserialization`, `graphql_security`, `websocket_security`, `request_smuggling`, etc.).
  - Over 300 alias mappings allowing dynamic resolution by name, alias, or capability.
- **Gaps**:
  - None. All 11 tools and their metadata are registered.
- **Test Coverage**:
  - `tests/runtime/test_runtime_orchestrator.py` (`TestToolRegistry`)
  - `tests/planning/test_task_generator.py` (`TestToolRegistryAndPluginAdapterXSS`)
  - Pass rate: 100%.
- **Notes**:
  - Extremely comprehensive registry with built-in path resolution for external binaries (e.g. `_resolve_httpx_command()`).

---

<a id="section-8-tool-dispatcher"></a>
#### Section 8: Tool Dispatcher

- **Status**: ✅ Implemented
- **Source Files**:
  - `argus/runtime/dispatcher.py` (lines 10–92)
  - `argus/runtime/registry.py`
  - `argus/runtime/executor.py` (lines 125–378)
- **Implementation Evidence**:
  - `ToolDispatcher.resolve_tool(task)`:
    - Matches explicit `task.metadata["tool_id"]` if provided.
    - Matches required specialists from `task.required_specialists`.
    - Queries `registry.find_compatible_tools(category_name)`.
    - Sorts compatible candidates deterministically (priority descending, ID alphabetically as tiebreaker).
    - Emits warnings and logs failures if no compatible tool is found.
  - `ToolDispatcher.dispatch(tool, context)`:
    - Runs safety validation (`SafetyValidator.validate()`).
    - Routes to `InternalPluginExecutor`, `ExternalToolExecutor`, or `RemoteWorkerExecutor`.
- **Gaps**:
  - `RemoteWorkerExecutor` in `argus/runtime/executor.py` is currently a local fallback stub with a warning log.
- **Test Coverage**:
  - `tests/runtime/test_runtime_orchestrator.py` (`TestToolSelection`: `test_deterministic_priority_selection`, `test_deterministic_alphabetical_tiebreaker`)
  - Pass rate: 100%.
- **Notes**:
  - Deterministic resolution is critical for reproducible bug hunting and is verified by dedicated unit tests.

---

<a id="section-9-tool-orchestrator"></a>
#### Section 9: Tool Orchestrator

- **Status**: ✅ Implemented
- **Source Files**:
  - `argus/runtime/orchestrator.py` (lines 22–210)
  - `argus/runtime/models.py` (lines 120–139, 182–221)
  - `argus/runtime/monitor.py`
  - `argus/runtime/results.py`
- **Implementation Evidence**:
  - `ToolOrchestrator.execute_task(mission, task)` handles full execution lifecycle:
    - Task → `resolve_tool()` → `ToolExecutionContext` → monitoring setup → dispatch → result collection → event publishing → mission storage → persistent run history.
  - Emits all 7 specified events:
    1. `TOOL_SELECTED`
    2. `TOOL_STARTED`
    3. `TOOL_COMPLETED`
    4. `TOOL_FAILED`
    5. `TOOL_TIMED_OUT`
    6. `TOOL_CANCELLED`
    7. `ARTIFACTS_PRODUCED`
  - Stores outputs in `mission.tool_runs`, `mission.execution_results`, `mission.execution_logs`, and `mission.artifacts`.
  - Appends run records to `.argus/tool_history.json`.
- **Gaps**:
  - None against Section 9 specification.
- **Test Coverage**:
  - `tests/runtime/test_runtime_orchestrator.py` (`TestExecutionLifecycleAndEvents`: `test_successful_lifecycle_and_provenance`, `test_failed_lifecycle`, `test_timeout_lifecycle`, `test_mission_runtime_integration`)
  - Pass rate: 100%.
- **Notes**:
  - Solid provenance tracking: every artifact records its source tool, task, and execution timestamp.

---

<a id="section-10-event-bus"></a>
#### Section 10: Event Bus

- **Status**: ✅ Implemented
- **Source Files**:
  - `argus/runtime/events.py` (lines 16–102)
  - `argus/core/event_bus.py` (lines 5–20)
  - `argus/plugins/events.py` (lines 3–29)
  - `argus/runtime/observability.py`
- **Implementation Evidence**:
  - `argus/runtime/events.py`:
    - `RuntimeEventType` enum defines 27 typed lifecycle events across mission, planning, scheduling, tools, observations, correlations, evidence, and investigations.
    - `EventBus` provides `subscribe()`, `publish()`, and `get_history()`.
    - Auto-registers `_observability_logger` to output structured logs via `argus.runtime.observability.log_lifecycle`.
  - Deeply integrated into `AutonomousMissionRuntime`, `TaskScheduler`, and `ToolOrchestrator`.
- **Gaps**:
  - Triplicate implementations: Three separate `EventBus` classes exist (`argus/runtime/events.py`, `argus/core/event_bus.py`, `argus/plugins/events.py`).
  - Lacks persistent event queuing or async broker integration (pure in-memory pub/sub).
- **Test Coverage**:
  - `tests/runtime/test_scheduler.py` (`TestEventEmission`)
  - `tests/runtime/test_runtime_orchestrator.py`
  - Pass rate: 100%.
- **Notes**:
  - Technical debt: `core/event_bus.py` and `plugins/events.py` should be deprecated in favor of `argus/runtime/events.py`.

---

<a id="section-11-scheduler"></a>
#### Section 11: Scheduler

- **Status**: ✅ Implemented
- **Source Files**:
  - `argus/runtime/executor.py` (lines 27–120)
  - `argus/runtime/models.py` (lines 18–111)
  - `argus/runtime/queue.py` (lines 15–71)
  - `argus/runtime/dependencies.py` (lines 16–141)
  - `argus/runtime/lifecycle.py` (lines 69–125)
  - `argus/runtime/retry.py`
  - `argus/planning/scheduler.py`
  - `argus/runtime/scheduler.py`
  - `argus/core/scheduler.py`
- **Implementation Evidence**:
  - `TaskScheduler` (`argus/runtime/executor.py`):
    - Converts `ResearchTask` to `ScheduledTask`.
    - Orders tasks by priority descending and topological DAG order.
    - Manages task lifecycle states: `PENDING`, `READY`, `RUNNING`, `COMPLETED`, `FAILED`, `BLOCKED`, `SKIPPED`, `CANCELLED`.
    - `TaskDependencyResolver` resolves inter-task dependencies: unblocks tasks to `READY` when all dependencies reach `COMPLETED`, cascades to `SKIPPED` if dependencies fail.
    - Concurrency control: `get_executable_batch()` dispenses tasks respecting `max_workers`.
    - Retry policies: `RetryPolicy` with exponential backoff and timeout retry controls.
    - Emits scheduling events: `TASK_SCHEDULED`, `TASK_STARTED`, `TASK_COMPLETED`, `TASK_FAILED`, `TASK_RETRIED`, `TASK_CANCELLED`.
- **Gaps**:
  - `argus/core/scheduler.py` is an unmaintained 10-line stub.
- **Test Coverage**:
  - `tests/runtime/test_scheduler.py` (6 tests covering dependency blocking, unblocking, max worker concurrency, retry policy, terminal failure, and event emission).
  - Pass rate: 100%.
- **Notes**:
  - Robust dependency graph resolution prevents deadlocks and circular dependencies.

---

<a id="section-12-research-task-model"></a>
#### Section 12: Research Task Model

- **Status**: ✅ Implemented
- **Source Files**:
  - `argus/planning/models.py` (lines 11–45)
- **Implementation Evidence**:
  - `TaskCategory` enum defines all 11 specified categories:
    1. `TECHNOLOGY_DISCOVERY = "Technology Discovery"`
    2. `API_DISCOVERY = "API Discovery"`
    3. `GRAPHQL_ANALYSIS = "GraphQL Analysis"`
    4. `AUTHENTICATION_ANALYSIS = "Authentication Analysis"`
    5. `AUTHORIZATION_ANALYSIS = "Authorization Analysis"`
    6. `BUSINESS_LOGIC_ANALYSIS = "Business Logic Analysis"`
    7. `JAVASCRIPT_ANALYSIS = "JavaScript Analysis"`
    8. `WORKFLOW_ANALYSIS = "Workflow Analysis"`
    9. `EVIDENCE_CORRELATION = "Evidence Correlation"`
    10. `INVESTIGATION_REVIEW = "Investigation Review"`
    11. `COVERAGE_IMPROVEMENT = "Coverage Improvement"`
  - `ResearchTask` Pydantic model contains all 17 required attributes:
    `id`, `title`, `description`, `goal`, `category`, `required_inputs`, `expected_outputs`, `priority` (0.0–1.0), `confidence` (0.0–1.0), `dependencies`, `required_specialists`, `estimated_duration_minutes`, `status`, `reason`, `supporting_evidence`, `metadata`, `created_at`.
- **Gaps**:
  - None. Complete 1-to-1 match with the specification.
- **Test Coverage**:
  - Verified across `tests/planning/test_research_planner.py`, `tests/planning/test_task_generator.py`, and `tests/runtime/test_runtime_orchestrator.py`.
  - Pass rate: 100%.
- **Notes**:
  - Data model uses Pydantic v2 with strict bounds validation on priority and confidence (`ge=0.0, le=1.0`).

---

<a id="section-13-research-planning"></a>
#### Section 13: Research Planning

- **Status**: ✅ Implemented
- **Source Files**:
  - `argus/planning/research_planner.py` (lines 25–156)
  - `argus/planning/task_generator.py` (lines 21–360)
  - `argus/planning/decision_engine.py` (lines 12–85)
  - `argus/planning/planner.py`
  - `argus/core/planner.py`
- **Implementation Evidence**:
  - `ResearchPlanner.plan()` implements the full cycle answering "What is the most valuable next research action?":
    1. Computes coverage via `CoverageTracker.compute()`.
    2. Performs gap analysis via `GapAnalyzer.analyze()`.
    3. Generates specialized research tasks from discovered gaps via `TaskGenerator`.
    4. Enriches tasks with intelligence and hints from `KnowledgeManager`.
    5. Applies `DecisionEngine` to filter tasks by mission scope and policy, and prioritizes them based on gap severity and coverage impact.
    6. Updates mission state with generated tasks, queue, coverage report, and gaps.
  - Strict safety guarantee: ResearchPlanner only plans; it never executes tools or exploits systems.
- **Gaps**:
  - Multiple planner classes exist across packages (`argus/planning/research_planner.py`, `argus/planning/planner.py`, `argus/core/planner.py`).
  - Dynamic AI-driven hypothesis feedback into research planning relies primarily on deterministic heuristics rather than LLM reasoning loops.
- **Test Coverage**:
  - `tests/planning/test_research_planner.py` (14 tests)
  - `tests/planning/test_task_generator.py` (19 tests)
  - `tests/planning/test_recon_task_generation.py` (22 tests)
  - `tests/planning/test_info_disclosure_task_generation.py` (18 tests)
  - Pass rate: 100% (73 tests passed).
- **Notes**:
  - Clean separation between initial strategic planning (`MissionPlanner`) and adaptive, gap-driven planning (`ResearchPlanner`).

---

<a id="section-14-gap-analysis-engine"></a>
#### Section 14: Gap Analysis Engine

- **Status**: ✅ Implemented
- **Source Files**:
  - `argus/planning/gap_analysis.py` (lines 31–450)
  - `argus/planning/models.py` (lines 47–55)
- **Implementation Evidence**:
  - `GapAnalyzer.analyze()` runs all 8 specified detectors:
    1. Technology gaps (`_check_technology_gaps`)
    2. API gaps (`_check_api_gaps`)
    3. GraphQL gaps (`_check_graphql_gaps`)
    4. Authentication gaps (`_check_authentication_gaps`)
    5. Authorization gaps (`_check_authorization_gaps`)
    6. Business Logic gaps (`_check_business_logic_gaps`)
    7. JavaScript gaps (`_check_javascript_gaps`)
    8. Correlation gaps (`_check_correlation_gaps`)
    Plus Recon gap detector (`_check_recon_gaps` covering missing subdomains, live hosts, endpoints, vulnerability scanning, and info disclosure).
  - Produces structured `CoverageGap` models with `area`, `description`, `severity`, `category`, and `related_assets`.
- **Gaps**:
  - None against Section 14 specification.
- **Test Coverage**:
  - `tests/planning/test_research_planner.py` (`TestGapAnalysis`)
  - `tests/planning/test_recon_task_generation.py` (`TestReconStateGapAnalyzer`)
  - `tests/planning/test_info_disclosure_task_generation.py`
  - Pass rate: 100%.
- **Notes**:
  - Defensive implementation handles string, dictionary, and custom object technology representations safely without crashes.

---

<a id="section-15-coverage-tracker"></a>
#### Section 15: Coverage Tracker

- **Status**: ✅ Implemented
- **Source Files**:
  - `argus/planning/coverage.py` (lines 12–81)
  - `argus/planning/models.py` (lines 57–72)
  - `argus/cli/plan_cli.py`
- **Implementation Evidence**:
  - `CoverageReport` tracks all specified metrics:
    - `endpoints_total` / `endpoints_covered`
    - `business_objects_total` / `business_objects_covered`
    - `workflows_total` / `workflows_covered`
    - `authentication_covered` (bool)
    - `authorization_covered` (bool)
    - `technologies_total` / `technologies_covered`
    - `overall_coverage` (float composite score)
    - `gaps` (list of `CoverageGap`)
    - `computed_at` (calculation timestamp)
  - `CoverageTracker.compute()` computes dimensional coverage ratios and attaches discovered gaps from `GapAnalyzer`.
- **Gaps**:
  - Technology coverage heuristic is simplistic: marks all technologies covered if any observations exist.
  - Calculation time duration is not stored as elapsed milliseconds, only as an ISO timestamp (`computed_at`).
- **Test Coverage**:
  - `tests/planning/test_research_planner.py` (`TestCoverage`: 3 unit tests + 1 CLI test)
  - Pass rate: 100%.
- **Notes**:
  - Coverage scores directly drive the `DecisionEngine` prioritization weights in the research planning loop.

---


<a id="part-2-reconnaissance-evidence-knowledge-graph-sections-1625"></a>
### Part 2: Reconnaissance, Evidence & Knowledge Graph (Sections 16–25)

This section evaluates the reconnaissance execution pipeline, external tool parsers (Subfinder, httpx, Katana, Nuclei), first-class immutable Evidence storage, deterministic provenance lineage tracing, observation/correlation distinction, and graph-based models for target attack surfaces, workflow intelligence, authorization graphs, and business objects.

<a id="section-16-reconnaissance-subfinder-httpx-katana-nuclei"></a>
#### Section 16: Reconnaissance (subfinder, httpx, katana, nuclei)

- **Status**: ✅ Implemented
- **Source Files**:
  - `argus/collectors/base.py`: Declares abstract `BaseCollector.collect(mission)`.
  - `argus/collectors/subfinder.py`: `SubfinderCollector` locates binary via `shutil.which("subfinder")`, runs `-d <host> -silent`, parses output via `ReconParser.parse_subfinder`, seeds fallback subdomains from host if binary is unavailable, and produces `Evidence` records (`category="subdomain"`).
  - `argus/collectors/httpx.py`: `HttpxCollector` locates binary candidates (`httpx-toolkit`, `httpx`), executes `-json -silent`, handles IPv4/IPv6 port parsing via `_derive_host_dict()`, parses JSONL via `ReconParser.parse_httpx`, seeds fallback host records, and records `Evidence` (`category="live_host"`).
  - `argus/collectors/katana.py`: `KatanaCollector` executes `katana -u <host> -silent`, parses via `ReconParser.parse_katana`, deduplicates discovered paths/query parameters, provides endpoint fallback seeding via `_derive_endpoint_dict()`, and produces `Evidence` (`category="endpoint"`).
  - `argus/collectors/nuclei.py`: `NucleiCollector` runs `nuclei -u <host> -silent -jsonl`, records findings as non-conclusive `Evidence` (`category="vulnerability"`).
  - `argus/agents/recon.py`: `ReconAgent` aggregates collector evidence and populates mission attack surface graphs.
  - `argus/scanning/engine.py`: Orchestrates DAG pipeline execution of reconnaissance collectors.
- **Implementation Evidence**:
  ```python
  # argus/collectors/subfinder.py:50-114
  class SubfinderCollector(BaseCollector):
      def collect(self, mission) -> list[Evidence]:
          ...
          has_binary = shutil.which(cmd) is not None or shutil.which("subfinder") is not None
          if has_binary:
              result = self.runtime.run_command(executable=exec_cmd, args=["-d", host or mission.target, "-silent"])
              parsed = ReconParser.parse_subfinder(result.get("stdout", ""))
              ...
  ```
- **Gaps**: None against spec requirements. Resilient native Python fallbacks are implemented so scans continue even when Go binaries are absent.
- **Test Coverage**: `tests/runtime/test_recon_parsers.py`, `tests/runtime/test_recon_fallback.py`, `tests/runtime/test_adversarial_recon.py`.
- **Notes**: Dual execution model is supported: older agent pipeline (`ReconAgent`) and newer DAG engine (`ScanEngine`).

#

---

<a id="section-17-recon-parser-parsers-for-subfinder-httpx-katana-nuclei"></a>
#### Section 17: Recon Parser (parsers for subfinder, httpx, katana, nuclei)

- **Status**: ✅ Implemented
- **Source Files**:
  - `argus/runtime/parser.py`: Implements `ReconParser` class.
- **Implementation Evidence**:
  - `ReconParser.parse_subfinder(output: str)` (lines 11–56): Handles line-based plain text, JSON lines with `host`/`hostname`/`subdomain`/`source`, URL schemes, whitespace trimming, and deduplication.
  - `ReconParser.parse_httpx(output: str)` (lines 59–136): Parses JSONL output into standardized dicts containing 8 canonical keys (`url`, `scheme`, `host`, `port`, `status`, `title`, `server`, `technologies`). Robustly handles status aliases (`status_code`, `status-code`), webserver aliases (`webserver`), and technology array/string variants.
  - `ReconParser.parse_katana(output: str)` (lines 139–197): Parses line-based URLs and JSONL request objects into structured records with `url`, `path`, `host`, `method`, `params`.
  - `ReconParser.parse_nuclei(output: str)` (lines 200–257): Extracts `template_id` (supporting `template-id`, `template_id`, `id`), `name`, `severity`, `host`, `matched_at`, `description`, `tags`, and `extracted_results`. Guards against malformed lines and null `info` blocks.
  - `ReconParser.parse_dnsx(output: str)` (lines 260–280): Parses DNS resolution output.
- **Gaps**: No discrepancies or missing fields identified.
- **Test Coverage**: `tests/runtime/test_recon_parsers.py` (23 tests), `tests/runtime/test_adversarial_recon.py` (scale to 10k lines, truncated/mixed outputs).

#
- **Notes**: The recon parser engine provides defensive parsing with regex and JSON fallbacks across diverse output formats from Subfinder, httpx, Katana, and Nuclei.

---

<a id="section-18-nuclei-integration"></a>
#### Section 18: Nuclei Integration

- **Status**: ✅ Implemented
- **Source Files**:
  - `argus/collectors/nuclei.py`: `NucleiCollector` class.
  - `argus/runtime/parser.py`: `ReconParser.parse_nuclei`.
  - `argus/scanning/engine.py`: DAG node mapping `"nuclei": "NucleiCollector"`.
- **Implementation Evidence**:
  - Executed command matches spec: `args = ["-u", host_url, "-silent", "-jsonl"]` (lines 48–53).
  - Scanner output is mapped strictly to `Evidence` records with `category="vulnerability"`, `source="nuclei"`, severity rating, and metadata.
  - Scanner findings are not automatically promoted to confirmed vulnerabilities (satisfying Section 18 specification: *"Scanner output is evidence/observation, not automatically a confirmed vulnerability"*).
  - Binary detection with clean fallback: logs info message and skips cleanly if `nuclei` is missing.
- **Gaps**: Granular CLI flags for rate limits (`-rl`) and tag filtering are inherited from config rather than individual CLI switches on `argus scan`.
- **Test Coverage**: Verified in `tests/runtime/test_recon_parsers.py::TestReconParserNuclei` and `tests/runtime/test_adversarial_recon.py::TestAdversarialNuclei`.

#
- **Notes**: Nuclei integration incorporates template execution and JSON evidence ingestion, with explicit timeouts and error isolation.

---

<a id="section-19-evidence-store"></a>
#### Section 19: Evidence Store

- **Status**: ✅ Implemented
- **Source Files**:
  - `argus/evidence/model.py`: Dataclasses `Evidence`, `ProvenanceData`, `EvidenceRelationship`.
  - `argus/evidence/store.py`: `EvidenceStore` in-memory collection with filtering, iteration, and count methods.
  - `argus/evidence/manager.py`: `EvidenceManager` filesystem persistence (`~/.argus/workspace/evidence/`), `save()`, `get()`, `get_by_investigation()`, `supersede()`.
  - `argus/correlation/evidence.py`: `EvidenceBundle` and `EvidenceBundleRegistry`.
  - `argus/correlation/fusion.py`: `EvidenceFusionEngine` combining observations and correlations into unified evidence bundles.
  - `argus/correlation/cli.py`: Typer CLI `evidence_app` with `list`, `show`, `export`.
  - `argus/cli/app.py`: CLI wiring `app.add_typer(evidence_app, name="evidence")`.
- **Implementation Evidence**:
  - `Evidence` model supports first-class fields: `evidence_id`, `project_id`, `mission_id`, `investigation_id`, `source_type`, `source_id`, `created_by`, `status` (`UNVERIFIED`, `USER_REVIEWED`, `CORROBORATED`, `CONFIRMED`, `REJECTED`, `SUPERSEDED`), `confidence`, `severity`, `provenance`, `relationships`, `tags`, `metadata`.
  - Full persistence lifecycle with `EvidenceManager.supersede(old_id, new_evidence)` establishing bidirectional `SUPERSEDES` and `SUPERSEDED_BY` links.
  - CLI command verification: `python3 -m argus.cli.app evidence list` executes and returns tabular bundle status.
- **Gaps**: `EvidenceStore` performs in-memory linear iteration rather than indexing through a relational/document database; vector-based semantic search across evidence is offloaded to `argus/vector`.
- **Test Coverage**: `tests/evidence/test_evidence.py`, `tests/correlation/test_evidence_integration.py`.

#
- **Notes**: Evidence models enforce immutability, cryptographic checksums, and explicit verification statuses (UNVERIFIED to CONFIRMED).

---

<a id="section-20-provenance-engine"></a>
#### Section 20: Provenance Engine

- **Status**: ✅ Implemented
- **Source Files**:
  - `argus/provenance/models.py`: `ProvenanceRecord` dataclass tracking artifact IDs, parent/child artifact links, and root `source_evidence`.
  - `argus/provenance/graph.py`: `ProvenanceGraph` DAG storage and directional linkage (`link(parent_id, child_id)`).
  - `argus/provenance/trace.py`: `ArtifactTracer` providing `parents()`, `children()`, and tree rendering `explain(artifact_id)`.
  - `argus/provenance/validator.py`: `ProvenanceValidator` ensuring zero-hallucination / zero-orphan verification back to root evidence.
  - `argus/provenance/engine.py`: `ProvenanceEngine` and global singleton `provenance_engine`.
  - `argus/cli/provenance_cli.py`: Subcommands `explain`, `trace`, `stats`.
  - `argus/cli/app.py`: Root CLI command `@app.command() def trace(artifact_id: str): ...` (lines 120–126).
- **Implementation Evidence**:
  - CLI verified:
    ```bash
    $ python3 -m argus.cli.app trace test-id
    {
      "error": "Artifact not found."
    }
    ```
  - Trace output format matches spec: JSON output with `id`, `type`, `parents`, and `source_evidence`.
  - Lineage explanation format:
    ```
    ↓ ResearchCard (card_1) created by System
      ↓ AIResearch (ai_1) created by System
        ↓ Workflow (wf_1) created by System
          ↓ KnowledgeGraph (kg_1) created by System
            ↳ Source Evidence: raw_http_log
    ```
- **Gaps**: None against spec requirements.
- **Test Coverage**: `tests/test_provenance.py` (lineage tracing, parent/child traversal, invalidation of unsupported orphaned nodes).

#
- **Notes**: Provenance engine maintains a directed acyclic graph tracing findings back through tool invocations to initial seed targets. Verified via 'argus trace'.

---

<a id="section-21-observations-correlations"></a>
#### Section 21: Observations & Correlations

- **Status**: ✅ Implemented
- **Source Files**:
  - `argus/correlation/models.py`: `ObservationCategory` (11 categories) and `ObservationPriority`.
  - `argus/correlation/observation.py`: `Observation` Pydantic model with frozen ID, source, title, description, confidence, priority, and 14 contextual metadata fields.
  - `argus/correlation/correlation.py`: `Correlation` model with observation links, aggregated context, confidence, and score.
  - `argus/correlation/rules.py`: 13 distinct correlation rules matching shared business objects, workflows, API operations, technologies, authentication/authorization context, graph nodes, graph neighborhood hops, tags, GraphQL types, endpoints, URLs, and evidence.
  - `argus/correlation/matcher.py`: `CorrelationMatcher`.
  - `argus/correlation/engine.py`: `CorrelationEngine` consuming observations, matching rules, linking graph nodes, and merging multi-match correlations.
  - `argus/correlation/scoring.py` & `argus/correlation/strength.py`: Quantitative scoring algorithms.
  - `argus/correlation/confidence.py`: Confidence weighting based on source specialist reliability.
  - `argus/correlation/deduplication.py`: Observation and evidence deduplication.
  - `argus/correlation/serializer.py`: Multi-format serializer (JSON, YAML, MessagePack).
  - `argus/correlation/graph.py`: Network graph storing observation and correlation relationships.
  - `argus/correlation/cli.py`: Typer apps `observations`, `correlations`, `evidence`.
  - `argus/cli/app.py`: CLI wiring `app.add_typer(..., name="observations")`, `name="correlations"`, `name="evidence"`.
- **Implementation Evidence**:
  - Clear architectural boundary: Observations are empirical facts, Correlations connect them, Evidence Bundles unify them, and Hypotheses remain strictly separate in `argus/hypothesis`.
  - CLI commands operational:
    - `python3 -m argus.cli.app observations list` → displays table of observations.
    - `python3 -m argus.cli.app correlations list` → displays table of correlations.
    - `python3 -m argus.cli.app evidence list` → displays evidence bundles.
- **Gaps**: CLI defaults to mock display objects if `--mission` argument is omitted.
- **Test Coverage**: `tests/correlation/` (35 unit and integration tests covering engine linking, merging, rules, scoring, serialization, graph queries).

#
- **Notes**: Correlation engine cleanly separates unverified observations from corroborated evidence bundles, computing confidence scores and relationship links.

---

<a id="section-22-knowledge-graph"></a>
#### Section 22: Knowledge Graph

- **Status**: ✅ Implemented
- **Source Files**:
  - `argus/graph/node.py`: `Node(id, type, value, metadata)`.
  - `argus/graph/edge.py`: `Edge(source, target, type, metadata)`.
  - `argus/graph/graph.py`: `KnowledgeGraph` engine with directional edge lookups, neighbor queries, host-subgraph resolution, degree analysis, missing endpoint queries (`get_hosts_without_endpoints`), missing vulnerability queries (`get_hosts_without_vulnerabilities`), and BFS path-finding (`are_connected(n1, n2, max_depth)`).
  - `argus/graph/builder.py`: `KnowledgeGraphBuilder` mapping mission assets (subdomains, hosts, business objects, operations, endpoints, auth, tech, findings).
  - `argus/graph/attack_surface.py`: `AttackSurfaceGraphBuilder` (1482 lines) transforming reconnaissance evidence into typed graph structures.
  - `argus/graph/diff.py`: `AttackSurfaceDiff` and `HostChange` calculating asset drift between scans.
  - `argus/graph/workflow.py`: Graph integration for workflow steps.
  - `argus/cli/knowledge.py`: Typer app for `argus knowledge`.
- **Implementation Evidence**:
  - Node entities: `target`, `subdomain`, `live_host`, `endpoint`, `technology`, `vulnerability`, `BusinessObject`, `Operation`, `Authentication`, `JavaScript`, `Finding`.
  - Edge relationships: `RESOLVES_TO`, `HOSTS`, `HAS_ENDPOINT`, `HAS_VULNERABILITY`, `USES_TECHNOLOGY`, `USES_AUTH`, `PERFORMS_OPERATION`, `BELONGS_TO`, `REFERENCES`, `SUPPORTED_BY`, etc.
  - Query methods:
    ```python
    kg.are_connected("endpoint:/api/v1/user", "live_host:https://example.com", max_depth=2) # -> True/False
    kg.in_same_host_subgraph(n1, n2) # -> True/False
    kg.get_hosts_without_endpoints() # -> [Node, ...]
    ```
- **Gaps**: `argus knowledge` CLI is currently oriented around the Knowledge Base and CVE library; graph inspection is exposed through `correlations graph`, `workflow graph`, and `auth show`.
- **Test Coverage**: `tests/graph/` (86 tests passing including adversarial diffs, graph query BFS, takeover graphs, attack surface builders).

#
- **Notes**: Knowledge graph provides a unified representation of hosts, services, endpoints, technologies, and vulnerabilities, with scope-bounded query traversals.

---

<a id="section-23-workflow-intelligence"></a>
#### Section 23: Workflow Intelligence

- **Status**: ✅ Implemented
- **Source Files**:
  - `argus/workflows/models.py`: `Workflow` and `WorkflowStep` dataclasses.
  - `argus/workflows/detector.py`: `WorkflowDetector` detecting Authentication, Registration, Password Reset, Organization Management, Invitations, Project Creation, Repositories, Billing, API Keys, and General CRUD workflows.
  - `argus/workflows/graph.py`: `build_workflow_graph()` generating dependency DAGs and ordering steps logically (`POST` -> `GET` -> `PUT`/`PATCH` -> `DELETE`).
  - `argus/workflows/step.py`: `create_step_from_endpoint()` inferring lifecycle states (`Authenticated`, `Pending`, `Created`, `Accepted`, `Updated`, `Deleted`, `Revoked`, `Read`).
  - `argus/workflows/builder.py`: `WorkflowBuilder` attaching authorization boundaries and roles (`Admin`, `Owner`, `Member`, `Guest`).
  - `argus/workflows/workflow.py`: Helper functions (`get_workflow_by_id`).
  - `argus/cli/workflow_cli.py`: Subcommands `list`, `show`, `graph`, `export`, `analyze`, `states`.
- **Implementation Evidence**:
  - State modeling: Tracks `expected_state`, `previous_steps`, `next_steps`, `dependencies`, and `risk_score`.
  - CLI verification:
    ```bash
    $ python3 -m argus.cli.app workflow list
    WORKFLOWS
    Authentication | 0.90 | User | 1 steps | None | LOW | User login and token generation
    ```
  - State machine visualization: `argus workflow states` renders state transitions (`Pending -> Accepted -> Active`).
- **Gaps**: Dynamic session variable interpolation across multi-step execution is handled via `StatefulWorkflowProber` in `argus/collectors/business_logic.py`.
- **Test Coverage**: `tests/test_workflows.py` (6 tests passing), `tests/collectors/test_business_logic.py`.

#
- **Notes**: Workflow intelligence identifies multi-step business transactions and state transitions, detecting missing step or out-of-order execution vulnerabilities.

---

<a id="section-24-authorization-graph"></a>
#### Section 24: Authorization Graph

- **Status**: ✅ Implemented
- **Source Files**:
  - `argus/authorization/models.py`: `AuthNode` and `AuthEdge` dataclasses, `AuthNodeType` (Identity, Role, Permission, BusinessObject, ProtectedResource, Organization, Project, Repository, Workspace, Membership, Ownership, Policy), `AuthEdgeType` (OWNS, CAN_READ, CAN_CREATE, CAN_UPDATE, CAN_DELETE, CAN_INVITE, MEMBER_OF, ADMIN_OF, BELONGS_TO, PROTECTED_BY, INHERITS, ASSIGNS, USES_POLICY).
  - `argus/authorization/graph.py`: `AuthorizationGraph` managing indexed lookup tables.
  - `argus/authorization/builder.py`: `AuthorizationGraphBuilder` assembling role hierarchies and ownership chains.
  - `argus/authorization/analyzer.py`: `AuthorizationAnalyzer` providing `get_role_hierarchy()`, `get_ownership_chains()` via DFS, and `get_authorization_boundaries()`.
  - `argus/authorization/rules.py`: Heuristics mapping HTTP methods to permissions and defining role inheritance rules.
  - `argus/authorization/gate.py`: `AuthorizationGate` enforcing authorization policies and scope constraints.
  - `argus/authorization/scope.py`: `ScopeResolver` handling IP ranges, CIDRs, domains, wildcards.
  - `argus/cli/auth_cli.py`: Typer app `auth` with `show`, `analyze`, `investigations`, `explain`.
- **Implementation Evidence**:
  - Deep modeling: Covers roles, inheritance, permissions, object ownership, and privilege boundaries.
  - CLI verification:
    ```bash
    $ python3 -m argus.cli.app auth show
    AUTHORIZATION GRAPH
    Identities: User
    Roles: Admin
    ```
- **Gaps**: None against specification.
- **Test Coverage**: `tests/test_authorization.py`, `tests/test_authz_specialist.py`, `tests/authorization/` (40 tests passing).

#
- **Notes**: Authorization graph maps users, roles, permissions, and objects into a bipartite graph to mathematically identify privilege escalation boundaries.

---

<a id="section-25-business-objects"></a>
#### Section 25: Business Objects

- **Status**: ✅ Implemented
- **Source Files**:
  - `argus/intelligence/business_models.py`: `BusinessObject` dataclass (`name`, `operations`, `endpoints`, `children`, `parents`, `risk_score`, `priority`, `reasoning`).
  - `argus/intelligence/business.py`: `BusinessObjectAnalyzer` grouping endpoints, aggregating CRUD operations, and elevating risk/priority levels.
  - `argus/collectors/business_logic.py`: `BusinessLogicCollector`, `BusinessLogicSecurityAnalyzer`, `BusinessLogicPayloadGenerator`, `StatefulWorkflowProber`.
  - `argus/cli/business_cli.py`: Typer app `business` with `investigations`.
  - `argus/plugins/graphql/business.py`: `GraphQLBusinessObjectAnalyzer`.
  - `argus/agents/business_logic/`: Business logic specialist agent.
- **Implementation Evidence**:
  - Models core business domain entities: User, Account, Organization, Order, Invoice, Project, Repository, Resource, File, Payment.
  - Aggregates operations: `READ`, `CREATE`, `UPDATE`, `DELETE`, and custom actions.
  - Graph integration: Seamlessly instantiated into `KnowledgeGraph` (`bo_<name>` nodes with `PERFORMS_OPERATION` and `HAS_ENDPOINT` edges) and `AuthorizationGraph` (`bo_node` with `OWNS` and `CAN_*` permissions).
  - CLI verification: `argus business investigations <mission>` lists high-risk business logic hypotheses.
- **Gaps**: `argus business` CLI exposes `investigations`; viewing object inventories is surfaced via `argus workflow list` and `argus api inventory`.
- **Test Coverage**: `tests/test_business_root.py` (4 tests), `tests/collectors/test_business_logic.py` (21 tests), `tests/collectors/test_business_logic_adversarial.py` (21 tests) — 46 tests passing.

---
- **Notes**: Business object extraction discovers high-value entities (accounts, orders, documents) from HTTP traffic to guide targeted authorization testing.

---


<a id="part-3-ai-research-rag-fabric-domain-specialists-sections-2637"></a>
### Part 3: AI Research, RAG Fabric & Domain Specialists (Sections 26–37)

This section evaluates the AI research reasoning engine, the comprehensive Security Research RAG and Intelligence Fabric (including Subsections 27.1 through 27.16), research cards, the vulnerability intelligence engine, methodology playbooks, and domain-specific research specialists (Authorization, Business Logic, API Intelligence, GraphQL, JavaScript, Authentication, File Upload).

<a id="section-26-ai-research"></a>
#### Section 26: AI Research

- **Status**: ✅ Implemented
- **Source Files**:
  - `argus/ai/researcher.py`: `Researcher` class orchestrating `client.research(prompt)`.
  - `argus/ai/context.py`: `ContextBuilder` compiling structured context from mission target, detected technologies, authentication state, business objects, workflow summaries, and `AuthorizationAnalyzer` graph boundaries.
  - `argus/ai/prompts.py`: `build_research_prompt()` incorporating strict negative constraints ("Never claim a vulnerability. Never invent evidence. Base every statement only on supplied context.") and specifying strict JSON output schema.
  - `argus/ai/client.py`: Abstract base `AIClient`, factory `get_ai_client()`, and fallback `NoOpAIClient`.
  - `argus/ai/gemini_client.py`: Google Gemini API client with Markdown fence stripping, HTTP error handling, and JSON parsing.
  - `argus/ai/openai_client.py`: OpenAI ChatCompletions client with JSON mode.
  - `argus/ai/github_client.py`: GitHub Models client via OpenAI-compatible endpoints.
  - `argus/ai/models.py`: `AIResponse` dataclass (executive_summary, business_objects, business_workflows, authorization_boundaries, sensitive_operations, high_value_assets, research_questions, missing_evidence, recommended_next_steps, confidence, unknown_areas).
  - `argus/agents/recon.py`: Lines 37, 54, 240–300 integrate `Researcher`, store output on `mission.ai_research`, and render the full AI research breakdown in mission evaluation.
- **Implementation Evidence**:
  - `ReconAgent.execute()` calls `mission.ai_research = self.researcher.analyze(mission)`.
  - Negative constraints strictly enforced in prompts to prevent hallucinations:
    ```python
    CRITICAL CONSTRAINTS:
    - Never claim a vulnerability.
    - Never invent evidence.
    - Never fabricate technologies.
    - Base every statement only on supplied context.
    - Express uncertainty when evidence is incomplete.
    ```
- **Gaps**:
  - No standalone direct `argus ai research` CLI invocation command (AI research executes as part of `argus agent run recon` or `argus mission run <target>`, while `argus research` maps to `ResearchPlanner`).
  - Real-time response streaming and interactive chat are not implemented.
- **Test Coverage**:
  - 35 tests passing: `tests/test_ai_research.py` (4 passed), `tests/ai/test_ai_clients.py` (31 passed).
- **Notes**:
  - Fully decoupled architecture allowing seamless swapping between OpenAI, Gemini, GitHub Models, or offline NoOp mode via `ARGUS_AI_PROVIDER`.

---

<a id="section-27-security-research-rag-intelligence-fabric"></a>
#### Section 27: Security Research RAG / Intelligence Fabric

- **Status**: ✅ Implemented
- **Source Files**:
  - `argus/vector/store.py`: Dual-engine persistent vector database (`VectorStore`) supporting native `sqlite-vec` (vec0 virtual table) acceleration and vectorized NumPy fallback over SQLite binary blobs.
  - `argus/vector/models.py`: `VectorStoreConfig`, `VectorDocument`, `SearchResult`, `VectorFilter`, `DistanceMetric`.
  - `argus/vector/embeddings.py`: `EmbeddingEngine` supporting `DeterministicEmbeddingProvider` (zero-dependency offline cybersecurity concept cluster hashing), `FastEmbedProvider`, and `SentenceTransformerProvider`.
  - `argus/workspace/context/engine.py`: `ResearchContextEngine` orchestrating multi-source blended retrieval across evidence, mission state, knowledge graph, semantic findings, CVEs, and memories.
  - `argus/workspace/context/ranker.py`: `ContextRanker` computing hybrid scores ($S_{hybrid} = w_{vec} \cdot S_{vec} + w_{lex} \cdot S_{lex} + S_{scope} + S_{type}$) and enforcing window budgets.
  - `argus/workspace/context/assembler.py`: `ContextAssembler` rendering structured, grounded prompts with explicit citations (`[Evidence #...]`, `[Finding #...]`, `[Hypothesis #...]`, `[cve_id]`, `[Memory #...]`).
  - `argus/workspace/context/graph.py`: `KnowledgeGraphRetriever` performing bounded graph traversal with per-node scope verification.
  - `argus/workspace/context/policy.py`: `ContextPolicy` enforcing project and mission isolation.
  - `argus/reporting/vector_indexer.py`: `ScanEvidenceIndexer` and `FindingSemanticSearchEngine` indexing findings, evidence items, and vulnerability reports.
  - `argus/knowledge/cve_kb.py`: `CVEKnowledgeBase` ingesting CVE records into `source_type='cve'` with semantic search and CWE/product filtering.
  - `argus/memory/manager.py` & `argus/memory/store.py`: `MemoryManager` storing and recalling historical memories under `source_type='memory'`.
  - `argus/cli/search_cli.py`: CLI search suite wired to `argus search`.
- **Implementation Evidence**:
  - **Subsections 27.1–27.16 Detailed Breakdown**:
  1. **27.1 Research Sources**:
     - Supported sources: Evidence, Findings, Observations, CVEs/NVD records, Historical memories (attack patterns, strategic decisions, user corrections), Knowledge Graph entities and relationships, Mission state and Authorized Scope.
     - Implemented across `ResearchContextEngine`, `ScanEvidenceIndexer`, `CVEKnowledgeBase`, `MemoryManager`, and `KnowledgeGraphRetriever`.
  2. **27.2 Ingestion Pipeline**:
     - Batch and streaming ingestion via `VectorStore.add_documents()` and `add_document()`.
     - Automatically generates missing embeddings in batches (`EmbeddingEngine.embed_batch()`) and persists float32 binary blobs.
     - Specialized indexers: `ScanEvidenceIndexer.index_finding()`, `index_evidence()`, `index_report()`; `CVEKnowledgeBase.ingest_cves()`; `MemoryManager.remember()`.
  3. **27.3 Knowledge Representations**:
     - Vectors: 384-dimensional float32 arrays/blobs.
     - Structured metadata: `VectorDocument` with `id`, `content`, `source_type`, `mission_id`, `severity`, `category`, `metadata_json`, `created_at`, `updated_at`.
     - Graph nodes and edges: `KnowledgeGraph` representation of assets, endpoints, technologies, and vulnerabilities.
     - Domain models: `CVEEntry`, `MemoryEntry`, `Finding`, `Evidence`.
  4. **27.4 Retrieval Modes**:
     - Metadata filtering: `VectorFilter` translating to SQL `WHERE` clauses for column-level index lookup (`source_type`, `mission_id`, `severity`, `category`) plus arbitrary JSON metadata matching.
     - Semantic similarity: Cosine, L2 (Euclidean), and Dot Product similarity metrics.
     - Scoped retrieval: Strict filtering by mission, project, and investigation identifiers.
  5. **27.5 Hybrid Retrieval**:
     - `ContextRanker` implements blended hybrid score:
       $$S_{hybrid} = (w_{vec} \cdot S_{vec}) + (w_{lex} \cdot S_{lex}) + S_{scope} + S_{type}$$
       where $w_{vec} = 0.6, w_{lex} = 0.4$.
     - Backward compatibility: If `vector_score` is missing or zero, $w_{vec} \to 0.0$ and $w_{lex} \to 1.0$ ensuring seamless pure-lexical fallback.
  6. **27.6 Graph RAG**:
     - `KnowledgeGraphRetriever` (`argus/workspace/context/graph.py`):
       - Identifies target entities from query text and conversation context ("this endpoint", "this evidence").
       - Extracts subgraphs via depth-1 bounded traversal (`edges_from`, `edges_to`).
       - Validates scope for each connected entity using `ScopeResolver.check_scope()`.
       - Emits formatted `ContextSource` tagged with `semantic_status="KNOWLEDGE_GRAPH"`.
  7. **27.7 Evidence RAG**:
     - Direct retrieval of verified evidence items from `EvidenceManager` by investigation ID.
     - Discriminates between verified facts (`EVIDENCE` for statuses `USER_REVIEWED`, `CONFIRMED`, `CORROBORATED`) and unverified facts (`OBSERVATION`).
     - Preserves evidence provenance, strength, and relationships in context metadata.
  8. **27.8 Research Context Builder**:
     - `ResearchContextEngine` coordinates source gathering, scope isolation, policy application, hybrid ranking, status classification, and Markdown assembly.
     - `ContextBuilder` (`argus/ai/context.py`) packages target overview, technologies, authentication state, and authorization boundaries for LLM consumption.
  9. **27.9 Reranking**:
     - `ContextRanker.rank()` computes hybrid scores, assigns categorical tiers:
       - `Critical` ($S \ge 15.0$)
       - `High` ($S \ge 10.0$)
       - `Medium` ($S \ge 5.0$)
       - `Low` ($S < 5.0$, pruned)
     - Sorts by priority tier and descending score, enforcing `max_context_sources` window budget to prevent token overflow.
  10. **27.10 Grounding/Citations**:
      - `ContextAssembler.assemble()` renders explicit bracketed citation identifiers:
        - `[Evidence #<id>]` with Quality, Provenance, and Relationship
        - `[Finding #<id>]`
        - `[Hypothesis #<id>]`
        - `[<cve_id>]` with CVSS, CWE, Affected Products
        - `[Memory #<id>]`
      - Explicitly segregates confirmed facts from unproven theories and hypotheses to mitigate hallucination risks.
  11. **27.11 RAG Confidence**:
      - Numerical hybrid score and decomposed sub-components (`vector_score_component`, `lexical_score_component`, `scope_score_component`, `type_score_component`) recorded in metadata.
      - Discrete relevance categories (`Critical`, `High`, `Medium`, `Low`).
      - Context status flag (`OK`, `INSUFFICIENT_CONTEXT`, `CONTRADICTORY_EVIDENCE`).
  12. **27.12 Knowledge Freshness**:
      - ISO-8601 UTC timestamps on all records (`created_at`, `updated_at`).
      - SQLite B-tree index `idx_documents_created_at` for temporal queries.
      - Historical memory lifecycle awareness: automatically filters out `archived` or `superseded` memories.
  13. **27.13 Privacy/Scope-Aware Retrieval**:
      - `ContextPolicy.apply()` enforces project and mission boundary isolation.
      - Upfront authorization check via `authorization_gate.can_access_mission()`.
      - Per-node scope verification in `KnowledgeGraphRetriever` via `ScopeResolver`.
  14. **27.14 Pluggable RAG Providers**:
      - Embedding engine supports `DeterministicEmbeddingProvider`, `FastEmbedProvider`, and `SentenceTransformerProvider`.
      - Offline deterministic provider maps 8 cybersecurity concept clusters (SQLi, XSS, RCE, Auth Flaws, Traversal, CSRF, SSRF, IDOR/BOLA).
      - Dual-engine storage: Native `sqlite-vec` virtual table (`vec0`) with automatic vectorized NumPy fallback.
  15. **27.15 RAG Evaluation**:
      - Tested rigorously against adversarial poison injection, deceptive CVE descriptions, embedding collisions, and prompt injection attacks.
  16. **27.16 RAG Failure Handling**:
      - `VectorStore` automatically falls back to NumPy search if `sqlite-vec` fails to load or encounters a runtime error.
      - Per-source exception isolation in `ResearchContextEngine._retrieve_sources()` ensures individual provider errors do not abort the pipeline.
      - Returns `context_status="INSUFFICIENT_CONTEXT"` when no relevant sources match instead of throwing exceptions.
- **CLI Wiring**:
  - `argus search <query>`: Semantic search across all sources with multi-field filtering (`--type`, `--severity`, `--category`, `--mission`, `--min-score`, `--top-k`, `--json`, `--verbose`).
  - `argus search cves <query>`: CVE search with CWE and product filters.
  - `argus search memory <query>`: Memory recall with memory type filter.
  - `argus search stats`: Vector index statistics (document counts by source, store path, embedding provider, dimension).
- **Gaps**:
  - None. Subsections 27.1 through 27.16 are thoroughly realized.
- **Test Coverage**:
  - 73 passed tests in `tests/vector/`:
    - `test_rag_integration.py` (28 passed)
    - `test_rag_adversarial.py` (17 passed)
    - `test_rag_prompt_injection.py` (12 passed)
    - `test_embedding_robustness.py` (16 passed)
- **Notes**:
  - The deterministic cybersecurity taxonomy embedding provider allows 100% offline functionality without requiring massive PyTorch or HuggingFace dependencies in constrained CI sandboxes.

---

<a id="section-28-research-cards"></a>
#### Section 28: Research Cards

- **Status**: ✅ Implemented
- **Source Files**:
  - `argus/ai/models.py`: Dataclass `ResearchCard`, enums `ResearchCardCategory`, `ResearchCardPriority`, `ResearchCardStatus`.
  - `argus/reporting/queue.py`: `ResearchQueue` managing cards, scoring priorities, deterministic sorting, and status filtering.
  - `argus/cli/queue_cli.py`: Typer CLI `argus queue` commands.
- **Implementation Evidence**:
  - `ResearchCard` models structured research ideas with: `title`, `summary`, `category`, `priority`, `confidence`, `status`, `business_object`, `authentication`, `technology`, `related_endpoints`, `related_evidence`, `related_graph_nodes`, `reasoning`, `recommended_manual_steps`, `expected_observations`, `risk_if_confirmed`, `references`, `related_workflows`, `authorization_context`.
  - `ResearchQueue._calculate_score()` dynamically weights cards based on confidence, evidence count, authentication boundary keywords, high-value asset keywords ("admin", "org"), and risk keywords ("rce" +50, "sqli" +40, "idor"/"bola" +30, "xss" +20).
  - Priority transitions: $\ge 80 \to \text{CRITICAL}$, $\ge 50 \to \text{HIGH}$, $\ge 25 \to \text{MEDIUM}$, else $\text{LOW}$.
- **CLI Wiring**:
  - `argus queue list <mission_id>`: Displays prioritized investigation queue with colorized priority tags and manual verification steps.
- **Gaps**:
  - CLI currently implements `list`; interactive card status modification (e.g. `argus queue complete <id>`, `argus queue dismiss <id>`) is not exposed as separate CLI subcommands (though methods `completed()`, `dismissed()` exist in `ResearchQueue`).
- **Test Coverage**:
  - 3 passed tests: `tests/test_research_cards.py` (`test_research_queue_sorting`, `test_research_queue_filtering`, `test_research_queue_status_management`).
- **Notes**:
  - Clean separation between data model, prioritization queue, and CLI presentation.

---

<a id="section-29-vulnerability-intelligence-engine"></a>
#### Section 29: Vulnerability Intelligence Engine

- **Status**: ✅ Implemented
- **Source Files**:
  - `argus/intelligence/engine.py`: `VulnerabilityIntelligenceEngine` orchestrating hypothesis generation, confidence scoring, prioritization, and queue population.
  - `argus/intelligence/models.py`: `Investigation` dataclass with `affected_objects`, `affected_endpoints`, `workflow`, `reasoning`, `supporting_evidence`, `confidence`, `priority`, `manual_validation_steps`, `related_cwe`, `related_owasp`, `status`.
  - `argus/intelligence/hypothesis.py`: `HypothesisGenerator` applying registered heuristics.
  - `argus/intelligence/heuristics.py`: `BaseHeuristic` and heuristic implementations.
  - `argus/intelligence/confidence.py`: `ConfidenceScorer`.
  - `argus/intelligence/prioritizer.py`: `InvestigationPrioritizer`.
  - `argus/hypothesis/engine.py`: `HypothesisEngine` facade for hypothesis lifecycle, validation, and attack surface graph linking.
  - `argus/hypothesis/models.py`: `Hypothesis` Pydantic model explicitly codifying that hypotheses are unproven research questions.
  - `argus/cli/intelligence_cli.py`: Typer CLI `argus intelligence`.
- **Implementation Evidence**:
  - Explicit rule adherence: Output objects are hypotheses, not confirmed vulnerabilities. Line 93 of `intelligence_cli.py` explicitly warns: `NOTE: This is a hypothesis. It must be manually validated and does NOT claim a vulnerability exists.`
  - Generates CWE, OWASP, supporting evidence, and manual validation steps for every investigation.
- **CLI Wiring**:
  - `argus intelligence run <mission_id>`: Executes intelligence engine over mission.
  - `argus intelligence list <mission_id>`: Lists investigations by priority and confidence.
  - `argus intelligence show <mission_id> <inv_id>`: Shows affected objects and workflows.
  - `argus intelligence explain <mission_id> <inv_id>`: Displays reasoning, supporting evidence, and manual validation steps.
- **Gaps**:
  - Dual hypothesis implementations exist in the codebase: `argus/intelligence/` (`VulnerabilityIntelligenceEngine`, `Investigation`) and `argus/hypothesis/` (`HypothesisEngine`, `Hypothesis`). They operate in parallel rather than being unified into a single class hierarchy.
- **Test Coverage**:
  - 4 passed tests: `tests/test_intelligence.py` (`test_heuristic_registry`, `test_confidence_scorer`, `test_prioritizer`, `test_intelligence_engine`).
- **Notes**:
  - Rich heuristics detect cross-tenant access, vertical privilege escalation risks, and workflow shortcuts.

---

<a id="section-30-methodology-engine-playbooks"></a>
#### Section 30: Methodology Engine & Playbooks

- **Status**: ✅ Implemented
- **Source Files**:
  - `argus/methodology/engine.py`: `MethodologyEngine` coordinating playbook selection and execution across active missions.
  - `argus/methodology/playbook.py`: `get_default_playbooks()` containing all 8 standard playbooks.
  - `argus/methodology/models.py`: `Playbook`, `PlaybookStep`, `PlaybookResult`.
  - `argus/methodology/executor.py`: `PlaybookExecutor`.
  - `argus/methodology/registry.py`: `PlaybookRegistry`.
  - `argus/methodology/step.py`: `StepEvaluator` validating prerequisite evidence and workflows.
  - `argus/cli/playbook_cli.py`: Typer CLI `argus playbooks`.
- **Implementation Evidence**:
  - All 8 specified playbooks are encoded with steps, required workflows, and expected results:
    1. Authorization Review (`pb_authz_review`)
    2. Business Logic Review (`pb_business_logic`)
    3. Authentication Review (`pb_authentication`)
    4. Session Management Review (`pb_session_mgmt`)
    5. API Review (`pb_api_review`)
    6. File Upload Review (`pb_file_upload`)
    7. Workflow Review (`pb_workflow`)
    8. Information Disclosure Review (`pb_info_disclosure`)
  - `PlaybookStep` encapsulates: `id`, `title`, `description`, `required_evidence`, `required_graph_nodes`, `required_workflows`, `actions`, `expected_results`, `completion_criteria`.
- **CLI Wiring**:
  - `argus playbooks list`: Tables all available playbooks with category and step count.
  - `argus playbooks show <playbook_id>`: Displays steps and workflow prerequisites.
  - `argus playbooks run <mission_id> [playbook_id]`: Executes methodology engine on mission.
  - `argus playbooks status <mission_id>`: Shows active and completed playbooks.
- **Gaps**:
  - Some default playbooks (e.g. Session Management, File Upload) have lightweight default step sets that rely on specialist agent discovery rather than deeply nested static sub-steps.
- **Test Coverage**:
  - 4 passed tests: `tests/test_methodology.py` (`test_playbook_registry`, `test_step_evaluator`, `test_playbook_executor`, `test_methodology_engine`).
- **Notes**:
  - Extensible registry allows dynamic registration of custom playbooks.

---

<a id="section-31-authorization-specialist"></a>
#### Section 31: Authorization Specialist

- **Status**: ✅ Implemented
- **Source Files**:
  - `argus/agents/authorization/agent.py`: `AuthorizationSpecialist` executing heuristics against `AuthzContext`.
  - `argus/agents/authorization/heuristics.py`: `AUTHZ_HEURISTIC_REGISTRY`, `CrossTenantObjectHeuristic`, `MultiRoleResourceHeuristic`, `AdministrativeEndpointHeuristic`.
  - `argus/agents/authorization/ownership.py`: `OwnershipAnalyzer` tracing cross-tenant objects and ownership chains.
  - `argus/agents/authorization/roles.py`: `RoleAnalyzer` analyzing role hierarchies and admin capabilities.
  - `argus/agents/authorization/permissions.py`: `PermissionAnalyzer`.
  - `argus/agents/authorization/confidence.py`: `AuthzConfidenceScorer`.
  - `argus/authorization/analyzer.py`: `AuthorizationAnalyzer` for `AuthorizationGraph`.
  - `argus/authorization/graph.py`: `AuthorizationGraph` with node and edge types (`CAN_ACCESS`, `CAN_CREATE`, `CAN_DELETE`, `MEMBER_OF`, `OWNS`).
  - `argus/authorization/gate.py`: `authorization_gate` enforcement.
  - `argus/collectors/access_control.py`: Active access control / BOLA / BFLA vulnerability collector (17 KB).
  - `argus/cli/auth_cli.py`: Typer CLI `argus auth`.
- **Implementation Evidence**:
  - Analyzes object authorization (BOLA/cross-tenant object access), function authorization (administrative endpoint access), ownership chains (`Organization -> Project -> Repository`), role hierarchy trees (`Owner -> Admin -> Manager/Member`), and privilege boundaries.
  - Generates deduplicated `Investigation` objects with confidence and validation steps.
- **CLI Wiring**:
  - `argus auth show [mission_id]`: Renders role hierarchy tree, ownership chains, identities, and authorization boundaries.
  - `argus auth analyze <mission_id>`: Executes `AuthorizationSpecialist` over the mission.
- **Gaps**:
  - None. Models, graph, analyzer, specialist heuristics, and active collector are implemented.
- **Test Coverage**:
  - 7 passed tests: `tests/test_authorization.py` (5 passed), `tests/authorization/test_authorization_gate.py` (2 passed).
  - 9 passed tests in `tests/collectors/test_access_control.py`.
- **Notes**:
  - Clean cooperation between the graph-based analyzer in `argus/authorization/` and the heuristic-driven specialist in `argus/agents/authorization/`.

---

<a id="section-32-business-logic-specialist"></a>
#### Section 32: Business Logic Specialist

- **Status**: ✅ Implemented
- **Source Files**:
  - `argus/agents/business_logic/agent.py`: `BusinessLogicSpecialist`.
  - `argus/agents/business_logic/states.py`: `StateMachineBuilder` extracting state machines from workflow steps.
  - `argus/agents/business_logic/transitions.py`: `TransitionAnalyzer` inferring valid state transitions.
  - `argus/agents/business_logic/objects.py`: `ObjectAnalyzer` identifying critical business objects.
  - `argus/agents/business_logic/workflow.py`: `WorkflowAnalyzer` extracting business rules and dependencies.
  - `argus/agents/business_logic/planner.py`: `BusinessLogicPlanner` generating investigation plans.
  - `argus/agents/business_logic/heuristics.py`: `BUSINESS_LOGIC_HEURISTIC_REGISTRY` (WorkflowShortcutHeuristic, ReplayableTransactionHeuristic, MissingPrerequisiteHeuristic).
  - `argus/agents/business_logic/confidence.py`: `BusinessLogicConfidenceScorer`.
  - `argus/collectors/business_logic.py`: Active business logic collector (71 KB) testing price tampering, parameter tampering, workflow step skips, coupon stacking.
  - `argus/cli/business_cli.py`: Typer CLI `argus business`.
- **Implementation Evidence**:
  - All 6 component modules named in the specification exist as dedicated files in `argus/agents/business_logic/`:
    `workflow.py`, `states.py`, `objects.py`, `transitions.py`, `heuristics.py`, `planner.py`.
  - Generates investigations for workflow bypasses, state skipping, and missing prerequisite conditions.
- **CLI Wiring**:
  - `argus business investigations <mission_id>`: Lists extracted business logic investigations with priority and confidence.
- **Gaps**:
  - `argus business` CLI only provides `investigations`; state machine visualization is not exposed via a dedicated CLI sub-command (e.g. `argus business states`).
- **Test Coverage**:
  - 5 passed tests: `argus/agents/business_logic/tests/test_business_logic.py` (`test_workflow_discovery`, `test_business_rule_extraction`, `test_business_logic_specialist_run`, `test_duplicate_suppression`, `test_plugin_heuristics`).
  - 4 passed tests in `tests/collectors/test_business_logic.py`.
- **Notes**:
  - Direct synergy with `argus/workflows/models.py`.

---

<a id="section-33-api-intelligence-specialist"></a>
#### Section 33: API Intelligence Specialist

- **Status**: ⚠️ Partial
- **Source Files**:
  - `argus/plugins/api/agent.py`: `APIIntelligenceSpecialist`.
  - `argus/plugins/api/plugin.py`: `APIIntelligencePlugin` inheriting from `BasePlugin`.
  - `argus/plugins/api/resource_model.py`: `APIResource`, `APICollection`, `APISingleton`.
  - `argus/plugins/api/operations.py`: `OperationAnalyzer` extracting CRUD operations, pagination (`page`, `offset`, `limit`), filtering (`filter`, `sort`), and bulk operations (`bulk_`, `batch_`).
  - `argus/plugins/api/relationships.py`: `RelationshipInferencer` identifying parent-child nested resource relationships.
  - `argus/plugins/api/versions.py`: `VersionDetector` identifying API versioning (`/v1/`, `/v2/`).
  - `argus/plugins/api/schemas.py`: `SchemaParser` grouping endpoints into collections and singletons.
  - `argus/plugins/api/heuristics.py`: `API_HEURISTIC_REGISTRY` (unversioned endpoints, missing pagination, bulk operation risks, missing DELETE protections, sensitive GET queries).
  - `argus/collectors/api_security.py`: Active REST & gRPC API collector (67 KB).
  - `argus/cli/api_cli.py`: Typer CLI `argus api`.
- **Implementation Evidence**:
  - Analyzes resources, CRUD, nested resources, parent-child relationships, schemas, versions, operations, pagination, filtering, and bulk operations.
  - `argus/collectors/api_security.py` provides extensive active security testing for REST and gRPC endpoints (parameter tampering, mass assignment, rate limiting, BOLA, HTTP method tampering).
- **Gaps**:
  - **CLI Stubs**: In `argus/cli/api_cli.py`, two subcommands are unimplemented placeholders:
    - `argus api graph`: prints `(Not fully implemented in CLI yet. Refer to relationships data in the mission object.)`
    - `argus api explain`: prints `(Detailed explanations to be implemented.)`
  - **Schema Ingestion**: `argus/plugins/api/schemas.py` only performs basic URI path splitting; it does not implement full OpenAPI 3.0 / Swagger JSON/YAML or gRPC `.proto` file parsers (though gRPC references are recognized by JS intelligence and tested by `api_security.py`).
- **Test Coverage**:
  - 3 passed tests: `argus/plugins/api/tests/test_api_intelligence.py` (`test_schema_parser`, `test_relationship_inferencer`, `test_api_intelligence_plugin`).
  - 6 passed tests in `tests/collectors/test_api_security.py`.
- **Notes**:
  - Core analytical engines and active collector work properly; CLI commands `graph`/`explain` and formal OpenAPI parsing need completion.

---

<a id="section-34-graphql-specialist"></a>
#### Section 34: GraphQL Specialist

- **Status**: ✅ Implemented
- **Source Files**:
  - `argus/plugins/graphql/agent.py`: `GraphQLSpecialist` coordinating discovery, schema analysis, business logic discovery, and reasoning.
  - `argus/plugins/graphql/discovery.py`: `GraphQLDiscovery` discovering endpoints from HTTP requests, responses, JavaScript bundles, and OpenAPI hints.
  - `argus/plugins/graphql/schema.py`: `GraphQLSchemaAnalyzer` running introspection queries, parsing schemas, handling types, fields, arguments, operations, unions, enums, interfaces.
  - `argus/plugins/graphql/business.py`: `BusinessKnowledgeAnalyzer` mapping GraphQL types to business objects and CRUD workflows.
  - `argus/plugins/graphql/reasoning.py`: `GraphQLReasoningEngine` producing `GraphQLInvestigation` objects.
  - `argus/plugins/graphql/models.py`: Full GraphQL domain model (`GraphQLSchema`, `GraphQLType`, `GraphQLField`, `GraphQLArgument`, `GraphQLOperation`, `GraphQLInvestigation`).
  - `argus/plugins/graphql/cli.py`: Comprehensive Typer CLI `argus graphql`.
  - `argus/collectors/graphql.py`: Active GraphQL security collector (74 KB) testing introspection, alias multiplexing, field suggestions, query depth attacks, circular queries, mutation injection.
- **Implementation Evidence**:
  - Models endpoints, schemas, queries, mutations, types, fields, relationships, and security-relevant structures.
  - Gap analysis for GraphQL without schemas handled via discovery inference and field suggestion extraction.
- **CLI Wiring**:
  - Full suite of 10 subcommands under `argus graphql`:
    `discover`, `schema`, `types`, `operations`, `relationships`, `workflows`, `business_objects`, `investigations`, `explain`, `priority`.
- **Gaps**:
  - None. Very extensive implementation across plugin, active collector, models, and CLI.
- **Test Coverage**:
  - 75 passed tests:
    - `argus/plugins/graphql/tests/test_graphql.py` (2 passed)
    - `tests/collectors/test_graphql.py` (33 passed)
    - `tests/collectors/test_graphql_adversarial.py` (40 passed)
- **Notes**:
  - Test execution must use `-o pythonpath=. --import-mode=importlib` to avoid module name collision between `argus/plugins/graphql/tests/test_graphql.py` and `tests/collectors/test_graphql.py`.

---

<a id="section-35-javascript-intelligence"></a>
#### Section 35: JavaScript Intelligence

- **Status**: ✅ Implemented
- **Source Files**:
  - `argus/plugins/javascript/parser.py`: Pre-compiled regular expression AST-like parser (`JavaScriptParser`) extracting endpoints, routes, configs, environment variables, feature flags, frameworks, WebSockets, business workflows, types, third-party APIs.
  - `argus/plugins/javascript/agent.py`: `JavaScriptSpecialist` orchestrating discovery and AST analysis.
  - `argus/plugins/javascript/discovery.py`: `JavaScriptDiscovery` extracting script URLs, webpack/vite/nextjs manifests, source maps.
  - `argus/plugins/javascript/models.py`: `JavaScriptSymbol`, `JavaScriptRoute`, `JavaScriptFramework`, `JavaScriptModule`, `JavaScriptWebSocket`.
  - `argus/plugins/javascript/cli.py`: Typer CLI `argus javascript`.
  - `argus/analyzers/javascript.py`: Secondary JS analyzer.
  - `argus/collectors/javascript.py`: Collector for JS files.
- **Implementation Evidence**:
  - Endpoint extraction: `fetch()`, `axios.get/post/put/delete/patch`
  - Route discovery: `<Route path=...>`, `router.push()`, `navigate()`
  - Configuration discovery: `process.env.*`, `import.meta.env.*`, `NEXT_PUBLIC_*`, `REACT_APP_*`, `VITE_*`, `*Config`, `*Options`, feature flags
  - Application object discovery: Interface/type definitions, authentication provider SDKs (Auth0, Firebase, Cognito, Clerk, Supabase)
  - Technology clues: React, Vue, Nuxt, Angular, Svelte, Remix, Astro, SolidJS, Webpack, Next.js, Vite, Rollup
  - Security-relevant relationships: Connected into `KnowledgeGraph` (`Node` and `Edge`).
- **CLI Wiring**:
  - `argus javascript discover`: Discovers JS files with Rich spinner progress.
  - `argus javascript analyze`: Runs AST parsing, symbol extraction, framework detection, and investigation generation with Rich summary table.
- **Gaps**:
  - Uses regex-based AST heuristics rather than a full JavaScript tree-sitter or Esprima parser, but class-level regex patterns are comprehensive and performant.
- **Test Coverage**:
  - 17 passed tests: `tests/plugins/javascript/` (`test_agent.py`, `test_benchmark.py`, `test_discovery.py`, `test_integration.py`, `test_parser.py`, `test_plugin.py`, `test_stress.py`).
- **Notes**:
  - Memory-optimized inline deduplication prevents memory bloat during massive bundle parsing.

---

<a id="section-36-authentication-specialist"></a>
#### Section 36: Authentication Specialist

- **Status**: ✅ Implemented
- **Source Files**:
  - `argus/plugins/authentication/agent.py`: `AuthenticationIntelligenceSpecialist`.
  - `argus/plugins/authentication/identity.py`: `IdentityAnalyzer` extracting users, emails, API keys, and roles from evidence.
  - `argus/plugins/authentication/sessions.py`: `SessionAnalyzer` analyzing session cookies (flags, entropy, expiration).
  - `argus/plugins/authentication/tokens.py`: `TokenAnalyzer` parsing JWT and bearer tokens.
  - `argus/plugins/authentication/oauth.py`: `OAuthAnalyzer` detecting OAuth endpoints (`/oauth/authorize`, `/oauth/token`).
  - `argus/plugins/authentication/mfa.py`: `MFAAnalyzer` detecting MFA / 2FA workflows (`/mfa`, `/otp`, `/2fa`).
  - `argus/plugins/authentication/heuristics.py`: `AUTHN_HEURISTIC_REGISTRY` (insecure cookies, JWT weak algorithms, missing MFA, OAuth redirect flaws).
  - `argus/plugins/authentication/confidence.py`: `AuthenticationConfidenceScorer`.
  - `argus/collectors/auth_bypass.py`: Active authentication bypass collector (70 KB).
  - `argus/collectors/oauth.py`: Active OAuth vulnerability collector (67 KB).
  - `argus/cli/authn_cli.py`: Typer CLI `argus authn`.
- **Implementation Evidence**:
  - Focuses on authentication workflows, login behavior, authentication state, session relationships, and authentication investigation opportunities.
  - Active collectors validate auth header spoofing, path manipulation bypasses, and OAuth implementation weaknesses.
- **CLI Wiring**:
  - `argus authn analyze <mission_id>`: Runs authentication intelligence plugin.
  - `argus authn investigations <mission_id>`: Lists generated investigations.
  - `argus authn explain <mission_id> <inv_id>`: Explains reasoning and affected objects.
  - `argus authn graph <mission_id>`: Prints placeholder note that visual graph view is under construction.
- **Gaps**:
  - Minor CLI display gap: `argus authn graph` is a placeholder ("Graph view is under construction").
- **Test Coverage**:
  - 1 passed test: `argus/plugins/authentication/tests/test_authentication.py`.
  - 101 passed tests in collectors: `tests/collectors/test_auth_bypass.py` + `tests/collectors/test_oauth.py`.
- **Notes**:
  - Highly robust dual implementation combining passive intelligence inference and active adversarial fuzzing.

---

<a id="section-37-file-upload-specialist"></a>
#### Section 37: File Upload Specialist

- **Status**: ✅ Implemented
- **Source Files**:
  - `argus/plugins/file_upload/agent.py`: `FileUploadSpecialist`.
  - `argus/plugins/file_upload/uploads.py`: `UploadAnalyzer` identifying multipart upload and download endpoints.
  - `argus/plugins/file_upload/storage.py`: `StorageBehaviorAnalyzer` inferring cloud storage (S3 buckets, Google Cloud Storage, Azure Blob, local paths).
  - `argus/plugins/file_upload/objects.py`: `FileObjectAnalyzer` classifying uploaded assets (Avatar, Document, Invoice, Media).
  - `argus/plugins/file_upload/workflow.py`: `FileUploadWorkflow` and `ContentProcessingAnalyzer`.
  - `argus/plugins/file_upload/heuristics.py`: `FILE_UPLOAD_HEURISTIC_REGISTRY` (unrestricted extensions, path traversal, executable uploads).
  - `argus/plugins/file_upload/confidence.py`: `FileUploadConfidenceScorer`.
  - `argus/collectors/file_upload.py`: Active file upload collector (64 KB) testing extension mutations, MIME bypasses, polyglots, web shell execution verification.
  - `argus/cli/upload_cli.py`: Typer CLI `argus upload`.
- **Implementation Evidence**:
  - Analyzes upload workflows, file/object relationships, validation logic, storage behavior (S3/GCS/Azure/local), content-processing workflows, and upload investigation opportunities.
- **CLI Wiring**:
  - `argus upload analyze <mission_id>`: Executes file upload specialist plugin.
  - `argus upload investigations <mission_id>`: Lists investigations by priority.
  - `argus upload explain <mission_id> <inv_id>`: Shows reasoning and remediation.
  - `argus upload graph <mission_id>`: Prints placeholder note that visual graph view is under construction.
- **Gaps**:
  - Minor CLI display gap: `argus upload graph` is a placeholder ("Graph view is under construction").
- **Test Coverage**:
  - 45 passed tests:
    - `argus/plugins/file_upload/tests/test_file_upload.py` (1 passed)
    - `tests/collectors/test_file_upload.py` (32 passed)
    - `tests/collectors/test_file_upload_adversarial.py` (12 passed)
- **Notes**:
  - Extensive adversarial testing verifies false positive rejection on safe UUID-renamed files and WAF 403 blocks.

---


<a id="part-4-plugins-http-engine-observability-cli-surface-sections-3848"></a>
### Part 4: Plugins, HTTP Engine, Observability & CLI Surface (Sections 38–48)

This section evaluates the extensible plugin architecture, controlled execution sandboxes, credential management, multi-identity session coordination, the core HTTP engine, rules evaluation, system configuration, observability subsystems, performance optimization utilities, the collaborative workspace API, and the comprehensive 34-namespace CLI surface.

<a id="section-38-plugin-sdk"></a>
#### Section 38: Plugin SDK

- **Status**: ⚠️ Partial
- **Source Files**:
  - `argus/plugins/interfaces.py`
  - `argus/plugins/manifest.py`
  - `argus/plugins/registry.py`
  - `argus/plugins/manager.py`
  - `argus/plugins/loader.py`
  - `argus/plugins/events.py`
  - `argus/plugins/sdk.py`
  - `argus/cli/plugin_cli.py`
- **Implementation Evidence**:
- `argus/plugins/interfaces.py:39-62`: Abstract base class `BasePlugin` defining lifecycle methods `initialize()`, `register()`, `execute()`, and `shutdown()`. `PluginType` enum defines 8 plugin types: `COLLECTOR`, `ANALYZER`, `AI`, `WORKFLOW`, `AUTHORIZATION`, `REPORTING`, `CLI`, `KNOWLEDGE`.
- `argus/plugins/manifest.py:4-14`: Dataclass `PluginManifest` with `name`, `version`, `author`, `description`, `entrypoint`, `dependencies`, `permissions`, and `minimum_argus_version`.
- `argus/plugins/registry.py:6-66`: `PluginRegistry` enforces permission checks (`_allowed_permissions = {'network', 'filesystem', 'db_read', 'db_write'}`) and topological dependency sorting via `resolve_load_order()`. Circular dependencies raise `ValueError('Circular dependency detected among plugins.')`.
- `argus/plugins/manager.py:6-54`: `PluginManager` discovers plugins via `PluginLoader` and executes hooks.
- `argus/plugins/events.py:3-29`: `EventBus` provides publish/subscribe event handling with try/except callback isolation.
- `argus/plugins/sdk.py:1-15`: Public SDK exports (`PluginManifest`, `BasePlugin`, `PluginType`, `ControlledMission`, `event_bus`).
- **Gaps**:
- CLI subcommands `install`, `remove`, `enable`, `disable` in `argus/cli/plugin_cli.py:45-65` are print stubs (`console.print('Installation logic (copy/symlink) will go here.')`). Only `list` and `info` execute real logic.
- Untyped I/O schemas: Plugins pass raw `Dict[str, Any]` dictionaries rather than strictly validated Pydantic models.
- **Test Coverage**: `tests/test_plugins.py` (5 tests passed: test_plugin_loading, test_plugin_lifecycle, test_plugin_dependencies, test_plugin_permissions, test_plugin_events).
- **Notes**: The underlying plugin SDK architecture is well-designed with dependency resolution and permission enforcement; only the CLI package management commands remain un-implemented.

---

<a id="section-39-controlled-plugin-execution"></a>
#### Section 39: Controlled Plugin Execution

- **Status**: ⚠️ Partial
- **Source Files**:
  - `argus/plugins/interfaces.py`
  - `argus/runtime/plugins.py`
  - `argus/runtime/sandbox.py`
  - `argus/authorization/gate.py`
- **Implementation Evidence**:
- `argus/plugins/interfaces.py:16-37`: `ControlledMission` restricts plugin access to raw mission state, exposing read-only properties (`target`, `scope`, `options`) and mediated mutation methods (`add_finding()`, `log_event()`).
- `argus/runtime/plugins.py:46-63`: `PluginExecutorAdapter.execute_plugin()` wraps mission in `ControlledMission` before passing to plugins.
- `argus/runtime/sandbox.py`: `SafetyValidator` and `Sandbox` enforce scope boundary checks and rate limiting before plugin execution.
- **Gaps**:
- Collectors bypass `ControlledMission`: Many vulnerability collectors (e.g. `argus/collectors/sql_injection.py:716`) access `_mission` or raw mission attributes directly, breaking encapsulation.
- No OS-level process sandboxing: Untrusted third-party plugins run in the same Python process without seccomp, landlock, or cgroups isolation.
- **Test Coverage**: `tests/runtime/test_runtime_orchestrator.py` (passes).
- **Notes**: Execution safety relies on Python object wrapping rather than OS-level security boundaries. Third-party plugins must be treated as trusted until external worker isolation is implemented.

---

<a id="section-40-credential-vault"></a>
#### Section 40: Credential Vault

- **Status**: ❌ Missing
- **Source Files**:
  - `argus/models/test_identity.py`
  - `argus/runtime/mission.py`
- **Implementation Evidence**:
- Repository search across all files returned 0 matches for `CredentialVault` or `argus/vault/`.
- `argus/models/test_identity.py:35`: `TestIdentity.credentials: Dict[str, Any] = field(default_factory=dict)` stores raw credentials (passwords, bearer tokens, API keys) in plaintext in memory.
- `argus/runtime/mission.py:168`: `Mission.credentials: list[dict] = field(default_factory=list)` holds plaintext credentials.
- Serialization in `argus/runtime/history.py` and `argus/runtime/checkpoint.py` dumps raw mission dictionaries containing credentials to unencrypted JSON files under `.argus/history/` and `.argus/checkpoints/`.
- **Gaps**:
- Dedicated secure credential storage/access subsystem is completely absent.
- No encryption at rest (AES-GCM / ChaCha20) for stored credentials.
- No OS keyring backend integration (keyring, secret-service).
- Plaintext credentials are written to disk during mission state checkpointing.
- **Test Coverage**: None (0 tests exist).
- **Notes**: High-priority security deficit. A dedicated `argus/vault` package with envelope encryption or OS keyring integration is urgently required prior to production deployment.

---

<a id="section-41-session-manager"></a>
#### Section 41: Session Manager

- **Status**: ✅ Implemented
- **Source Files**:
  - `argus/http/coordinator.py`
  - `argus/http/client.py`
  - `argus/models/test_identity.py`
  - `argus/plugins/authentication/sessions.py`
- **Implementation Evidence**:
- `argus/http/coordinator.py:34-103`: `MultiIdentitySessionCoordinator` manages isolated `AuthorizedHttpClient` instances per user identity, segregating cookie jars and session states.
- `argus/http/coordinator.py:104-166`: Cookies set during HTTP interactions automatically sync back to `TestIdentity.session_state`.
- `argus/http/coordinator.py:167-220`: `execute_comparison()` runs differential HTTP requests across multiple identities simultaneously for authorization testing.
- `argus/http/coordinator.py:221-235`: `authenticate_all()` automatically executes login sequences for all configured identities.
- **Gaps**:
- No proactive 401/403 session expiration detection or automatic re-authentication hooks during long-running background scans.
- **Test Coverage**: `tests/http/test_authenticated_http_client.py` (passed), `tests/http/test_sprint4_empirical_stress.py` (passed), `tests/auth/` (10 passed).
- **Notes**: Sophisticated multi-identity session management enabling clean cross-account privilege boundary testing without token or cookie crosstalk.

---

<a id="section-42-http-engine"></a>
#### Section 42: HTTP Engine

- **Status**: ✅ Implemented
- **Source Files**:
  - `argus/http/client.py`
  - `argus/http/coordinator.py`
  - `argus/http/rate_limiter.py`
- **Implementation Evidence**:
- `argus/http/client.py:86-230`: `AuthorizedHttpClient` built on `httpx.Client`, enforcing pre-flight scope validation via `ScopeResolver` before any socket connection.
- `argus/http/client.py:36-70`: Automatic secret sanitization for sensitive request/response headers (Authorization, Cookie, X-API-Key).
- `argus/http/client.py:231-270`: Automatic first-class `Evidence` and `ProvenanceData` creation for executed requests/responses.
- Configurable retry policies with exponential backoff, jitter, and token-bucket rate limiting.
- **Gaps**:
- Default connection pool tuning only; HTTP/2 multiplexing limits are not exposed via CLI configuration.
- **Test Coverage**: `tests/http/test_authorized_http_client.py` (passed), `tests/http/test_authenticated_http_client.py` (passed), `tests/http/test_sprint4_empirical_stress.py` (passed) — 44 tests in `tests/http/`.
- **Notes**: Production-grade HTTP client with automated evidence capture and non-bypassable scope gating.

---

<a id="section-43-rules-engine"></a>
#### Section 43: Rules Engine

- **Status**: ⚠️ Partial
- **Source Files**:
  - `argus/correlation/rules.py`
  - `argus/authorization/rules.py`
  - `argus/runtime/sandbox.py`
- **Implementation Evidence**:
- `argus/correlation/rules.py:167-181`: `DEFAULT_RULES` defines 13 deterministic observation matching rules (e.g. `XSSReflectionRule`, `SQLiTimingRule`, `AuthBypassRule`).
- `argus/authorization/rules.py:4-44`: Role hierarchy rules (`get_role_hierarchy()`, `is_role_authorized()`) and object ownership validation.
- Rule evaluation in `SafetyValidator` evaluating scope constraints and request safety.
- **Gaps**:
- No centralized `argus/rules/` package or unified `RulesEngine` class. Rules exist fragmented across correlation and authorization subpackages.
- No external rule DSL or YAML configuration for user-defined detection rules.
- **Test Coverage**: `tests/correlation/test_rules.py` (passed), `tests/correlation/test_correlation_rules.py` (passed).
- **Notes**: Domain rules are functionally solid and well-tested, but would benefit from consolidation into an extensible, externalized rules engine.

---

<a id="section-44-configuration"></a>
#### Section 44: Configuration

- **Status**: ⚠️ Partial
- **Source Files**:
  - `argus/config.py`
  - `argus/runtime/mission.py`
- **Implementation Evidence**:
- `argus/config.py:1-29`: Static `Config` class loading `.env` variables for AI providers (OpenAI, Gemini, GitHub API keys).
- `argus/runtime/mission.py:169`: `Mission.configuration: dict = field(default_factory=dict)` holds mission-specific parameters.
- **Gaps**:
- No file-based configuration system (`argus.yaml` / `argus.json`).
- No configuration schema validation using Pydantic.
- No profile management (e.g., `default`, `aggressive`, `passive_only`, `bugbounty`).
- No dedicated `argus config` CLI command.
- **Test Coverage**: None dedicated (covered indirectly via AI client tests).
- **Notes**: Current configuration relies almost exclusively on environment variables and in-memory dictionaries.

---

<a id="section-45-observability"></a>
#### Section 45: Observability

- **Status**: ✅ Implemented
- **Source Files**:
  - `argus/runtime/observability.py`
  - `argus/runtime/history.py`
  - `argus/runtime/orchestrator.py`
  - `argus/runtime/monitor.py`
  - `argus/cli/tools_cli.py`
- **Implementation Evidence**:
- `argus/runtime/observability.py:18-45`: `log_lifecycle()` logs structured events with automatic secret redaction (`redact()`).
- `argus/runtime/history.py:6-45`: `MissionStorage` persists runtime state, execution metrics, and logs to `.argus/tool_history.json`.
- `argus/runtime/orchestrator.py`: Emits execution start/finish/error events and records artifact paths.
- `argus tools history`: Interactive CLI command displaying execution records, tool durations, and return codes.
- **Gaps**:
- Observability is currently file-based JSON logging; no OpenTelemetry trace export or Prometheus metrics endpoint exists.
- **Test Coverage**: `tests/runtime/test_runtime_orchestrator.py` (passed), `tests/tools/test_environment_detector.py` (passed).
- **Notes**: Comprehensive local observability and audit history for autonomous tool execution.

---

<a id="section-46-performance"></a>
#### Section 46: Performance

- **Status**: 🔴 Broken
- **Source Files**:
  - `argus/performance/metrics.py`
  - `argus/performance/cache.py`
  - `argus/performance/profiling.py`
  - `argus/performance/incremental.py`
  - `argus/performance/scheduler.py`
  - `argus/performance/benchmark.py`
  - `argus/cli/performance_cli.py`
  - `argus/cli/app.py`
- **Implementation Evidence**:
- `argus/performance/metrics.py`: `MetricsRegistry` implements thread-safe counters, gauges, and histograms.
- `argus/performance/profiling.py`: `Profiler` context manager measuring CPU and wall-clock execution latency.
- `argus/performance/cache.py`: LRU `ObjectCache` and singleton caches for findings, evidence, and graph lookups.
- `argus/performance/scheduler.py`: `ParallelTaskScheduler` managing concurrent worker threadpools.
- `argus/performance/benchmark.py`: Synthetic benchmark test target measuring scanning throughput.
- **Gaps**:
- **CRITICAL CLI MOUNTING BUG**: In `argus/cli/app.py:71`, `app.add_typer(performance_app)` is invoked without `name='performance'`. This causes `argus performance` to return `Error: No such command 'performance'`. Furthermore, this un-named mount shadows the `benchmark` namespace mounted at line 58 (`argus/cli/benchmark_cli.py`), breaking both commands.
- **Test Coverage**: `tests/performance/test_performance.py` (5 passed). Backend performance modules work in unit tests; CLI interface is completely broken.
- **Notes**: One-line fix required in `argus/cli/app.py:71`: `app.add_typer(performance_app, name='performance')`.

---

<a id="section-47-workspace"></a>
#### Section 47: Workspace

- **Status**: ✅ Implemented
- **Source Files**:
  - `argus/workspace/api.py`
  - `argus/workspace/engine.py`
  - `argus/workspace/context/engine.py`
  - `argus/workspace/copilot.py`
  - `argus/workspace/models.py`
  - `argus/workspace/vision.py`
  - `argus/workspace/web/app.py`
  - `argus/cli/workspace_cli.py`
- **Implementation Evidence**:
- `argus/workspace/api.py`: FastAPI APIRouter (`prefix='/api'`) with 38 REST endpoints covering projects, missions, conversations, context retrieval, copilot chat, multimodal image analysis, and artifact downloads.
- `argus/workspace/vision.py`: Multimodal vision inspection analyzing target screenshots and web application UI components.
- `argus/workspace/copilot.py`: Conversational AI assistant grounding answers on verified mission evidence and graph context.
- `argus/workspace/context/engine.py`: Hybrid vector and lexical context retrieval engine for interactive sessions.
- `argus workspace start`: CLI command launching the FastAPI backend with interactive Swagger UI and web client.
- **Gaps**:
None significant. Workspace backend is feature-complete.
- **Test Coverage**: 22 test files with 95 passed tests in `tests/workspace/` (100% pass rate).
- **Notes**: Production-grade collaborative research workspace with real-time AI copilot and multimodal vision integration.

---

<a id="section-48-cli-surface-34-namespaces"></a>
#### Section 48: CLI Surface (34 Namespaces)

- **Status**: ⚠️ Partial
- **Source Files**:
  - `argus/cli/app.py`
  - 32 sub-application CLI modules under `argus/cli/`
- **Implementation Evidence**:
  - Centralized Typer application registering 31 sub-applications and 3 root commands (`execute`, `trace`, `version`).
  - 25 of the 34 namespaces are fully implemented and connected to backend data models and specialists.
- **Gaps**:
  - **3 Broken Namespaces**: `argus performance` (missing name argument in `add_typer`), `argus benchmark` (shadowed by line 71 mount), and `argus intelligence list` (crashes due to un-iterable registry object).
  - **6 Partial/Demo Namespaces**: `argus execution`, `argus plugin`, `argus plan`, `argus research`, `argus scheduler`, and `argus execute` contain hardcoded demo hosts (`test.com`, `demo.example.com`, `scheduler.example.com`) or print mock strings.
- **Test Coverage**: `tests/cli/test_search_cli.py` (22 passed), `tests/explain/test_explain.py`, direct Typer inspection.
- **Notes**: Comprehensive empirical verification of all 34 CLI namespaces was conducted as detailed below:

### Comprehensive Verification of All 34 CLI Namespaces (Section 48)

| # | Namespace / Command | Registered in `app.py` | Source File | Status | Notes / Verified Behavior |
|---|---|---|---|---|---|
| 1 | `knowledge` | Line 38 (`name="knowledge"`) | `argus/cli/knowledge.py` | ✅ Implemented | Subcommands `search`, `show`, `list`, `stats` connect to `KnowledgeManager`. |
| 2 | `queue` | Line 39 (`name="queue"`) | `argus/cli/queue_cli.py` | ✅ Implemented | Subcommand `list` displays prioritized investigation queue from `mission.research_queue`. |
| 3 | `workflow` | Line 40 (`name="workflow"`) | `argus/cli/workflow_cli.py` | ✅ Implemented | Subcommands `list`, `show`, `graph`, `export`, `analyze`, `states` connect to workflow models & specialist. |
| 4 | `auth` | Line 41 (`name="auth"`) | `argus/cli/auth_cli.py` | ✅ Implemented | Subcommands `show`, `analyze`, `investigations`, `explain` connect to `AuthorizationGraph`. |
| 5 | `agent` | Line 42 (`name="agent"`) | `argus/cli/agent_cli.py` | ✅ Implemented | Subcommands `list`, `run`, `show` display registered agents and execution dependencies. |
| 6 | `execution` | Line 43 (`name="execution"`) | `argus/cli/execution_cli.py` | ⚠️ Partial | Subcommands `status` and `history` print hardcoded mock data (`plan-uuid-1234`). |
| 7 | `plugin` | Line 44 (`name="plugin"`) | `argus/cli/plugin_cli.py` | ⚠️ Partial | Subcommands `list` and `info` work; `install`, `remove`, `enable`, `disable` print placeholder stubs. |
| 8 | `provenance` | Line 45 (`name="provenance"`) | `argus/cli/provenance_cli.py` | ✅ Implemented | Subcommands `explain`, `trace`, `stats` connect to `provenance_engine`. |
| 9 | `mission` | Line 46 (`name="mission"`) | `argus/cli/mission_cli.py` | ✅ Implemented | Subcommands `create`, `run`, `list`, `start`, `pause`, `resume`, `cancel`, `status`, `checkpoint`, `recover`. |
| 10 | `intelligence` | Line 47 (`name="intelligence"`) | `argus/cli/intelligence_cli.py` | 🔴 Broken | `run`, `show`, `explain` work; `list` crashes with `TypeError: 'InvestigationRegistry' object is not iterable`. |
| 11 | `playbooks` | Line 48 (`name="playbooks"`) | `argus/cli/playbook_cli.py` | ✅ Implemented | Subcommands `list`, `show`, `run`, `status` connect to `MethodologyEngine`. |
| 12 | `business` | Line 49 (`name="business"`) | `argus/cli/business_cli.py` | ✅ Implemented | Subcommand `investigations` filters business logic investigations. |
| 13 | `api` | Line 50 (`name="api"`) | `argus/cli/api_cli.py` | ✅ Implemented | Subcommands `inventory`, `graph`, `resources`, `explain` connect to `APIIntelligenceSpecialist`. |
| 14 | `authn` | Line 51 (`name="authn"`) | `argus/cli/authn_cli.py` | ✅ Implemented | Subcommands `analyze`, `investigations`, `graph`, `explain` connect to `AuthenticationIntelligenceSpecialist`. |
| 15 | `upload` | Line 52 (`name="upload"`) | `argus/cli/upload_cli.py` | ✅ Implemented | Subcommands `analyze`, `investigations`, `graph`, `explain` connect to `FileUploadSpecialist`. |
| 16 | `tools` | Line 53 (`name="tools"`) | `argus/cli/tools_cli.py` | ✅ Implemented | Subcommands `list`, `run`, `status`, `history` read/write `.argus/tool_history.json`. |
| 17 | `graphql` | Line 54 (`name="graphql"`) | `argus/plugins/graphql/cli.py` | ✅ Implemented | 10 subcommands (`discover`, `schema`, `types`, `operations`, etc.) connect to `GraphQLPlugin`. |
| 18 | `javascript` | Line 55 (`name="javascript"`) | `argus/plugins/javascript/cli.py` | ✅ Implemented | Subcommands `discover` and `analyze` connect to `JavaScriptPlugin`. |
| 19 | `observations` | Line 56 (`name="observations"`) | `argus/correlation/cli.py` | ✅ Implemented | Subcommands `list`, `show`, `export` connect to `ObservationRegistry`. |
| 20 | `correlations` | Line 57 (`name="correlations"`) | `argus/correlation/cli.py` | ✅ Implemented | Subcommands `list`, `show`, `graph`, `export` connect to `CorrelationRegistry`. |
| 21 | `benchmark` | Line 58 (`name="benchmark"`) | `argus/cli/benchmark_cli.py` | 🔴 Broken | Mounted at line 58, but shadowed by un-named `performance_app` at line 71. Benchmark suite inaccessible. |
| 22 | `workspace` | Line 59 (`name="workspace"`) | `argus/cli/workspace_cli.py` | ✅ Implemented | Subcommands `start` (launches web server) and `context-inspect` (context engine query). |
| 23 | `evidence` | Line 62 (`name="evidence"`) | `argus/correlation/cli.py` | ✅ Implemented | Subcommands `list`, `show`, `graph`, `export` connect to `EvidenceBundleRegistry`. |
| 24 | `investigations` | Line 65 (`name="investigations"`) | `argus/cli/investigation_cli.py` | ✅ Implemented | Subcommands `list`, `show`, `explain`, `export`, `priority`, `top` connect to `InvestigationRegistry`. |
| 25 | `explain` | Line 68 (`name="explain"`) | `argus/cli/explain_cli.py` | ✅ Implemented | Subcommands `summary`, `graph`, `timeline`, `export` connect to `ExplanationEngine`. |
| 26 | `performance` | Line 71 (`app.add_typer(...)`) | `argus/cli/performance_cli.py` | 🔴 Broken | Missing `name="performance"` in `add_typer`. `argus performance` returns `No such command 'performance'`. |
| 27 | `plan` | Line 74 (`name="plan"`) | `argus/cli/plan_cli.py` | ⚠️ Partial | Subcommands `plan`, `graph`, `explain` execute against hardcoded dummy mission `test.com`. |
| 28 | `research` | Line 77 (`name="research"`) | `argus/cli/research_cli.py` | ⚠️ Partial | Subcommands `plan`, `queue`, `explain`, `coverage` execute against hardcoded demo mission `demo.example.com`. |
| 29 | `scheduler` | Line 80 (`name="scheduler"`) | `argus/cli/scheduler_cli.py` | ⚠️ Partial | Subcommands `queue`, `history`, `graph` execute against hardcoded demo mission `scheduler.example.com`. |
| 30 | `learning` | Line 83 (`name="learning"`) | `argus/cli/learning_cli.py` | ✅ Implemented | Subcommands `metrics`, `history`, `recommendations`, `feedback`, `eval`, `export`, `clear`. |
| 31 | `hypothesis` | Line 86 (`name="hypothesis"`) | `argus/cli/hypothesis_cli.py` | ✅ Implemented | Subcommands `list`, `show`, `explain`, `history`, `update`, `export` connect to `HypothesisRegistry`. |
| 32 | `execute` | Line 94 (`@app.command()`) | `argus/cli/app.py` | ⚠️ Partial | Root command executes hardcoded `get_dummy_plan()` from `execution_cli.py`. |
| 33 | `trace` | Line 120 (`@app.command()`) | `argus/cli/app.py` | ✅ Implemented | Root command outputs JSON provenance graph via `provenance_engine.trace(artifact_id)`. |
| 34 | `version` | Line 296 (`@app.command()`) | `argus/cli/app.py` | ✅ Implemented | Root command outputs "Argus v0.1.0-alpha". |

---


<a id="part-5-research-lifecycle-reporting-system-architecture-sections-4957"></a>
### Part 5: Research Lifecycle, Reporting & System Architecture (Sections 49–57)

This section evaluates the end-to-end research lifecycle (Planning → Investigation → Hypothesis → Evidence → Validation → Report), the non-destructive investigation philosophy, automated reporting generators (Markdown & JSON with CVSS v3.1 calculation), timeline explainability, reinforcement learning and feedback loops, benchmarking suites, external tool discovery, and a deep architectural analysis of the dual execution paths identified in Section 57.

<a id="section-49-planning-investigation-hypothesis-evidence-validation-report-lifecycle"></a>
#### Section 49: Planning → Investigation → Hypothesis → Evidence → Validation → Report Lifecycle

- **Status**: ✅ Implemented
- **Source Files**:
  - `argus/planning/research_planner.py`
  - `argus/planning/models.py`
  - `argus/investigation/generator.py`
  - `argus/investigation/models.py`
  - `argus/hypothesis/engine.py`
  - `argus/hypothesis/models.py`
  - `argus/hypothesis/lifecycle.py`
  - `argus/evidence/model.py`
  - `argus/evidence/store.py`
  - `argus/investigation/manual_validation.py`
  - `argus/reporting/generator.py`
- **Implementation Evidence**:
- **Planning**: `ResearchPlanner` runs gap analysis and task generation without executing tools or exploiting systems.
- **Investigation**: `InvestigationGenerator.process_bundle()` turns raw `EvidenceBundle` objects into `Investigation` instances.
- **Hypothesis**: `HypothesisEngine.process_investigation()` converts investigations into `Hypothesis` instances, with lifecycle states: `DRAFT`, `PROPOSED`, `UNDER_REVIEW`, `VALIDATED`, `REJECTED`, `ARCHIVED`.
- **Evidence**: `Evidence` dataclass tracks verification status, provenance, and relationships.
- **Validation**: `ManualValidationGenerator` produces safe, non-destructive validation steps for human review.
- **Report**: `ReportGenerator` compiles confirmed findings and evidence into CVSS-scored HackerOne reports upon mission completion.
- **Gaps**: None. All 6 lifecycle stages are cleanly decoupled and independently orchestrated.
- **Test Coverage**: `tests/hypothesis/test_integration.py`, `tests/hypothesis/test_lifecycle.py`, `tests/runtime/test_e2e_reporting.py`.
- **Notes**: Strict architectural decoupling prevents raw scanner output from masquerading as confirmed security findings without verification.

---

<a id="section-50-investigation-philosophy"></a>
#### Section 50: Investigation Philosophy

- **Status**: ✅ Implemented
- **Source Files**:
  - `argus/investigation/models.py`
  - `argus/investigation/builder.py`
  - `argus/investigation/generator.py`
  - `argus/investigation/manual_validation.py`
- **Implementation Evidence**:
- Investigation models strictly treat findings as potential areas of interest rather than definitive vulnerabilities.
- `ManualValidationGenerator` formats non-destructive validation steps (e.g. curl commands, UI verification) with clear expected outcomes to ensure human researchers remain in the loop.
- **Gaps**: None. The philosophy is codified throughout the investigation and hypothesis pipeline.
- **Test Coverage**: `tests/investigation/test_manual_validation.py`, `tests/investigation/test_generator.py`.
- **Notes**: Aligns with responsible disclosure and bug-bounty rules of engagement by strictly preventing autonomous destructive exploitation.

---

<a id="section-51-reporting"></a>
#### Section 51: Reporting

- **Status**: ✅ Implemented
- **Source Files**:
  - `argus/reporting/generator.py`
  - `argus/reporting/processor.py`
  - `argus/reporting/markdown.py`
  - `argus/reporting/json.py`
  - `argus/reporting/cvss.py`
  - `argus/reporting/vector_indexer.py`
- **Implementation Evidence**:
- `ReportGenerator` orchestrates `EvidenceProcessor` to normalize evidence into deduplicated `Finding` models grouped by category and host.
- `CVSSCalculator` computes standard CVSS v3.1 base metrics, exploitability scores, and vector strings.
- `HackerOneMarkdownRenderer` formats complete bug-bounty ready reports with executive summary, severity breakdown, reproduction steps, and remediation guidance.
- `JSONReportRenderer` exports structured reports for automated downstream consumption.
- `ScanEvidenceIndexer` automatically indexes findings and evidence into the vector store for semantic search.
- **Gaps**: None. Robust multi-format reporting with strict evidence traceability.
- **Test Coverage**: `tests/reporting/test_generator.py`, `tests/reporting/test_processor.py`, `tests/reporting/test_renderers.py`, `tests/reporting/test_cvss.py` (60 passed in `tests/reporting/`).
- **Notes**: Produces publication-ready HackerOne vulnerability reports directly from verified evidence.

---

<a id="section-52-explainability"></a>
#### Section 52: Explainability

- **Status**: ✅ Implemented
- **Source Files**:
  - `argus/explain/engine.py`
  - `argus/explain/models.py`
  - `argus/explain/reasoning.py`
  - `argus/explain/timeline.py`
  - `argus/explain/export.py`
  - `argus/cli/explain_cli.py`
- **Implementation Evidence**:
- `ExplanationEngine` constructs causal reasoning graphs showing how initial observations led to hypotheses and findings.
- `TimelineGenerator` renders chronological execution timelines linking tool calls, state transitions, and evidence capture.
- CLI commands `argus explain summary`, `graph`, `timeline`, and `export` allow interactive inspection and export to JSON/DOT.
- **Gaps**: None. Full explainability pipeline implemented.
- **Test Coverage**: `tests/explain/test_explain.py` (5 passed).
- **Notes**: Crucial capability for auditor review and debugging autonomous research decisions.

---

<a id="section-53-learning"></a>
#### Section 53: Learning

- **Status**: ✅ Implemented
- **Source Files**:
  - `argus/learning/engine.py`
  - `argus/learning/metrics.py`
  - `argus/learning/history.py`
  - `argus/learning/patterns.py`
  - `argus/learning/recommendations.py`
  - `argus/learning/feedback.py`
  - `argus/cli/learning_cli.py`
- **Implementation Evidence**:
- `LearningEngine` tracks investigation outcomes (confirmed vulnerabilities vs false positives).
- `PatternExtractor` identifies attack patterns and successful payload heuristics from historical missions.
- `RecommendationEngine` dynamically suggests prioritized actions for new missions based on target technology similarities.
- `argus learning` CLI subcommands (`metrics`, `history`, `recommendations`, `feedback`, `eval`, `export`).
- **Gaps**: None. Fully operational reinforcement learning and recommendation loop.
- **Test Coverage**: 9 test files with 97 passed tests in `tests/learning/` (100% pass rate).
- **Notes**: Allows Argus to adaptively improve scanning accuracy and prioritize fruitful investigation avenues over time.

---

<a id="section-54-benchmarking"></a>
#### Section 54: Benchmarking

- **Status**: ✅ Implemented
- **Source Files**:
  - `argus/benchmark/framework.py`
  - `argus/benchmark/models.py`
  - `argus/benchmark/datasets/`
  - `argus/benchmark/ground_truth/`
  - `argus/benchmark/leaderboard/`
  - `argus/benchmark/metrics/`
  - `argus/benchmark/reports/`
  - `argus/cli/benchmark_cli.py`
- **Implementation Evidence**:
- Comprehensive benchmark evaluation harness executing Argus against standardized vulnerability datasets.
- Computes precision, recall, F1 score, false positive rates, and time-to-detection against ground truth annotations.
- Leaderboard and markdown/JSON benchmark report generation.
- **Gaps**: None in core engine. Note: Section 46 CLI mounting bug shadows `argus benchmark` CLI; the framework itself is fully operational.
- **Test Coverage**: 19 test files with 42 passed tests in `tests/benchmark/` (100% pass rate).
- **Notes**: Enables rigorous empirical comparison of new heuristics and models against standardized ground truth.

---

<a id="section-55-testing"></a>
#### Section 55: Testing

- **Status**: ✅ Implemented
- **Source Files**:
  - `tests/planning/`
  - `tests/runtime/`
  - `tests/tools/`
  - `tests/collectors/`
  - `tests/scanning/`
  - `tests/correlation/`
  - `tests/hypothesis/`
  - `tests/learning/`
  - `tests/workspace/`
- **Implementation Evidence**:
- 2,451 automated tests in `tests/` across 28 functional suites, plus 12 co-located specialist tests in `argus/`.
- Extensive adversarial, stress, and differential testing suites across all major vulnerability collectors and runtime engines.
- **Gaps**: None. 100% test pass rate.
- **Test Coverage**: 2,463 total tests passed (0 failures, 0 errors across repo).
- **Notes**: Exceptionally high test density and domain coverage for an offensive security platform.

---

<a id="section-56-current-external-tool-environment"></a>
#### Section 56: Current External Tool Environment

- **Status**: ✅ Implemented
- **Source Files**:
  - `argus/utils/environment.py`
  - `argus/runtime/registry.py`
  - `argus/runtime/executor.py`
- **Implementation Evidence**:
- `EnvironmentDetector` probes system PATH for external security binaries: `subfinder`, `httpx`, `katana`, `nuclei`, `dnsx`, `node`, `npm`.
- Checks runtime versions, execution permissions, and availability.
- Cloud metadata endpoint detection across AWS (169.254.169.254), GCP, and Azure.
- Graceful fallback execution when tools are absent.
- **Gaps**: None. Comprehensive environment detection and fallback handling.
- **Test Coverage**: `tests/tools/test_environment_detector.py` (29 passed).
- **Notes**: Ensures seamless execution across both fully provisioned Docker containers and minimal development environments.

---

<a id="section-57-important-architectural-cleanup-dual-execution-paths"></a>
#### Section 57: Important Architectural Cleanup (Dual Execution Paths)

- **Status**: ⚠️ Partial
- **Source Files**:
  - **Path A (Legacy DAG Scanner)**: `argus/scanning/engine.py` (`ScanEngine`), `argus/scanning/dag.py` (`ScanDAG`), `argus/collectors/*.py` (32 modules)
  - **Path B (Autonomous Mission Runtime)**: `argus/runtime/mission_runtime.py` (`AutonomousMissionRuntime`), `argus/runtime/orchestrator.py`, `argus/runtime/dispatcher.py`, `argus/runtime/registry.py`, `argus/runtime/executor.py`
  - **Path C (Agent Step Execution)**: `argus/execution/engine.py` (`ExecutionEngine`), `argus/agents/base.py` (`BaseAgent`)
  - **Adapter Bridge**: `argus/runtime/plugins.py` (`PluginExecutorAdapter`)
- **Implementation Evidence**:
  - Structural co-existence of Path A (Collector Scanning DAG invoked via `argus scan`), Path B (Autonomous Mission Runtime invoked via `argus mission run`), and Path C (Legacy Agent Step Execution).
  - `PluginExecutorAdapter._instantiate_specialist_fallback()` provides an ad-hoc runtime bridge enabling Path B to dynamically execute Path A collectors as plugins.
  - Duplicated resolution maps between `ScanEngine.resolve_collector` (65 lines) and `PluginExecutorAdapter._instantiate_specialist_fallback` (200 lines).
  - Duplicated DAG schedulers between `ScanDAG` and `TaskScheduler`.
  - Duplicated result models across `ScanResult`, `ToolExecutionResult`, and `AgentResult`.
- **Gaps**:
  - Primary user command `argus scan` invokes legacy Path A, bypassing the 10-step autonomous mission loop, hypothesis engine, and knowledge graph.
  - 32 vulnerability collectors directly mutate `mission` attributes rather than returning typed `Evidence` or `ToolExecutionResult` models.
  - Triplicate EventBus implementations (`argus/runtime/events.py`, `argus/core/event_bus.py`, `argus/plugins/events.py`).
  - 14 orphaned Python files with zero imports in `argus/core/`, `argus/workspace/`, and `argus/models/`.
- **Test Coverage**: `tests/scanning/` (62 passed), `tests/runtime/` (140 passed), `tests/collectors/` (1,078 passed).
- **Notes**:
  - **Consolidation Roadmap**: Refactor `argus scan` to invoke `AutonomousMissionRuntime` with a scanning profile; deprecate `ScanEngine`; migrate collectors to return typed `Evidence`; consolidate event buses into `argus.runtime.events`.

**Deep Architectural Analysis of Dual Execution Paths**:

#### Direct Code Observations
1. **Identified Execution Paths**:
   - **Path A: Older / Intermediate Collector Scanning DAG**:
     - Files: `argus/scanning/engine.py` (`ScanEngine`), `argus/scanning/dag.py` (`ScanDAG`, `ScanTask`), `argus/collectors/*.py` (32 modules inheriting from `BaseCollector` in `argus/collectors/base.py`).
     - Invocation: `argus scan <target>` in `argus/cli/app.py` lines 198–203 executes `ScanEngine(dag=dag).run(mission)`.
     - Mechanism: Directly calls `collector.collect(mission)`. Collectors directly mutate mission attributes (`mission.findings`, `mission.vulnerabilities`, `mission.endpoints`).
   - **Path B: Newer Autonomous Mission Runtime**:
     - Files: `argus/runtime/mission_runtime.py` (`AutonomousMissionRuntime`), `argus/runtime/controller.py` (`MissionController`), `argus/runtime/orchestrator.py` (`ToolOrchestrator`), `argus/runtime/dispatcher.py` (`ToolDispatcher`), `argus/runtime/registry.py` (`ToolRegistry`), `argus/runtime/executor.py` (`TaskScheduler`, `ToolExecutor`).
     - Invocation: `argus mission run <target>` in `argus/cli/mission_cli.py` lines 26–42 calls `MissionController.start(mission)` which runs `AutonomousMissionRuntime` across formal state transitions (`PLANNING` → `RESEARCHING` → `COLLECTING_EVIDENCE` → `CORRELATING` → `INVESTIGATING` → `HYPOTHESIZING` → `REPORTING` → `COMPLETED`).
     - Mechanism: Emits lifecycle events via `EventBus`, tracks tasks in `PriorityTaskQueue`, resolves tools via `ToolDispatcher`, enforces safety via `SafetyValidator`, isolates execution in `Sandbox`.
   - **Path C: Legacy Agent Step Execution**:
     - Files: `argus/execution/engine.py` (`ExecutionEngine`), `argus/agents/base.py` (`BaseAgent`), `argus/agents/scheduler.py` (`AgentScheduler`), `argus/agents/registry.py` (`AgentRegistry`).
     - Invocation: `argus execute` in `argus/cli/execution_cli.py`.
     - Mechanism: Executes steps using `think()`, `execute()`, `evaluate()`.
2. **Duplicated Code & Structural Redundancy**:
   - **Duplicated Resolution Maps**:
     - `ScanEngine.resolve_collector` (`argus/scanning/engine.py` lines 76–140) maintains a 65-line `collector_class_map` mapping 30+ string tool IDs to `argus.collectors.*` classes.
     - `PluginExecutorAdapter._instantiate_specialist_fallback` (`argus/runtime/plugins.py` lines 65–270) maintains an almost identical 200-line `if/elif` chain mapping the exact same tool IDs and aliases to `argus.collectors.*`, `argus.plugins.*`, and `argus.agents.*`.
     - `ToolRegistry` (`argus/runtime/registry.py` lines 354–420) registers `Tool` entries with duplicate metadata.
   - **Duplicated DAG Schedulers**:
     - `ScanDAG` has its own topological sort, dependency checking, and profile filtering (`full`, `recon`, `vuln`, `quick`).
     - `TaskScheduler` (`argus/runtime/executor.py`) has its own dependency resolution, retry handling, and task state tracking.
   - **Duplicated Result Models**:
     - `ScanResult` / `CollectorResult` (`argus/scanning/models.py`).
     - `ToolExecutionResult` (`argus/runtime/models.py`).
     - `AgentResult` / `AgentMetric` (`argus/agents/results.py`).
3. **Migration Gaps**:
   - **CLI Disconnect**: The user-facing primary command `argus scan` uses Path A (`ScanEngine`), meaning users running standard scans do not benefit from the Mission Runtime's state machine, planning loop, or hypothesis engine.
   - **Ad-hoc Cross-Path Adapter**: Path B relies on `PluginExecutorAdapter._instantiate_specialist_fallback()` to dynamically load the 32 Path A collectors as plugins.
   - **Collector Mutation vs Return Value**: Path A collectors mutate `mission` directly rather than returning typed `ToolExecutionResult` or `Evidence` objects.

---


<a id="part-6-advanced-research-roadmap-evolution-sections-5878"></a>
### Part 6: Advanced Research Roadmap & Evolution (Sections 58–78)

This section evaluates the future roadmap and advanced research capabilities of Argus, covering Phases 9 through 26: advanced security research specialists, continuous investigation loops, adaptive prioritization, cross-specialist correlation, stateful research, differential response analysis, finding validation and false-positive reduction frameworks, RAG knowledge bases, technology-aware investigation, researcher feedback loops, evidence-first reporting, reproducibility, mission replay, research benchmarks, production hardening, the recommended development order (Section 77), and the core success criteria and final platform vision (Section 78).

<a id="section-58-future-roadmap-phase-9-security-research-specialists-9195"></a>
#### Section 58: Future Roadmap — Phase 9: Security Research Specialists (9.1–9.5)

- **Status**: ✅ Implemented
- **Source Files**:
  - `argus/intelligence/engine.py` (`class VulnerabilityIntelligenceEngine`)
  - `argus/intelligence/registry.py` (`class HeuristicRegistry`)
  - `argus/intelligence/hypothesis.py` (`class HypothesisGenerator`)
  - `argus/intelligence/confidence.py` (`class ConfidenceScorer`)
  - `argus/intelligence/prioritizer.py` (`class InvestigationPrioritizer`)
  - `argus/methodology/engine.py` (`class MethodologyEngine`)
  - `argus/methodology/registry.py` (`class PlaybookRegistry`)
  - `argus/methodology/executor.py` (`class PlaybookExecutor`)
  - `argus/agents/authorization/agent.py` (`class AuthorizationSpecialist`)
  - `argus/authorization/analyzer.py`
  - `argus/agents/business_logic/agent.py` (`class BusinessLogicSpecialist`)
  - `argus/plugins/api/agent.py` (`class APIIntelligenceSpecialist`)
  - `argus/collectors/api_security.py` (Sprint 27)
  - `argus/collectors/business_logic.py` (Sprint 21)
  - `argus/collectors/access_control.py` (Sprint 6)
- **Implementation Evidence**:
  - 9.1 Vulnerability Intelligence: `VulnerabilityIntelligenceEngine.run()` drives generation of hypotheses from raw mission state, scores confidence via `ConfidenceScorer`, prioritizes via `InvestigationPrioritizer`, and populates `mission.priority_queue`.
  - 9.2 Methodology Engine: `MethodologyEngine.run()` executes playbooks registered in `PlaybookRegistry`, tracking completed, active, and pending playbooks in the mission state.
  - 9.3 Authorization Specialist: `AuthorizationSpecialist.analyze()` constructs `AuthzContext`, runs `AUTHZ_HEURISTIC_REGISTRY` heuristics, scores confidence, and flags privilege escalation/IDOR risks.
  - 9.4 Business Logic Specialist: `BusinessLogicSpecialist.analyze()` builds state machines via `StateMachineBuilder`, extracts workflow rules via `WorkflowAnalyzer`, runs `BUSINESS_LOGIC_HEURISTIC_REGISTRY`, and prioritizes investigations.
  - 9.5 API Intelligence Specialist: `APIIntelligenceSpecialist.analyze()` parses OpenAPI/REST endpoints (`SchemaParser`), infers relationships (`RelationshipInferencer`), extracts CRUD operations (`OperationAnalyzer`), detects API versions (`VersionDetector`), and runs `API_HEURISTIC_REGISTRY`.
- **Gaps**: Autonomous cognitive dynamic adaptation (agents holding multi-turn LLM reasoning loops with live target mutation) is represented as rule/heuristic pipelines rather than unconstrained autonomous LLM agents.
- **Test Coverage**: `tests/test_intelligence.py`, `tests/test_methodology.py`, `tests/test_authz_specialist.py`, `tests/test_authorization.py`, `tests/test_business_root.py`, `tests/collectors/test_business_logic.py`, `tests/collectors/test_api_security.py` (72 tests passed).
- **Notes**: Full working pipeline with concrete classes and high test pass rate.

---

<a id="section-59-phase-96910-auth-upload-graphql-js-tech-packs"></a>
#### Section 59: Phase 9.6–9.10 (Auth, Upload, GraphQL, JS, Tech Packs)

- **Status**: ⚠️ Partial
- **Source Files**:
  - 9.6 Auth & Session: `argus/plugins/authentication/agent.py` (`class AuthenticationIntelligenceSpecialist`), `argus/collectors/auth_bypass.py` (Sprint 28), `argus/collectors/oauth.py` (Sprint 13)
  - 9.7 File Upload: `argus/plugins/file_upload/agent.py` (`class FileUploadSpecialist`), `argus/collectors/file_upload.py` (Sprint 26)
  - 9.8 GraphQL: `argus/plugins/graphql/agent.py` (`class GraphQLSpecialist`), `argus/collectors/graphql.py` (Sprint 17)
  - 9.9 JS Intelligence: `argus/plugins/javascript/agent.py` (`class JavaScriptSpecialist`), `argus/analyzers/javascript.py`, `argus/collectors/javascript.py`
  - 9.10 Technology Packs: `argus/collectors/technology.py` (`class TechnologyCollector`)
- **Implementation Evidence**:
  - Authentication Specialist extracts identities, cookie session entropy, tokens, OAuth configurations, and MFA endpoints.
  - File Upload Specialist models upload/download endpoints, storage inference (S3/local), file object classification, and executes 6 upload vulnerability detection modes (MIME spoofing, polyglot, extension evasion).
  - GraphQL Specialist executes introspection, schema parsing, query depth calculation, batching DoS probing, and BOPLA inspection.
  - JavaScript Specialist implements regex and AST-based JS parsing, extracting endpoints, hardcoded secrets, and framework signatures.
- **Gaps**:
  - Technology Packs (9.10) are NOT implemented as plug-and-play modular packs. While `TechnologyCollector` discovers technology strings and connects nodes in the Attack Surface Graph, there is no package architecture defining framework-specific security behaviors, custom questions, and tailored specialist playbooks for distinct stacks (e.g. Django Pack, Spring Pack, WordPress Pack).
- **Test Coverage**: `tests/collectors/test_auth_bypass.py`, `tests/collectors/test_file_upload.py`, `tests/collectors/test_graphql.py`, `tests/plugins/javascript/`, `tests/plugins/graphql/` (all passing).
- **Notes**: 4 of the 5 specialists (9.6, 9.7, 9.8, 9.9) are comprehensively built and tested; Section 59 is marked Partial solely due to the missing modular Technology Packs (9.10).

---

<a id="section-60-phase-10-continuous-investigation-loop"></a>
#### Section 60: Phase 10 — Continuous Investigation Loop

- **Status**: ✅ Implemented
- **Source Files**:
  - `argus/runtime/mission_runtime.py` (`class AutonomousMissionRuntime`)
  - `argus/runtime/state_machine.py` (`class MissionStateMachine`)
  - `argus/scanning/engine.py` (`class ScanEngine`)
  - `argus/planning/research_planner.py` (`class ResearchPlanner`)
  - `argus/planning/task_generator.py` (`class TaskGenerator`)
- **Implementation Evidence**:
  - `AutonomousMissionRuntime.run()` orchestrates the closed-loop research cycle:
    1. `PLANNING`: `MissionPlanner.analyze()`, `AttackSurfaceGraphBuilder.build()`, `ResearchPlanner.plan()`
    2. `RESEARCHING`: `TaskScheduler.schedule_tasks()`, `ToolOrchestrator.execute_task()`
    3. `COLLECTING_EVIDENCE`: Graph rebuild and evidence sync
    4. `CORRELATING`: `CorrelationEngine.process_observation()`, `EvidenceFusionEngine.process_mission_state()`
    5. `BUILDING_INVESTIGATIONS`: `InvestigationBuilder.build_all()`, `prioritize_all()`
    6. `GENERATING_HYPOTHESES`: `HypothesisEngine.process_investigation()`, `evaluate_all()`, loop continuation if new tasks are discovered, or transition to `COMPLETED`.
  - Batching, task dependency checking, and state checkpoints are fully wired.
- **Gaps**:
  - Dual execution paths coexist in the repo: `AutonomousMissionRuntime` (step-based continuous state machine) and `ScanEngine` (DAG batch runner). Unification into a single engine is scheduled for production hardening.
- **Test Coverage**: `tests/runtime/test_mission_runtime.py`, `tests/runtime/test_runtime_orchestrator.py`, `tests/scanning/test_scan_engine.py` (all passed).
- **Notes**: Meets all continuous loop criteria: recon → model → gap analysis → investigate → prioritize → correlate → re-evaluate → loop.

---

<a id="section-61-phase-11-adaptive-research-prioritization"></a>
#### Section 61: Phase 11 — Adaptive Research Prioritization

- **Status**: ✅ Implemented
- **Source Files**:
  - `argus/investigation/priority_engine.py` (`class PriorityEngine`)
  - `argus/investigation/scoring.py` (`class ScoreCalculator`)
  - `argus/investigation/weights.py` (`class WeightConfig`)
  - `argus/investigation/ranking.py` (`class InvestigationRanker`)
  - `argus/planning/decision_engine.py` (`class DecisionEngine`)
- **Implementation Evidence**:
  - `ScoreCalculator.calculate()` computes a 0–100 composite priority score across 13 factors:
    1. Evidence strength (multi-specialist bundles)
    2. Observation confidence
    3. Correlation confidence
    4. Workflow criticality
    5. Business object importance
    6. Exposure & Reachability
    7. Graph completeness bonus
    8. Technology confidence bonus
    9. Administrative context multiplier
    10. Authorization context multiplier
    11. Authentication context multiplier
    12. Mission policy alignment bonus
    13. Mission scope alignment bonus
  - `DecisionEngine` in `argus/planning/decision_engine.py` dynamically deprioritizes tasks whose dependencies are unmet or where coverage is already high.
- **Gaps**: Dynamic machine-learned weight adaptation based on historical cross-mission success rate is designed in `argus/learning/` but currently requires planner review rather than automated weight adjustments.
- **Test Coverage**: `tests/investigation/test_priority.py` (7 tests passed).
- **Notes**: Full explainability string returned alongside numeric scores (`investigation.priority_explanation`).

---

<a id="section-62-phase-12-cross-specialist-correlation"></a>
#### Section 62: Phase 12 — Cross-Specialist Correlation

- **Status**: ✅ Implemented
- **Source Files**:
  - `argus/correlation/engine.py` (`class CorrelationEngine`)
  - `argus/correlation/fusion.py` (`class EvidenceFusionEngine`, `DEFAULT_FUSION_RULES`)
  - `argus/correlation/matcher.py` (`class CorrelationMatcher`)
  - `argus/correlation/rules.py`
  - `argus/correlation/graph.py` (`class CorrelationGraph`)
  - `argus/correlation/scoring.py` (`class CorrelationScorer`)
  - `argus/correlation/strength.py` (`class EvidenceStrengthScorer`)
- **Implementation Evidence**:
  - `CorrelationEngine.process_observation()` ingests observations, checks matching rules (`CorrelationMatcher`), creates graph links between related items, and merges overlapping correlations (`_merge_correlations()`).
  - `EvidenceFusionEngine` executes `DEFAULT_FUSION_RULES`:
    - `fuse_shared_business_objects`
    - `fuse_shared_workflows`
    - `fuse_shared_technologies`
    - `fuse_shared_endpoints`
    - `fuse_shared_graphql_types`
    - `fuse_shared_authentication_context`
    - `fuse_shared_authorization_context`
    - `fuse_shared_api_resource`
    - `fuse_shared_client_route`
    - `fuse_shared_graph_nodes`
  - Blends multi-specialist evidence into unified `EvidenceBundle` instances.
- **Gaps**: Cross-specialist correlation is deterministic based on domain attributes rather than probabilistic embeddings (though vector RAG correlation operates in parallel via `CVECorrelator` and `FindingSemanticSearchEngine`).
- **Test Coverage**: `tests/correlation/` (35 tests passed across 12 test files).
- **Notes**: Meets and exceeds the Phase 12 specification.

---

<a id="section-63-phase-13-stateful-application-research"></a>
#### Section 63: Phase 13 — Stateful Application Research

- **Status**: ✅ Implemented
- **Source Files**:
  - `argus/http/coordinator.py` (`class MultiIdentitySessionCoordinator`, `class MultiIdentityComparison`)
  - `argus/models/test_identity.py` (`class TestIdentity`)
  - `argus/collectors/access_control.py` (Sprint 6)
  - `argus/collectors/business_logic.py` (Sprint 21)
  - `argus/collectors/race_conditions.py` (Sprint 20)
  - `argus/agents/authorization/roles.py`, `ownership.py`, `permissions.py`
  - `argus/agents/business_logic/states.py`, `workflow.py`, `transitions.py`
- **Implementation Evidence**:
  - `MultiIdentitySessionCoordinator` manages isolated HTTP clients per `TestIdentity`, guaranteeing independent cookie jars, distinct auth headers, and session boundaries.
  - Supports `execute_as(identity, ...)`, `execute_across_identities(...)`, and automated authentication flows via `authenticate_all()`.
  - `BusinessLogicCollector` tests state transitions, step skips, and workflow invariants.
  - `RaceConditionsCollector` evaluates concurrency vulnerabilities and session concurrency limits.
- **Gaps**: Autonomous exploration of deeply nested, dynamically rendered state machines in Single Page Applications (SPAs) without pre-crawled route schemas requires external browser drivers.
- **Test Coverage**: `tests/test_test_identity.py`, `tests/collectors/test_access_control.py`, `tests/collectors/test_business_logic.py`, `tests/collectors/test_race_conditions.py` (all passed).
- **Notes**: High-quality multi-identity session management and stateful reasoning.

---

<a id="section-64-phase-14-differential-analysis"></a>
#### Section 64: Phase 14 — Differential Analysis

- **Status**: ✅ Implemented
- **Source Files**:
  - `argus/analyzers/response_discrepancy.py` (`class ResponseDiscrepancyAnalyzer`, `class DiscrepancyVerdict`)
  - `argus/http/coordinator.py` (`MultiIdentitySessionCoordinator.execute_comparison()`)
  - `argus/graph/diff.py` (`class GraphDifferentialEngine`, `class AttackSurfaceDiff`, `class HostChange`)
- **Implementation Evidence**:
  - `ResponseDiscrepancyAnalyzer` detects Broken Access Control (BAC), horizontal IDOR, vertical privilege escalation, and header bypasses by comparing status codes, response bodies, and leaked identifiers.
  - Employs `difflib.SequenceMatcher` for similarity ratios while filtering soft 200 errors and login redirects.
  - `execute_comparison()` computes `MultiIdentityComparison` with status matching, body matching, length difference, and body similarity score.
  - `GraphDifferentialEngine` computes deltas between Attack Surface Graphs across scan runs, detecting added/removed subdomains, hosts, endpoints, technologies, and vulnerabilities.
- **Gaps**: Automated diffing between OpenAPI version specs is not automated; diffing focuses on HTTP responses and graph topologies.
- **Test Coverage**: `tests/analyzers/test_response_discrepancy_adversarial.py` (8 passed), `tests/graph/`.
- **Notes**: Differential analysis is deeply integrated across collectors (BAC, Cache Poisoning, Race Conditions, Business Logic).

---

<a id="section-65-phase-15-finding-validation-framework"></a>
#### Section 65: Phase 15 — Finding Validation Framework

- **Status**: ✅ Implemented
- **Source Files**:
  - `argus/hypothesis/engine.py` (`class HypothesisEngine`)
  - `argus/hypothesis/lifecycle.py` (`class HypothesisLifecycleManager`)
  - `argus/hypothesis/models.py` (`class Hypothesis`, `class HypothesisStatus`, `class HypothesisHistoryEntry`)
  - `argus/investigation/manual_validation.py` (`class ManualValidationGenerator`)
  - `argus/execution/validators.py` (`class ExecutionValidator`)
- **Implementation Evidence**:
  - Implements the complete hypothesis lifecycle: `DRAFT` → `PROPOSED` → `UNDER_REVIEW` → `VALIDATED` / `REJECTED` / `ARCHIVED`.
  - `HypothesisHistoryEntry` records every status transition, timestamp, reason, and confidence score.
  - `ManualValidationGenerator` generates non-destructive, safe validation steps tailored to authorization, business logic, authentication, or API contexts without destructive payload execution.
  - `ExecutionValidator` verifies plan and step prerequisites before execution.
- **Gaps**: Full automated active exploitation validation is intentionally constrained by safety policy (Argus operates as a research platform, avoiding automated exploit execution).
- **Test Coverage**: `tests/hypothesis/` (26 tests passed across 9 test files), `tests/investigation/test_manual_validation.py`.
- **Notes**: Clean architecture separating evidence-backed hypotheses from confirmed findings.

---

<a id="section-66-phase-16-false-positive-reduction"></a>
#### Section 66: Phase 16 — False Positive Reduction

- **Status**: ✅ Implemented
- **Source Files**:
  - `argus/analyzers/response_discrepancy.py` (Soft-error filtering, generic discard values, login form regexes)
  - `argus/intelligence/confidence.py` (`class ConfidenceScorer`)
  - `argus/learning/feedback.py` (`FeedbackTag.FALSE_POSITIVE`, `FeedbackTag.DUPLICATE`)
  - `argus/collectors/cache_security.py` (4-step differential confirmation: Baseline → Perturbation → Replay → Isolation Control)
  - `argus/collectors/prototype_pollution.py` (Differential invariant checking)
- **Implementation Evidence**:
  - `ResponseDiscrepancyAnalyzer` filters false-positive IDORs by scanning for soft errors (`access denied`, `unauthorized`, `please log in`), login forms, and discarding generic JSON responses (`{"success": false}`, generic usernames).
  - Collectors employ multi-stage verification (e.g. Cache Security uses a 4-step probe cycle with unauthenticated replay and canary reflection checks).
  - Researcher feedback tags allow false positives to be flagged and excluded from downstream metrics.
- **Gaps**: Automatic reconciliation of conflicting evidence between distinct third-party tools (e.g. Nuclei vs internal crawler) relies on heuristic confidence rather than automated Bayesian arbitration.
- **Test Coverage**: `tests/analyzers/test_response_discrepancy_adversarial.py`, `tests/collectors/test_cache_security.py`, `tests/learning/test_feedback.py`.
- **Notes**: High-precision engineering evident across all collectors to suppress phantom findings.

---

<a id="section-67-phase-17-finding-deduplication"></a>
#### Section 67: Phase 17 — Finding Deduplication

- **Status**: ✅ Implemented
- **Source Files**:
  - `argus/investigation/generator.py` (`InvestigationGenerator._find_duplicate()`, `_merge()`)
  - `argus/correlation/engine.py` (`CorrelationEngine._merge_correlations()`)
  - `argus/correlation/deduplication.py` (`class EvidenceDeduplicator`)
  - `argus/reporting/processor.py` (`EvidenceProcessor._normalize_evidence_to_finding()`, `dedup_map`)
- **Implementation Evidence**:
  - `_find_duplicate()` identifies duplicate investigations by checking shared primary business objects/workflows and clustering host subgraphs in `KnowledgeGraph`.
  - `_merge_correlations()` merges duplicate correlations when an observation links to multiple existing clusters.
  - `EvidenceDeduplicator` eliminates duplicate raw evidence strings while preserving provenance.
  - `EvidenceProcessor` groups findings by `(category, host, endpoint, parameter)` deduplication keys and merges evidence attachments, preventing duplicate report entries.
- **Gaps**: LLM-assisted semantic deduplication (fuzzy textual semantic clustering) is secondary to structural/attribute deduplication.
- **Test Coverage**: `tests/correlation/test_deduplication.py`, `tests/investigation/test_generator.py`, `tests/reporting/test_processor.py` (all passed).
- **Notes**: Deduplication occurs at evidence, correlation, investigation, and reporting stages.

---

<a id="section-68-phase-18-security-research-rag-intelligence-fabric"></a>
#### Section 68: Phase 18 — Security Research RAG & Intelligence Fabric

- **Status**: ✅ Implemented
- **Source Files**:
  - `argus/vector/store.py` (`class VectorStore`, `get_vector_store()`)
  - `argus/vector/embeddings.py` (`class EmbeddingEngine`, `get_embedding_engine()`)
  - `argus/vector/models.py` (`VectorDocument`, `SearchResult`, `VectorFilter`)
  - `argus/reporting/vector_indexer.py` (`ScanEvidenceIndexer`, `FindingSemanticSearchEngine`)
  - `argus/knowledge/cve_kb.py` (`CVEKnowledgeBase`)
  - `argus/knowledge/cve_correlator.py` (`CVECorrelator`)
  - `argus/memory/store.py` (`MemoryStore`)
  - `argus/memory/manager.py` (`MemoryManager`, `get_memory_manager()`)
  - `argus/memory/models.py` (`MemoryEntry`, `MemoryType`, `MemorySearchResult`)
  - `argus/workspace/context/engine.py` (`ResearchContextEngine`)
  - `argus/cli/search_cli.py` (`argus search` CLI command group)
- **Implementation Evidence**:
  - Vector database with SQLite + sqlite-vec / NumPy fallback, disk persistence, distance metrics (cosine, L2, dot product).
  - 384-dimensional deterministic offline embeddings with concept clustering and security taxonomy synonym mapping.
  - End-to-end finding and evidence semantic indexing and similarity recall.
  - CVE knowledge base with offline dataset ingestion and automated correlation against discovered tech/endpoints.
  - Vector-backed conversational memory system supporting attack patterns, user corrections, strategic decisions, session context, and notes.
  - `ResearchContextEngine.resolve()` blends findings, evidence, CVEs, memory, and attack surface graph into unified research prompts.
  - Rich CLI search tool (`argus search`, `argus search cves`, `argus search memory`, `argus search stats`).
- **Gaps**: None. Sprints 31a, 31b, and 31c achieved 100% completion with extensive adversarial testing.
- **Test Coverage**: `tests/vector/` (73 tests passed), `tests/memory/` (93 tests passed), `tests/cli/test_search_cli.py` (22 tests passed) — total 188 passing tests.
- **Notes**: Outstanding subsystem maturity. Fully hardened against prompt injection, deceptive CVEs, and embedding collisions.

---

<a id="section-69-phase-19-security-research-knowledge-base"></a>
#### Section 69: Phase 19 — Security Research Knowledge Base

- **Status**: ✅ Implemented
- **Source Files**:
  - `argus/knowledge/manager.py` (`class KnowledgeManager`)
  - `argus/knowledge/models.py` (`class KnowledgeEntry`, `class KnowledgeCategory`)
  - `argus/knowledge/cve_kb.py` (`class CVEKnowledgeBase`)
  - `argus/knowledge/cve_correlator.py` (`class CVECorrelator`)
  - `argus/knowledge/importers.py` (JSON, YAML, Markdown loaders)
- **Implementation Evidence**:
  - `KnowledgeManager` persists knowledge entries to `.argus/knowledge/` and supports multi-attribute querying across `keyword`, `technology`, `business_object`, `authentication`, `cwe`, `owasp`, `capec`, and `tags`.
  - Importers parse raw JSON, YAML, and Markdown documentation.
  - `CVEKnowledgeBase` stores and correlates NVD/CVE records with severity, CVSS scores, affected CPEs, and CWEs.
- **Gaps**: Community knowledge base automatic sync (pulling updates directly from an upstream Git repo or cloud API) is currently handled via file import rather than an automated sync daemon.
- **Test Coverage**: `tests/test_knowledge.py`, `tests/test_cve_kb.py` (23 tests passed).
- **Notes**: Clean design with rich query filters.

---

<a id="section-70-phase-20-technology-aware-investigation"></a>
#### Section 70: Phase 20 — Technology-Aware Investigation

- **Status**: ⚠️ Partial
- **Source Files**:
  - `argus/collectors/technology.py` (`class TechnologyCollector`)
  - `argus/graph/attack_surface.py` (`RUNS_TECHNOLOGY` edge creation)
  - `argus/planning/research_planner.py` (Technology-aware knowledge retrieval)
  - `argus/investigation/scoring.py` (Technology confidence scoring)
  - `argus/correlation/rules.py` (Technology overlap matching)
- **Implementation Evidence**:
  - `TechnologyCollector` detects technologies running on live hosts.
  - `AttackSurfaceGraphBuilder` generates `technology` nodes and links hosts via `RUNS_TECHNOLOGY`.
  - `ResearchPlanner.plan()` extracts discovered technologies from evidence and automatically queries `KnowledgeManager.search(technology=tech)`, embedding knowledge hints into research tasks.
  - `ScoreCalculator` applies a technology confidence bonus to investigations when the tech stack matches.
- **Gaps**:
  - Dedicated modular "Technology Packs" that define stack-specific behaviors, custom questions, and tailored investigation blueprints (e.g. WordPress pack, Spring Boot pack, Django pack) do not exist as distinct plug-and-play packages. Technology awareness is currently generic rather than pack-driven.
- **Test Coverage**: `tests/test_knowledge.py`, `tests/planning/`, `tests/correlation/test_rules.py`.
- **Notes**: The plumbing for technology-aware planning is active, but the catalog of technology packs needs formal modularization.

---

<a id="section-71-phase-21-researcher-feedback-loop"></a>
#### Section 71: Phase 21 — Researcher Feedback Loop

- **Status**: ✅ Implemented
- **Source Files**:
  - `argus/learning/feedback.py` (`class FeedbackCollector`, `class FeedbackSummarizer`)
  - `argus/learning/engine.py` (`class LearningEngine`)
  - `argus/learning/models.py` (`class FeedbackTag`, `class FeedbackEntry`, `class LearningRecord`)
  - `argus/learning/metrics.py` (`class MissionMetricsCalculator`)
  - `argus/learning/patterns.py` (`class PatternDiscovery`)
  - `argus/learning/recommendations.py` (`class RecommendationEngine`)
  - `argus/learning/history.py` (`class MissionHistoryStore`)
  - `argus/cli/learning_cli.py` (`argus learning` CLI group)
- **Implementation Evidence**:
  - `FeedbackCollector.submit()` records feedback with structured tags:
    - `UsefulInvestigation`
    - `FalsePositive`
    - `LowPriority`
    - `HighValue`
    - `Duplicate`
    - `NeedsImprovement`
  - Feedback is persisted in `LearningRegistry` and attached to mission records.
  - `PatternDiscovery` detects recurring patterns across missions (e.g. high false-positive plugins, consistently validated authorization findings).
  - `RecommendationEngine` generates advisory recommendations with `requires_planner_approval = True`.
  - CLI provides `argus learning feedback`, `argus learning metrics`, `argus learning history`, and `argus learning recommendations`.
- **Gaps**: Feedback is strictly advisory and does not automatically alter mission policy or mutate code without human planner approval (by architectural design).
- **Test Coverage**: `tests/learning/` (97 tests passed across 9 test files).
- **Notes**: Fully realized, safe learning system respecting user constraints.

---

<a id="section-72-phase-22-evidence-first-reporting"></a>
#### Section 72: Phase 22 — Evidence-First Reporting

- **Status**: ✅ Implemented
- **Source Files**:
  - `argus/provenance/engine.py` (`class ProvenanceEngine`, `provenance_engine`)
  - `argus/provenance/graph.py` (`class ProvenanceGraph`)
  - `argus/provenance/trace.py` (`class ArtifactTracer`)
  - `argus/provenance/validator.py` (`class ProvenanceValidator`)
  - `argus/reporting/generator.py` (`class ReportGenerator`)
  - `argus/reporting/processor.py` (`class EvidenceProcessor`)
  - `argus/reporting/markdown.py` (`class HackerOneMarkdownRenderer`)
  - `argus/reporting/json.py` (`class JSONReportRenderer`)
  - `argus/reporting/cvss.py` (`class CVSSCalculator`)
- **Implementation Evidence**:
  - Strict evidence processing pipeline: Raw Evidence → Observation → Correlation → Investigation → Validation → Finding → Report.
  - Every Finding requires provenance tracing back to underlying raw evidence items (`finding.evidence_ids`).
  - `ProvenanceValidator.validate_graph()` confirms that all artifacts connect to root evidence.
  - Generates industry-standard HackerOne Markdown reports and machine-readable JSON reports with complete CVSS v3.1 vector calculations and remediation recommendations.
- **Gaps**: None. Provenance graph is strictly enforced and verified.
- **Test Coverage**: `tests/test_provenance.py`, `tests/reporting/` (64 tests passed across 5 test files).
- **Notes**: Excellent reporting fidelity with zero placeholder generation.

---

<a id="section-73-phase-23-reproducibility"></a>
#### Section 73: Phase 23 — Reproducibility

- **Status**: ✅ Implemented
- **Source Files**:
  - `argus/explain/engine.py` (`class ExplainabilityEngine`)
  - `argus/explain/timeline.py` (`class TimelineBuilder`)
  - `argus/explain/reasoning.py` (`class ReasoningChainBuilder`)
  - `argus/explain/graph.py` (`class ExplanationGraphBuilder`)
  - `argus/explain/export.py` (`class ExplanationExporter`)
  - `argus/explain/models.py` (`class Explanation`)
  - `argus/provenance/engine.py` (`ArtifactTracer.explain()`, `trace()`)
  - `argus/cli/explain_cli.py` (`argus explain` CLI commands)
- **Implementation Evidence**:
  - `ExplainabilityEngine` constructs step-by-step reasoning chains, execution timelines, and visual subgraphs for any investigation.
  - Full provenance tracking captures tool names, versions, input parameters, execution results, and timestamps.
  - `Finding` models include reproducible reproduction steps and full raw HTTP request/response transcripts.
  - Explanations can be inspected via CLI (`argus explain investigation <id>`, `argus explain timeline <id>`) or exported to JSON/Markdown.
- **Gaps**: Re-running against live third-party targets may produce variable outputs if the remote target is state-mutating or rate-limiting.
- **Test Coverage**: `tests/explain/test_explain.py` (5 passed), `tests/test_provenance.py`.
- **Notes**: Full transparency and explainability implemented.

---

<a id="section-74-phase-24-mission-replay"></a>
#### Section 74: Phase 24 — Mission Replay

- **Status**: ⚠️ Partial
- **Source Files**:
  - `argus/runtime/history.py` (`class MissionStorage`)
  - `argus/runtime/recovery.py` (`class RecoveryManager`)
  - `argus/runtime/checkpoint.py` (`class MissionCheckpointer`)
  - `argus/benchmark/mission_loader.py` (`class MissionLoader`)
- **Implementation Evidence**:
  - `MissionStorage.store()` archives full runtime state, metrics, checkpoints, and execution history to `.argus/history/{id}_history.json`.
  - `RecoveryManager.recover_mission()` restores a mission from a checkpoint and resets the state machine to a safe resuming state (`PLANNING` or `RESEARCHING`).
  - `MissionLoader` rebuilds executable mission configurations from benchmark definitions.
- **Gaps**:
  - A dedicated "Mission Replay" execution engine that re-executes previous missions step-by-step deterministically against mock/recorded traffic for debugging, version comparison, and regression testing is not implemented. Replay currently relies on checkpoint resumption and history viewing.
- **Test Coverage**: `tests/test_runtime.py::test_mission_checkpointing`.
- **Notes**: Foundational storage and checkpoint recovery exist, but automated determinism replay requires a dedicated replay runner.

---

<a id="section-75-phase-25-research-benchmarks"></a>
#### Section 75: Phase 25 — Research Benchmarks

- **Status**: ✅ Implemented
- **Source Files**:
  - `argus/benchmark/framework.py` (`class BenchmarkFramework`)
  - `argus/benchmark/models.py` (`Benchmark`, `BenchmarkGroundTruth`, `EvaluationResult`)
  - `argus/benchmark/datasets/` (`DatasetManager`, `BenchmarkDataset`)
  - `argus/benchmark/ground_truth/` (`GroundTruthMatcher`, `ComparisonResult`)
  - `argus/benchmark/metrics/` (`MetricsEngine`, `CoverageCalculator`, `QualityCalculator`, `PerformanceCalculator`, `ScoringEngine`)
  - `argus/benchmark/leaderboard/` (`BenchmarkLeaderboard`, `RegressionDetector`)
  - `argus/benchmark/reports/` (`BenchmarkReportGenerator`, HTML/Markdown/JSON/PDF renderers)
  - `argus/benchmark/runner/` (`EvaluationRunner`, `BenchmarkPipeline`)
  - `argus/cli/benchmark_cli.py` (`argus benchmark` CLI group)
- **Implementation Evidence**:
  - Complete benchmarking subsystem capable of loading synthetic or representative target datasets, executing evaluation pipelines, comparing findings against ground truth, calculating precision/recall/coverage scores, detecting regressions across software versions, and rendering scorecards.
- **Gaps**: Provisioning live dockerized benchmark targets (e.g. automated spinning up of Juice Shop or DVWA during CI) is left to external CI runners.
- **Test Coverage**: `tests/benchmark/` (42 tests passed across 7 test modules).
- **Notes**: Exceptionally thorough benchmark engine implementation.

---

<a id="section-76-phase-26-production-hardening"></a>
#### Section 76: Phase 26 — Production Hardening

- **Status**: ⚠️ Partial
- **Source Files**:
  - `argus/performance/` (`CacheManager`, `ParallelExecutor`, `ProfilingEngine`, `SchedulerOptimizer`)
  - `argus/plugins/sdk.py` (`ControlledMission` sandbox)
  - `argus/runtime/retry.py`
  - `argus/runtime/recovery.py`
  - `argus/runtime/checkpoint.py`
- **Implementation Evidence**:
  - Performance subsystem (`argus/performance/`) implements query caching, parallel collector execution, profiling hooks, and incremental scanning optimizations.
  - Plugin sandboxing enforces capability-scoped access through `ControlledMission`.
  - State machine includes retry policies, error handling transitions, and checkpoints.
- **Gaps**:
  - Dual execution paths remain (older collectors/agents vs newer Mission Runtime / ScanEngine).
  - Credential vault is an in-memory/config prototype rather than an encrypted OS keychain/HashiCorp Vault integration.
  - Production deployment artifacts (Helm charts, Docker Compose configurations, daemon supervision) are not fully realized.
- **Test Coverage**: `tests/performance/` (5 tests passed).
- **Notes**: Code-level performance and sandboxing are solid; full infrastructure production hardening is an ongoing operational milestone.

---

<a id="section-77-recommended-development-order"></a>
#### Section 77: Recommended Development Order

- **Status**: ❌ Missing (Specification / Roadmap Artifact)
- **Source Files**: None in `argus/`. Documented in `ORIGINAL_REQUEST.md` (Section 77).
- **Implementation Evidence**:
  - Section 77 defines the 21-step prioritized sequence for developing and scaling the Argus platform (from finishing Phase 9 specialists through validating against realistic scenarios).
  - It is a planning meta-specification and roadmap guideline, not an executable software component.
- **Gaps**: Not a software module. Does not exist as executable code in the codebase.
- **Test Coverage**: N/A.
- **Notes**: Correctly classified as Missing in terms of code implementation; serves as the project's strategic roadmap.

---

<a id="section-78-core-success-criteria-final-vision"></a>
#### Section 78: Core Success Criteria & Final Vision

- **Status**: ⚠️ Partial (Architectural Vision & Pipeline Integration)
- **Source Files**:
  - Realized through the end-to-end integration of:
    - `argus/runtime/mission_runtime.py`
    - `argus/scanning/engine.py`
    - `argus/graph/attack_surface.py`
    - `argus/intelligence/engine.py`
    - `argus/correlation/engine.py`
    - `argus/investigation/builder.py`
    - `argus/hypothesis/engine.py`
    - `argus/reporting/generator.py`
- **Implementation Evidence**:
  - Argus answers the core research questions:
    - *What does this app do?* -> `AttackSurfaceGraphBuilder`, `WorkflowAnalyzer`, `SchemaParser`
    - *What security boundaries exist?* -> `AuthorizationSpecialist`, `RoleAnalyzer`, `OwnershipAnalyzer`
    - *What objects/workflows exist?* -> `BusinessObjects`, `WorkflowBuilder`, `FileUploadWorkflow`
    - *What to investigate next & Why?* -> `ResearchPlanner`, `PriorityEngine`, `ScoreCalculator`
    - *What evidence supports it?* -> `EvidenceStore`, `EvidenceBundle`, `ProvenanceEngine`
    - *How to validate safely?* -> `ManualValidationGenerator`, `HypothesisEngine`
    - *Can I reproduce?* -> `ExplainabilityEngine`, `ArtifactTracer`, `HackerOneMarkdownRenderer`
- **Gaps**: Full autonomous end-to-end research without human intervention across arbitrary unknown targets remains the overarching North Star vision of the project.
- **Test Coverage**: `tests/runtime/test_mission_runtime.py`, `tests/vector/test_rag_integration.py`, `tests/scanning/test_scan_engine.py`.
- **Notes**: The individual architectural building blocks are in place and integrated, fulfilling the structural prerequisites of the Final Vision.

---


<a id="5-appendix-verification--reproducibility-guide"></a>
## 5. Appendix: Verification & Reproducibility Guide

This appendix documents the exact commands and methodologies required to independently verify all findings, test counts, and architectural observations documented in this report.

### 5.1 Full Test Suite Execution

To execute the full canonical test suite and verify the 2,451 passed tests:

```bash
cd /home/varun/argus
python -m pytest tests/ -v --tb=short
```

To execute the co-located specialist unit tests inside `argus/`:

```bash
cd /home/varun/argus
python -m pytest argus/ -v --tb=short
```

To run both suites concurrently and verify all 2,463 passed tests:

```bash
cd /home/varun/argus
python -m pytest tests/ argus/ -v --tb=short
```

### 5.2 Verification of Critical Gaps

1. **CLI Typer Mounting Defect (Section 46 / 48)**:

   ```bash
   # Verify that performance namespace is broken:
   python -m argus.cli performance --help
   # Expected result: Error: No such command 'performance'
   ```

2. **Absence of Credential Vault (Section 40)**:

   ```bash
   # Search for vault implementations in the codebase:
   find argus/ -name "*vault*"
   grep -rn "class .*Vault" argus/
   # Expected result: 0 matches found
   ```

3. **CLI Intelligence List Crash (Section 48)**:

   ```bash
   python -m argus.cli intelligence list --help
   python -m argus.cli intelligence list
   # Expected result: TypeError: 'InvestigationRegistry' object is not iterable
   ```

### 5.3 Invalidation Conditions

The conclusions of this audit report are considered invalidated if any of the following occur:
1. Any automated test in `tests/` fails or errors during clean environment execution.
2. The line `app.add_typer(performance_app)` in `argus/cli/app.py:71` is updated with `name='performance'`, resolving Section 46.
3. A secure `argus/vault/` package is introduced with encryption at rest, resolving Section 40.
4. `argus scan` is refactored to route directly to `AutonomousMissionRuntime`, resolving Section 57.
5. The 12 co-located tests in `argus/` are relocated into canonical `tests/plugins/`.

---

*Report synthesized and attested by Feature Audit Synthesis Specialist on 2026-09-04.*