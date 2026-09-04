# Subagent Prompt Drafts

## 1. Test Suite Runner & Coverage Specialist
- **Agent Type**: `teamwork_preview_worker`
- **Role**: Test Suite Specialist
- **Working Directory**: `/home/varun/argus/.agents/audit_test_runner/`
- **Prompt Details**:
  - Run full test suite: `python -m pytest tests/ -v --tb=short 2>&1` (or in batches/full run as needed to avoid timeout).
  - Also run `python -m pytest tests/ --collect-only -q` to get total test collection count.
  - Summarize total tests, passed, failed, errors, skipped, duration.
  - Detail every failing test or test error, the exact test file, test function name, error message, and which feature area it belongs to.
  - List all test files under `tests/` and map them to their corresponding source domains in `argus/`.
  - Identify which areas of `argus/` have zero test files or low test coverage.
  - Output complete findings to `/home/varun/argus/.agents/audit_test_runner/handoff.md`.

## 2. Cluster 1 Explorer (Sections 1–15)
- **Agent Type**: `teamwork_preview_explorer`
- **Role**: Cluster 1 Auditor (Core Architecture & Runtime)
- **Working Directory**: `/home/varun/argus/.agents/audit_cluster1/`
- **Sections**:
  - 1: Project Identity
  - 2: Core Architecture
  - 3: Mission
  - 4: Scope Manager
  - 5: Policy Engine
  - 6: Mission Runtime
  - 7: Tool Registry
  - 8: Tool Dispatcher
  - 9: Tool Orchestrator
  - 10: Event Bus
  - 11: Scheduler
  - 12: Research Task Model
  - 13: Research Planning
  - 14: Gap Analysis Engine
  - 15: Coverage Tracker
- **Instructions**:
  - Deeply inspect code under `argus/core/`, `argus/policy/`, `argus/runtime/`, `argus/planning/`, `argus/analysis/`, `argus/coverage/`, `argus/events/`, etc.
  - For each of the 15 sections, examine actual code logic, classes, methods, data models, stubs/placeholders.
  - Determine status: ✅ Implemented, ⚠️ Partial, ❌ Missing, 🔴 Broken.
  - Document Source Files, Implementation Evidence, Gaps, Test Coverage, Notes.
  - Output to `/home/varun/argus/.agents/audit_cluster1/handoff.md`.

## 3. Cluster 2 Explorer (Sections 16–25)
- **Agent Type**: `teamwork_preview_explorer`
- **Role**: Cluster 2 Auditor (Recon, Evidence & Knowledge)
- **Working Directory**: `/home/varun/argus/.agents/audit_cluster2/`
- **Sections**:
  - 16: Reconnaissance
  - 17: Recon Parser
  - 18: Nuclei Integration
  - 19: Evidence Store
  - 20: Provenance Engine
  - 21: Observations & Correlations
  - 22: Knowledge Graph
  - 23: Workflow Intelligence
  - 24: Authorization Graph
  - 25: Business Objects
- **Instructions**:
  - Inspect code in `argus/recon/`, `argus/evidence/`, `argus/provenance/`, `argus/observation/`, `argus/correlation/`, `argus/graph/`, `argus/workflow/`, `argus/authz/` / `argus/authorization/`, `argus/objects/`, `argus/business/`, etc.
  - For each of the 10 sections, examine actual code logic, classes, methods, CLI commands (e.g. `argus trace`, `argus observations`, `argus correlations`, `argus evidence`).
  - Output to `/home/varun/argus/.agents/audit_cluster2/handoff.md`.

## 4. Cluster 3 Explorer (Sections 26–37)
- **Agent Type**: `teamwork_preview_explorer`
- **Role**: Cluster 3 Auditor (AI, RAG Fabric & Specialists)
- **Working Directory**: `/home/varun/argus/.agents/audit_cluster3/`
- **Sections**:
  - 26: AI Research
  - 27: Security Research RAG / Intelligence Fabric (Subsections 27.1–27.16)
  - 28: Research Cards
  - 29: Vulnerability Intelligence Engine
  - 30: Methodology Engine
  - 31: Authorization Specialist
  - 32: Business Logic Specialist
  - 33: API Intelligence Specialist
  - 34: GraphQL Specialist
  - 35: JavaScript Intelligence
  - 36: Authentication Specialist
  - 37: File Upload Specialist
- **Instructions**:
  - Inspect code in `argus/ai/`, `argus/vector/`, `argus/rag/`, `argus/cards/`, `argus/intelligence/`, `argus/methodology/`, `argus/specialists/`, `argus/api/`, `argus/graphql/`, `argus/js/` / `argus/javascript/`, `argus/auth/`, `argus/upload/`, etc.
  - For Section 27, address all 16 subsections (27.1-27.16) in detail.
  - Check CLI commands: `argus api ...`, `argus graphql`, `argus javascript`.
  - Output to `/home/varun/argus/.agents/audit_cluster3/handoff.md`.

## 5. Cluster 4 Explorer (Sections 38–48)
- **Agent Type**: `teamwork_preview_explorer`
- **Role**: Cluster 4 Auditor (Platform & CLI Surface)
- **Working Directory**: `/home/varun/argus/.agents/audit_cluster4/`
- **Sections**:
  - 38: Plugin SDK
  - 39: Controlled Plugin Execution
  - 40: Credential Vault
  - 41: Session Manager
  - 42: HTTP Engine
  - 43: Rules Engine
  - 44: Configuration
  - 45: Observability
  - 46: Performance
  - 47: Workspace
  - 48: CLI Surface (Verify all 32+ namespaces listed in Section 48)
- **Instructions**:
  - Inspect code in `argus/plugins/`, `argus/vault/`, `argus/session/`, `argus/http/`, `argus/rules/`, `argus/config/`, `argus/observability/`, `argus/telemetry/`, `argus/perf/`, `argus/workspace/`, `argus/cli/`, `argus/cli/app.py`.
  - Check CLI subcommands registration and whether commands work or stub out.
  - Output to `/home/varun/argus/.agents/audit_cluster4/handoff.md`.

## 6. Cluster 5 Explorer (Sections 49–57)
- **Agent Type**: `teamwork_preview_explorer`
- **Role**: Cluster 5 Auditor (Lifecycle, Health & Architecture)
- **Working Directory**: `/home/varun/argus/.agents/audit_cluster5/`
- **Sections**:
  - 49: Planning → Validation → Report Lifecycle
  - 50: Investigation Philosophy
  - 51: Reporting
  - 52: Explainability
  - 53: Learning
  - 54: Benchmarking
  - 55: Testing
  - 56: Current External Tool Environment
  - 57: Architectural Cleanup (Dual Execution Paths / Collectors vs Mission Runtime)
- **Instructions**:
  - Inspect `argus/reporting/`, `argus/investigation/`, `argus/explain/`, `argus/learning/`, `argus/benchmark/`, `argus/runtime/`, `argus/collectors/`, `tests/`.
  - Deep dive on Section 57: exact nature of duplication between older collectors and newer Mission Runtime, what needs unifying.
  - Output to `/home/varun/argus/.agents/audit_cluster5/handoff.md`.

## 7. Cluster 6 Explorer (Sections 58–78)
- **Agent Type**: `teamwork_preview_explorer`
- **Role**: Cluster 6 Auditor (Roadmap & Vision Phases)
- **Working Directory**: `/home/varun/argus/.agents/audit_cluster6/`
- **Sections**:
  - 58 to 78 (Roadmap Phases 9 through 26, plus Development Order & Vision)
- **Instructions**:
  - Audit sections 58 through 78 individually against the codebase.
  - For each, determine if code exists, if it is partially implemented, if it is an unstarted roadmap phase, or if any parts are broken.
  - Provide specific code references or verify absence.
  - Output to `/home/varun/argus/.agents/audit_cluster6/handoff.md`.
