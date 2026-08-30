# ARGUS Sprint Handoff — Sprint 14 (Reporting Engine)

> **This file is self-contained.** A new agent with zero prior context can execute the next sprint from this file alone.
> **Instructions for user:** Open a new conversation and say:
> `Read /home/varun/argus/.agents/sprint_handoff.md and launch the sprint`

---

## Current State of ARGUS

**Test baseline:** 1,196 passing tests (`python -m pytest tests/ --ignore=tests/workspace -x -q`)
**Working directory:** `/home/varun/argus`
**Integrity mode:** benchmark (all sprints use this)

---

## Completed Sprints Summary

| Sprint | Engine | Tests After | Key Files Created |
|--------|--------|:-----------:|-------------------|
| 0–3 | Mission Loop, DAG, Attack Surface Graph, Graph-Aware Reasoning | 578 | `argus/runtime/mission.py`, `argus/graph/attack_surface.py`, `argus/planning/task_generator.py` |
| 4 | CNAME Takeover + Auth Foundation (TestIdentity, AuthenticatedHttpClient) | 646 | `argus/models/test_identity.py`, `argus/http/client.py`, `argus/collectors/takeover.py` |
| 5 | Information Disclosure (`.env`, `.git`, actuator fuzzing, secret extraction) | 701 | `argus/collectors/information_disclosure.py` |
| 6 | Access Control / IDOR (Multi-Identity Sessions, Response Discrepancy Analyzer) | 749 | `argus/collectors/access_control.py`, `argus/http/coordinator.py`, `argus/analyzers/response_discrepancy.py` |
| 8 | Path Traversal (payload mutations, OS file signatures) | 861 | `argus/collectors/path_traversal.py` |
| 9 | SQL Injection (error-based, boolean-blind, time-blind, WAF bypass) | 896 | `argus/collectors/sql_injection.py` |
| 10 | XSS (reflected, stored, context-aware) + Environment Detector | 996 | `argus/collectors/xss.py`, `argus/utils/environment.py` |
| 11 | Command Injection (result-based, time-blind, separator mutations) | 1,071 | `argus/collectors/command_injection.py` |
| 12 | SSRF (cloud metadata AWS/GCP/Azure, internal service banners, 9 bypass strategies) | 1,127 | `argus/collectors/ssrf.py` |
| 13 | OAuth/OIDC (JWT alg:none, key confusion, redirect_uri, CSRF state, session security) | 1,196 | `argus/collectors/oauth.py` |

---

## Remaining Roadmap

| Sprint | Engine | Priority | Covers (User Checklist) |
|--------|--------|:--------:|-------------------------|
| **14 (NEXT)** | **Reporting Engine** | 🔴 HIGH | Produce structured vulnerability report |
| 15 | XXE Injection | 🟡 MEDIUM | XML external entity injection |
| 16 | Deserialization | 🟡 MEDIUM | Insecure deserialization (Java, Python pickle) |
| 17 | GraphQL Security | 🟡 MEDIUM | Introspection, batching, DoS |
| 18 | WebSocket Security | 🟡 MEDIUM | WS origin bypass, message tampering |
| 19 | HTTP Request Smuggling | 🟠 HIGH | CL.TE, TE.CL variants |
| 20 | Race Conditions | 🟡 MEDIUM | TOCTOU, parallel request limit bypasses |

---

## Key Architecture Patterns (for the new agent)

- **Collectors** follow the pattern in `argus/collectors/oauth.py` or `argus/collectors/sql_injection.py`
- **Registration:** add to `argus/runtime/registry.py` AND `argus/runtime/plugins.py`
- **DAG scheduling:** add template to `_RECON_TEMPLATES` in `argus/planning/task_generator.py`
- **Graph edges:** create `HAS_VULNERABILITY` edges via `argus/graph/attack_surface.py`
- **Evidence:** use `EvidenceStore` (at `argus/evidence/store.py`) to store findings
- **AuthenticatedHttpClient** in `argus/http/client.py` enforces scope boundaries — test scripts MUST set `mission.scope` correctly

## Orchestration Rules

Read `/home/varun/argus/.agents/rules/user_global.md` before starting. Key rules:
- **ZERO intermediate messages** — subagents ONLY message on task completion or unrecoverable blocker
- **Post-sprint verification** — run test suite + functional mock test + DAG/registry connectivity check
- **Update this file** with the Sprint 15 prompt after Sprint 14 completes

---

## Sprint 14 Prompt (Ready to Launch)

```
Build the Vulnerability Reporting Engine for the ARGUS autonomous security research platform.
This module aggregates all Evidence from the EvidenceStore and KnowledgeGraph and renders
structured, actionable vulnerability reports in multiple formats.

Working directory: /home/varun/argus
Integrity mode: benchmark

## Requirements

### R1. Report Generator
Implement a ReportGenerator that reads all Evidence from a completed mission's EvidenceStore
and produces structured vulnerability reports. The generator must:
1. Deduplicate findings (same vulnerability class, same URL, same parameter = one finding)
2. Severity-sort findings (critical → high → medium → low → informational)
3. Group findings by vulnerability category and by target host

### R2. Output Formats
The generator must support at minimum two output formats:
1. HackerOne-style Markdown: title, severity, CVSS score (computed from severity), summary,
   steps to reproduce (from Evidence metadata), impact, remediation advice
2. JSON: machine-readable structured output suitable for pipeline consumption

### R3. CVSS Scoring
For each finding, compute an approximate CVSS v3.1 base score from the Evidence severity
and category. Use standard mappings: critical→9.0–10.0, high→7.0–8.9, medium→4.0–6.9,
low→0.1–3.9. Include the score and vector string in the report.

### R4. Pipeline Connectivity
Wire the ReportGenerator so it runs automatically at mission completion (after all collectors
finish). Store the generated report paths in the mission state. Register any needed hooks
in the mission lifecycle.

### R5. Zero Regression & E2E Validation
All 1,196+ currently passing tests must continue to pass. Write at least 15 new tests covering
deduplication logic, severity sorting, both output formats, and CVSS score computation.
Write a handoff report to .agents/sprint14_reporting/handoff.md.

## Acceptance Criteria

### Report Generation
- [ ] Given a mission with 5 Evidence items (2 critical SQLi, 1 high XSS, 2 medium info disclosure),
  the generator produces a report with findings deduplicated, sorted by severity.
- [ ] HackerOne markdown output contains: title, severity badge, CVSS score, steps to reproduce,
  impact, and remediation sections.
- [ ] JSON output is valid JSON with a findings array containing all required fields.

### CVSS
- [ ] A critical-severity finding maps to a CVSS base score >= 9.0.
- [ ] A medium-severity finding maps to a CVSS base score between 4.0 and 6.9.

### Pipeline
- [ ] ReportGenerator runs automatically at mission completion.
- [ ] Report file paths are stored in mission state.

### Regression
- [ ] python -m pytest tests/ --ignore=tests/workspace -x -q exits 0 (1,196+ passing, 0 regressions).
- [ ] At least 15 new tests added.
- [ ] Handoff written to .agents/sprint14_reporting/handoff.md.
```

---

## Instructions for the New Agent

1. Read `/home/varun/argus/.agents/rules/user_global.md` for orchestration rules
2. Launch the Sprint 14 prompt above using `invoke_subagent` with `TypeName: teamwork_preview`
3. Wait silently for the ONLY message (final completion report) — no polling, no intermediate checks
4. On completion, independently verify: run test suite + functional test + pipeline connectivity
5. After verification, update THIS FILE (`/home/varun/argus/.agents/sprint_handoff.md`) with the Sprint 15 prompt and tell the user to open a new conversation
