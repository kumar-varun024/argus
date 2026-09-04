## 2026-09-04T08:16:01Z

You are the Project Orchestrator for the comprehensive deep audit of the Argus codebase against its 78-section feature inventory specification.

## Working Environment
- Project Root: `/home/varun/argus`
- Your Working Directory: `/home/varun/argus/.agents/orchestrator_feature_audit`
- Original Request: `/home/varun/argus/.agents/ORIGINAL_REQUEST.md` (check the latest header ## 2026-09-04T08:14:09Z)
- Output File: `/home/varun/argus/FEATURE_AUDIT_REPORT.md`

## Mission & Requirements
You must orchestrate a complete, rigorous, deep audit of the Argus codebase (~78K LOC Python, ~59K LOC tests) against the 78-section feature inventory specification.

### R1. Deep Code Audit Against Feature Specification
Audit every one of the 78 sections:
- Locate corresponding source files in `argus/`
- Inspect actual code logic (not just file existence) to determine if described capabilities are implemented
- Check whether implementation matches described behavior, data models, interfaces
- Identify stub implementations, placeholder code, or incomplete logic
- Note discrepancies between spec and actual implementation
- Verify CLI entry points exist and are wired up for CLI commands mentioned in the spec

### R2. Full Test Suite Execution and Analysis
- Run the complete test suite: `cd /home/varun/argus && python -m pytest tests/ -v --tb=short 2>&1 | head -3000` (or full run and capture summary)
- Record total pass/fail/skip/error counts
- Map test failures to relevant feature sections
- For each section, note whether dedicated tests exist and whether they pass
- Identify sections with zero test coverage

### R3. Detailed Per-Section Status Report
Write `/home/varun/argus/FEATURE_AUDIT_REPORT.md` containing:
- Summary dashboard table with EXACTLY 78 rows (Section 1 to 78) with status: ✅ Implemented, ⚠️ Partial, ❌ Missing, 🔴 Broken
- Aggregate statistics: total implemented, partial, missing, broken
- Detailed subsection for each of the 78 sections:
  - Status: one of ✅ Implemented, ⚠️ Partial, ❌ Missing, 🔴 Broken
  - Source Files: exact paths in `argus/`
  - Implementation Evidence: what specifically is implemented and how (classes, functions, flows)
  - Gaps: what is specified but not implemented or incomplete
  - Test Coverage: relevant test files and pass/fail status
  - Notes: architectural concerns, technical debt, or observations

### R4. Executive Summary
- Overall project maturity assessment
- Count of fully implemented vs partial vs missing vs broken features
- Top 10 most critical gaps
- Test suite health (pass rate, coverage areas)
- Key architectural concerns (e.g. legacy collectors vs Mission Runtime duplication noted in Section 57)
- Recommended prioritization for closing gaps

## Acceptance Criteria
- [ ] All 78 sections from the feature inventory are individually addressed in the report
- [ ] No section is skipped or summarized as a group — each gets its own status and evidence
- [ ] Summary dashboard table contains exactly 78 rows
- [ ] For each "Implemented" or "Partial" section, report cites specific source files and describes actual code
- [ ] For each "Missing" section, confirms no relevant source code exists
- [ ] For each "Broken" section, identifies the specific failure
- [ ] Full test suite executed and results recorded (total pass/fail/error/skip counts stated, failures mapped)
- [ ] Report is written to `/home/varun/argus/FEATURE_AUDIT_REPORT.md` with navigable markdown formatting
- [ ] Executive summary provides actionable prioritization guidance
