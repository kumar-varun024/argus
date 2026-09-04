# DISPATCH — Test Suite Runner & Coverage Specialist

## Working Directory
`/home/varun/argus/.agents/audit_test_runner`

## Task
1. Execute the full test suite:
   `cd /home/varun/argus && python -m pytest tests/ -v --tb=short 2>&1`
   Capture the complete summary (total passed, failed, error, skipped, duration).
   Also run `python -m pytest tests/ --collect-only -q` to get total test counts if full run has truncations or issues.
2. If there are any test failures or errors, record each failing test name, location, error trace, and map it to the corresponding feature area in `argus/`.
3. Inventory all test directories/files in `tests/` and map them to `argus/` packages.
4. Identify which packages/modules in `argus/` have zero or minimal test coverage.
5. Write your comprehensive report to `/home/varun/argus/.agents/audit_test_runner/handoff.md`.

## 2026-09-04T08:18:11Z
You are the Test Suite Runner & Coverage Specialist.
Working directory: /home/varun/argus/.agents/audit_test_runner
Read /home/varun/argus/.agents/ORIGINAL_REQUEST.md (specifically the latest section ## 2026-09-04T08:14:09Z and requirement R2).
Also read /home/varun/argus/.agents/audit_test_runner/DISPATCH.md.

TASK:
1. Run the test suite: `cd /home/varun/argus && python -m pytest tests/ -v --tb=short 2>&1` (or run in logical test directories if full output is too long, and capture the exact final totals). Also verify test collection count with `python -m pytest tests/ --collect-only -q`.
2. Record total pass/fail/skip/error/xfail counts and run duration.
3. Map any test failures or errors to the corresponding feature sections (1-78). Detail exact failure traces and root causes.
4. Inventory all test suites in `tests/` and map them to `argus/` packages.
5. Identify any modules or feature areas in `argus/` with ZERO test coverage.
6. Write your comprehensive report to `/home/varun/argus/.agents/audit_test_runner/handoff.md`.
7. Follow the communication hygiene protocol: operate silently without intermediate status pings. When 100% finished, send a message to parent with the final metrics and handoff.md path.
