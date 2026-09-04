# Milestone M4 Handoff Report: CLI Entry Point & Scan Command

**Author**: Worker M4 (CLI & Scan Command Specialist)  
**Date**: 2026-09-02  
**Milestone**: M4 — CLI Entry Point & Scan Command (Sprint 30: Scanner Glue)  

---

## 1. Observation

1. **Missing Module Entry Point (`argus/__main__.py`)**:
   - `argus/cli/__main__.py` previously existed, enabling `python -m argus.cli`.
   - However, invoking `python -m argus` resulted in `No module named argus.__main__; 'argus' is a package and cannot be directly executed`.
2. **ScanDAG Profile Filtering (`argus/scanning/dag.py`)**:
   - `ScanDAG` previously loaded all 26 tasks from `_RECON_TEMPLATES` without a built-in mechanism to instantiate filtered profiles (`full`, `recon`, `vuln`, `quick`).
3. **Missing `scan` CLI Command (`argus/cli/app.py`)**:
   - `argus/cli/app.py` defined top-level commands `execute`, `trace`, `version`, but lacked a unified top-level `scan` command invoking the full `ScanEngine` DAG pipeline with Rich formatting, progress spinners, summary tables, severity breakdown panels, and report file links.
4. **Missing Test Coverage (`tests/test_cli_scan.py`)**:
   - No dedicated test suite existed to test `python -m argus` or `typer.testing.CliRunner` invocations of the `scan` command across profile variants, custom output directories, scopes, and error exits.

---

## 2. Logic Chain

1. **Module Entrypoint Implementation (`argus/__main__.py`)**:
   - Created `argus/__main__.py` importing `app` from `argus.cli.app` and running `app()`.
   - Allows direct execution via `python -m argus`.
2. **DAG Profile Support (`argus/scanning/dag.py`)**:
   - Added classmethod `ScanDAG.create_for_profile(profile_name)` and alias `ScanDAG.from_profile`:
     - `"full"` / `"all"`: All 26 reconnaissance and vulnerability detection tasks.
     - `"recon"` / `"reconnaissance"`: 5 reconnaissance tasks (`subfinder`, `httpx`, `katana_crawler`, `nuclei`, `info_disclosure`).
     - `"vuln"` / `"vulnerability"`: 21 vulnerability tasks.
     - `"quick"` / `"fast"`: Recon tasks + high-priority vulnerability tasks (e.g. `sql_injection`, `xss`, `auth_bypass`, `access_control`, `ssrf`, `command_injection`, `cors_security`, `cache_security`).
   - Kahn's topological sort dynamically evaluates dependencies based only on tasks present in `self._tasks`, ensuring filtered profiles sort deterministically without cycle or missing dependency exceptions.
3. **Scan CLI Command Implementation (`argus/cli/app.py`)**:
   - Added `@app.command("scan")` with parameters:
     - `target: str` (required positional argument with empty/whitespace validation)
     - `--profile`, `-p`: `full`, `recon`, `vuln`, `quick` (default: `"full"`)
     - `--output`, `-o`, `--output-dir`: output directory for reports (default: `None` -> `.argus/reports`)
     - `--threads`, `-t`: worker concurrency (default: `10`)
     - `--timeout`: scan timeout in seconds (default: `None`)
     - `--scope`, `-s`: additional in-scope domains/CIDRs (Optional[List[str]])
     - `--workspace`, `-w`: workspace identifier (default: `"default"`)
     - `--format`, `-f`: report format (`both`, `markdown`, `json`, default: `"both"`)
     - `--verbose`, `-v`: enable debug logging
   - Rich UI features:
     - Header Panel with Target, Profile, Workspace, Output directory.
     - Mission creation and registration in `mission_manager._active_missions[mission.id]`.
     - `console.status` spinner while `ScanEngine(dag=dag, output_dir=output_dir).run(mission)` executes.
     - Collector Execution Table showing Task/Collector name, Phase, Status (COMPLETED in green, SKIPPED in yellow, FAILED in red), Evidence count, and Duration (s).
     - Vulnerability Severity Breakdown Panel (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`).
     - Generated Reports file path list (Markdown and JSON).
     - Summary footer with Scan ID, Duration, Total Evidence, and Final Status.
     - Exit code `0` on success, `1` on failure / exception (`raise typer.Exit(code=1)`).
4. **Comprehensive Test Suite (`tests/test_cli_scan.py`)**:
   - Implemented 16 test cases covering:
     - CLI help, version, and scan help.
     - `ScanDAG.create_for_profile` across all profiles.
     - Default profile scan execution with mock `ScanEngine.run`.
     - Parameterized profile runs (`recon`, `vuln`, `quick`, `full`).
     - Additional scope appending and workspace identification.
     - Report format filtering (`markdown`, `json`, `both`).
     - Target validation and error exit code 1.
     - Engine failure status and engine exception handling.
     - End-to-end execution with real report generation on disk in custom temp directories.
     - Subprocess execution of `python -m argus version`.

---

## 3. Caveats

- In test environments, tests isolate external Go network binaries and network calls to ensure fast, deterministic CI execution while testing genuine data flow, report creation on disk, and CLI output rendering.
- No files outside the exclusive write boundaries were modified.

---

## 4. Conclusion

Milestone M4 is 100% complete and fully verified:
- `argus/__main__.py` created and operational.
- `argus/scanning/dag.py` enhanced with profile support.
- `argus/cli/app.py` equipped with `@app.command("scan")`.
- `tests/test_cli_scan.py` created with 16 passing tests.
- Full workspace test suite passed: **2,102 passed, 0 failures, 0 regressions** (exceeding the 2,086+ requirement).

---

## 5. Verification Method

To independently verify this milestone:

1. **Run CLI Scan Test Suite**:
   ```bash
   python -m pytest tests/test_cli_scan.py -v
   ```
   *Expected*: 16 passed, 0 failed.

2. **Run Full Test Suite Victory Audit**:
   ```bash
   python -m pytest tests/ --ignore=tests/workspace -x -q
   ```
   *Expected*: 2,102 passed, 0 failed.

3. **CLI Direct Invocation Checks**:
   ```bash
   python -m argus --help
   python -m argus version
   python -m argus scan --help
   ```
