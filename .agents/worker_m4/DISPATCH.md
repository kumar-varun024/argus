## 2026-09-02T17:59:59Z

You are Worker M4: CLI & Scan Command Specialist.
Working directory: /home/varun/argus/.agents/worker_m4

Read /home/varun/argus/.agents/ORIGINAL_REQUEST.md and /home/varun/argus/PROJECT.md before starting work.

MANDATORY INTEGRITY WARNING:
DO NOT CHEAT. All implementations must be genuine. DO NOT hardcode test results, create dummy/facade implementations, or circumvent the intended task. An auditor will independently verify your work. Integrity violations WILL be detected and your work WILL be rejected.

Your Exclusive Write Boundaries (DO NOT touch files outside this list):
- `argus/__main__.py`
- `argus/cli/app.py`
- `argus/scanning/dag.py`
- `tests/test_cli_scan.py`

Detailed Tasks:
1. Create `argus/__main__.py`:
   - Enables direct execution via `python -m argus`.
   - Imports `app` from `argus.cli.app` and runs `app()`.
2. Enhance `argus/scanning/dag.py` (if needed):
   - Add helper `ScanDAG.create_for_profile(profile_name)` or filter tasks based on profile: `"full"` (all 26 tasks), `"recon"` (recon phase only), `"vuln"` (vulnerability phase only), `"quick"` (recon + high-priority vulnerability tasks).
3. Implement `@app.command("scan")` in `argus/cli/app.py`:
   - Typer options:
     - `target: str = typer.Argument(..., help="Target URL, domain, or IP address to scan.")`
     - `--profile`, `-p`: scan profile (`full`, `recon`, `vuln`, `quick`, default: `"full"`)
     - `--output`, `-o`, `--output-dir`: output directory for reports (default: `None` -> `.argus/reports`)
     - `--threads`, `-t`: worker threads / concurrency (default: `10`)
     - `--timeout`: scan timeout in seconds (default: `None`)
     - `--scope`, `-s`: additional in-scope domains/CIDRs (Optional[List[str]])
     - `--workspace`, `-w`: workspace identifier (default: `"default"`)
     - `--format`, `-f`: report format (`both`, `markdown`, `json`, default: `"both"`)
     - `--verbose`, `-v`: verbose execution logs (default: `False`)
   - Rich UI display:
     - Banner Panel with Target, Profile, Workspace, Output dir.
     - Creates `Mission(target=target, workspace=workspace)` and appends any extra scope.
     - Registers mission in `mission_manager._active_missions[mission.id] = mission`.
     - Executes `ScanEngine(dag=dag, output_dir=output_dir).run(mission)` with Rich spinner/status.
     - Displays Rich Collector Execution Table showing Task/Collector name, Phase, Status (COMPLETED [green], SKIPPED [yellow], FAILED [red]), Evidence count, and Duration (s).
     - Displays Vulnerability Severity Summary Panel (CRITICAL, HIGH, MEDIUM, LOW, INFO counts).
     - Displays Generated Reports list with paths to Markdown (.md) and JSON (.json) files.
     - Exits with code `0` on success, `1` on failure (`raise typer.Exit(code=1)`).
4. Write comprehensive tests in `tests/test_cli_scan.py` using `typer.testing.CliRunner`:
   - Test `python -m argus` / `app` help, version, and scan help.
   - Test `argus scan <target>` default profile execution and successful exit code 0.
   - Test profiles: `--profile recon`, `--profile vuln`, `--profile quick`.
   - Test custom `--output` directory and report generation verification on disk.
   - Test `--scope` option appending additional scopes.
   - Test invalid target or scan failure exit code 1 handling.
5. VICTORY AUDIT:
   - Run `python -m pytest tests/test_cli_scan.py -v`
   - Run `python -m pytest tests/ --ignore=tests/workspace -x -q` (confirm 2,086+ passing with 0 failures).
6. Write complete handoff report to `/home/varun/argus/.agents/worker_m4/handoff.md`.
7. Send a final completion message to orchestrator via send_message. Operate silently during execution.

## 2026-09-02T18:31:50Z
**Context**: Status check on Milestone M4 (CLI Entry Point & Scan Command).
**Content**: Please report your current progress on tasks (creating `argus/__main__.py`, implementing `scan` command in `argus/cli/app.py`, `ScanDAG` profile support, `tests/test_cli_scan.py`, and victory audit).
**Action**: Continue execution, run victory audit, and provide handoff when complete.
