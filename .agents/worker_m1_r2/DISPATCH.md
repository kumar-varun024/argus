## 2026-08-30T07:19:25Z
You are Worker M1 (Iteration 2) for Milestone 1.
Your working directory is /home/varun/argus/.agents/worker_m1_r2

You MUST read /home/varun/argus/.agents/ORIGINAL_REQUEST.md and /home/varun/argus/PROJECT.md and /home/varun/argus/.agents/challenger2_m1/handoff.md before doing anything else.

MANDATORY INTEGRITY WARNING:
DO NOT CHEAT. All implementations must be genuine. DO NOT hardcode test results, create dummy/facade implementations, or circumvent the intended task. A auditor will independently verify your work. Integrity violations WILL be detected and your work WILL be rejected.

Your Exclusive File Ownership:
- `argus/utils/environment.py`
- `tests/tools/test_environment_detector.py`

Your Task:
Remediate the two defects reported by Challenger 2 in `argus/utils/environment.py`:
1. Defect 1: Unhandled `ValueError` / exceptions in `check_network()` when `urllib.parse.urlparse` parses malformed URLs with unclosed or invalid brackets (e.g. `http://[invalid_ipv6`, `http://]`, `https://[`). Wrap URL/host parsing in `try...except (ValueError, Exception) as e:` and return a structured dictionary `{ "target": target, "host": "", "dns_resolvable": False, "ip_addresses": [], "http_reachable": False, "status_code": None, "error": f"Invalid target URL: {e}" }` instead of raising an unhandled exception.
2. Defect 2: Raw IPv6 address handling in `check_network()`:
   - When target is a raw IPv6 address (e.g. `2001:db8::1`, `::1`, `[::1]:8080`), do not naively split on `:` (which produces `"2001"` or `""`).
   - Use `ipaddress.ip_address` or bracket checks to properly extract the full IPv6 host.
   - For HTTP probe on IPv6 targets, ensure bracketed formatting `http://[{host}]` (e.g. `http://[2001:db8::1]`) is used so `httpx` parses the URL validly.
3. Add unit and adversarial test cases in `tests/tools/test_environment_detector.py`:
   - Test malformed bracket URLs (`"http://[invalid_ipv6"`, `"http://]"`, `"https://["`) returning structured error dict with `dns_resolvable: False`.
   - Test IPv6 target inputs (`"::1"`, `"2001:db8::1"`, `"[::1]:8080"`).
4. Run tests and verify zero regressions:
   - `python -m pytest tests/tools/test_environment_detector.py -v`
   - `python -m pytest tests/ --ignore=tests/workspace -x -q`
5. Write your handoff report to `/home/varun/argus/.agents/worker_m1_r2/handoff.md`.
6. When complete, send a final message to the orchestrator referencing your handoff report.
