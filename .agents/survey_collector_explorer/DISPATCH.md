## 2026-08-30T07:09:13Z
You are Survey Explorer 1 (Collector Specialist).
Your working directory is /home/varun/argus/.agents/survey_collector_explorer
You MUST read /home/varun/argus/.agents/ORIGINAL_REQUEST.md before doing anything else.

Your Mission:
Investigate the ARGUS codebase to survey all patterns, architectures, and conventions needed for implementing the XSS Detection Collector (R1):
1. Read existing collectors:
   - `argus/collectors/path_traversal.py`
   - `argus/collectors/sql_injection.py`
   - `argus/collectors/javascript.py`
   - `argus/collectors/base.py` (and any other collectors in `argus/collectors/`)
   - `argus/http/client.py` (AuthenticatedHttpClient methods, scope checks, request/response models)
   - `argus/models/` (Evidence models, Target, Endpoint, Finding, Severity, Category, etc.)
2. Map out the exact requirements for XSS detection:
   - Reflected XSS: canary generation (unique random strings/tokens), parameter injection (query params, POST body, headers), HTML parsing/checking if canary is unescaped vs properly escaped (e.g. HTML entity encoded &lt;, &gt;, &quot;, &#39;, &amp;), false positive rejection.
   - Stored XSS: POST payload submission, then re-fetching (GET) the page/endpoint to check for persistence of unescaped payload.
   - Context-aware payload generation: HTML body context (`<tag>...CANARY...</tag>`), HTML attribute context (`<tag attr="...CANARY...">` or `'...CANARY...'`), JavaScript string context (`<script>var x = "...CANARY...";</script>`), and URL context (`<a href="...CANARY...">`). Define the payload sets and escape sequences required for each context.
3. Produce a detailed architecture and design specification for `argus/collectors/xss.py`.
4. Write your full analysis and handoff report to `/home/varun/argus/.agents/survey_collector_explorer/handoff.md`.
5. Update your `/home/varun/argus/.agents/survey_collector_explorer/progress.md` with timestamps and status.
6. When 100% complete, send a final message to the orchestrator referencing your handoff report.
