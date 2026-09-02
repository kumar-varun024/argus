## 2026-09-02T05:50:33Z
You are the Architecture & Collector Patterns Explorer for the ARGUS platform sprint: Authentication Bypass & Credential Attack Detection Module.

Working Directory: /home/varun/argus
Agent Working Directory: /home/varun/argus/.agents/explorer_survey_arch
Original Request: /home/varun/argus/.agents/ORIGINAL_REQUEST.md

Your role is to conduct a read-only investigation of the existing ARGUS collector architecture, specifically:
1. BaseCollector class and existing active collectors (e.g. SQLi, XSS, SSRF, CORS, SSTI, Command Injection, etc.) to identify:
   - Tripartite architecture pattern (Collector + PayloadGenerator + Analyzer).
   - Quadruple State Publishing pattern (finding publishing, state transitions, events, metrics/graph updates).
   - AuthenticatedHttpClient usage, session handling, rate limiting, and HTTP client integration.
2. Code layout conventions in `src/` (or wherever collector code resides), module naming, class hierarchies, dataclass/pydantic models, finding models, evidence structures, and logger usage.
3. How finding objects are constructed, severity rating, confidence rating, evidence formatting, and CWE/OWASP metadata.
4. Existing test patterns for active collectors in `tests/` (unit tests, mock HTTP clients, fixture conventions).

Outputs:
Write a comprehensive survey report to `/home/varun/argus/.agents/explorer_survey_arch/handoff.md` and keep `/home/varun/argus/.agents/explorer_survey_arch/progress.md` updated.
When complete, notify the parent orchestrator via `send_message`.
