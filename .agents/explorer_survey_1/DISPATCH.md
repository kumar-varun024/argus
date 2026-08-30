## 2026-08-30T12:17:40Z
You are Explorer 1 for Sprint 13 Codebase Survey.
Your working directory is /home/varun/argus/.agents/explorer_survey_1.
Create your working directory and maintain progress.md and handoff.md in it.

Read /home/varun/argus/.agents/ORIGINAL_REQUEST.md.

Your mission is to explore the existing Collector architecture in Argus:
1. Locate and analyze existing vulnerability collectors: SQLInjectionCollector, XSSCollector, PathTraversalCollector, CommandInjectionCollector, SSRFCollector, and their base classes (e.g. in src/argus or wherever the source is located).
2. Identify the base collector interface: lifecycle methods (run, collect, probe, etc.), input data structures (Endpoints, Targets, HTTP requests/responses, Config), and output data structures (Evidence, Vulnerability, Finding, Severity levels).
3. Analyze how AuthenticatedHttpClient or other HTTP clients are instantiated and used for sending requests, handling auth headers, cookies, redirects, and session state.
4. Document the exact patterns, class names, file paths, import structures, and conventions needed to implement the new OAuth/OIDC, Token Validation, and Stateful Authentication collectors.
5. Write your detailed findings to /home/varun/argus/.agents/explorer_survey_1/handoff.md and report back via send_message to parent. Operate silently during execution.
