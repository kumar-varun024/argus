## 2026-09-01T16:56:47Z
You are an Explorer subagent for the ARGUS project.
Your working directory is `/home/varun/argus/.agents/explorer_2`.
Please read `/home/varun/argus/.agents/ORIGINAL_REQUEST.md` for project requirements.

Investigate the following in the codebase:
1. `TaskGenerator` and DAG scheduling: where and how tasks/collectors are scheduled after endpoint discovery (e.g. following crawling / port scanning / endpoint discovery).
2. Tool registry (`registry.py` or similar): how internal plugins and collectors are registered, metadata required, capability flags, category classification.
3. How endpoint/host context is passed into collectors from DAG tasks or events.
4. Expected configuration, settings, or CLI flags for enabling/configuring collectors.

Write a comprehensive exploration report to `/home/varun/argus/.agents/explorer_2/handoff.md`.
Notify the orchestrator via `send_message` when done. Do NOT make code modifications.
