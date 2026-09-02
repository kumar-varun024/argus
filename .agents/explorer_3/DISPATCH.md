## 2026-09-01T16:56:47Z
You are an Explorer subagent for the ARGUS project.
Your working directory is `/home/varun/argus/.agents/explorer_3`.
Please read `/home/varun/argus/.agents/ORIGINAL_REQUEST.md` for project requirements.

Investigate the following in the codebase:
1. Existing collector implementations in ARGUS (e.g. HTTP collectors, SSL collectors, header or vulnerability collectors) to identify code patterns, coding conventions, exception handling, typing, and async patterns.
2. Existing test suites in `tests/`: test fixtures, mock servers (e.g. `aioresponses`, `unittest.mock`, `pytest-asyncio`, custom HTTP mocks), test structure.
3. Run the baseline test command (`python -m pytest tests/ --ignore=tests/workspace -x -q` or inspect it) to confirm current test suite count and baseline health.
4. Recommended file paths for the new CORS & HTTP Security Header collector, probers/auditors, and test files.

Write a comprehensive exploration report to `/home/varun/argus/.agents/explorer_3/handoff.md`.
Notify the orchestrator via `send_message` when done. Do NOT make code modifications.
